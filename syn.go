package scanner

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snaplen = 65536
)

func (s *Scanner) synCapturer() (func(), error) {
	handle, err := pcap.OpenLive(s.iface.Device, snaplen, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	// tcp.flags.syn == 1 and tcp.flags.ack == 1
	_ = handle.SetBPFFilter("tcp[13] = 0x12")
	go func() {
		defer close(s.packetChan) // synParser will close
		for {
			data, _, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				return
			}
			d := make([]byte, len(data))
			copy(d, data)
			s.packetChan <- d
		}
	}()
	go func() {
		<-s.stopSignal
		handle.Close()
	}()
	return handle.Close, nil
}

func (s *Scanner) synParser(wg *sync.WaitGroup) {
	defer wg.Done()
	var (
		err     error
		data    []byte
		eth     layers.Ethernet
		ipv4    layers.IPv4
		ipv6    layers.IPv6
		tcp     layers.TCP
		decoded []gopacket.LayerType
	)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &ipv4, &ipv6, &tcp)
	for data = range s.packetChan {
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			continue
		}
		// check port
		port := strconv.Itoa(int(tcp.SrcPort))
		_, ok := s.ports[port]
		if !ok {
			continue
		}
		// send address
		for i := 0; i < len(decoded); i++ {
			switch decoded[i] {
			case layers.LayerTypeIPv4:
				// check hash
				sha := sha256.New()
				sha.Write(ipv4.SrcIP)
				sha.Write(s.salt)
				hash := sha.Sum(nil)
				// check port and ack
				if uint16(tcp.DstPort) == binary.BigEndian.Uint16(hash[:2]) &&
					tcp.Ack-1 == binary.BigEndian.Uint32(hash[2:6]) {
					select {
					case <-s.stopSignal:
						return
					case s.Address <- ipv4.SrcIP.String() + ":" + port:
					}
				}
				goto getNewData
			case layers.LayerTypeIPv6:
				// check hash
				sha := sha256.New()
				sha.Write(ipv6.SrcIP)
				sha.Write(s.salt)
				hash := sha.Sum(nil)
				// check port and ack
				if uint16(tcp.SrcPort) == binary.BigEndian.Uint16(hash[:2]) &&
					tcp.Ack-1 == binary.BigEndian.Uint32(hash[2:6]) {
					select {
					case <-s.stopSignal:
						return
					case s.Address <- "[" + ipv6.SrcIP.String() + "]:" + port:
					}
				}
				goto getNewData
			}
		}
	getNewData:
	}
}

func (s *Scanner) synScanner(wg *sync.WaitGroup) error {
	handle, err := pcap.OpenLive(s.iface.Device, snaplen, false, pcap.BlockForever)
	if err != nil {
		return err
	}
	var (
		target  net.IP
		port    string
		gateway net.IP
		srcIP   net.IP
	)
	eth := new(layers.Ethernet)
	ipv4 := &layers.IPv4{
		Version:  4,
		Flags:    layers.IPv4DontFragment,
		TTL:      128,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SYN: true,
		// ECE:    true,
		// CWR:    true,
		Window: 8192,
		// Options:[]layers.TCPOption{}
	}
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buf := gopacket.NewSerializeBuffer()
	scan := func() {
		gateway, srcIP, err = s.route.route(target)
		if err != nil {
			return
		}
		// set dst MAC
		if gateway != nil { // send to gateway
			eth.DstMAC, err = s.getGatewayHardwareAddr(srcIP, gateway)
			if err != nil {
				return
			}
		} else { // LAN
			eth.DstMAC, err = s.getHardwareAddr(srcIP, target)
			if err != nil {
				return
			}
		}
		eth.SrcMAC = s.iface.MAC
		// hash
		sha := sha256.New()
		sha.Write(target)
		sha.Write(s.salt)
		hash := sha.Sum(nil)
		// set src port
		tcp.SrcPort = layers.TCPPort(binary.BigEndian.Uint16(hash[:2]))
		tcp.Seq = binary.BigEndian.Uint32(hash[2:6])
		// set dst port
		p, _ := strconv.Atoi(port)
		tcp.DstPort = layers.TCPPort(p)
		// set ip
		switch len(target) {
		case net.IPv4len:
			eth.EthernetType = layers.EthernetTypeIPv4
			ipv4.SrcIP = srcIP
			ipv4.DstIP = target
			_ = tcp.SetNetworkLayerForChecksum(ipv4)
			_ = buf.Clear()
			_ = gopacket.SerializeLayers(buf, opt, eth, ipv4, tcp)
		case net.IPv6len:
			eth.EthernetType = layers.EthernetTypeIPv6
		}
		_ = handle.WritePacketData(buf.Bytes())
	}
	portsLen := len(s.ports)
	wg.Add(1)
	go func() {
		defer func() {
			handle.Close()
			wg.Done()
		}()
		for {
		getIP:
			select {
			case target = <-s.generator.IP:
				if target == nil {
					return
				}
				for port = range s.ports {
					select {
					case <-s.tokenBucket:
					case <-s.stopSignal:
						return
					}
					// check target
					if target.Equal(net.IPv4bcast) ||
						target.IsUnspecified() ||
						target.IsMulticast() ||
						target.IsLinkLocalUnicast() {
						for i := 0; i < portsLen; i++ {
							s.addScanned()
						}
						goto getIP
					}
					// scan loopback
					if target.IsLoopback() {
						s.scanLoopback(target, port)
						return
					}
					scan()
					s.addScanned()
				}
			case <-s.stopSignal:
				return
			}
		}
	}()
	return nil
}

func (s *Scanner) scanLoopback(ip net.IP, port string) {
	var address string
	if len(ip) == net.IPv4len {
		address = ip.String() + ":" + port
	} else {
		address = "[" + ip.String() + "]:" + port
	}
	dialer := net.Dialer{Timeout: s.opts.Timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		s.addScanned()
		return
	}
	address = conn.RemoteAddr().String()
	_ = conn.Close()
	select {
	case <-s.stopSignal:
	case s.Address <- address:
		s.addScanned()
	}
}

func (s *Scanner) getGatewayHardwareAddr(srcIP, gateway net.IP) (net.HardwareAddr, error) {
	s.gatewayMu.Lock()
	defer s.gatewayMu.Unlock()
	gatewayStr := gateway.String()
	m, ok := s.gatewayMACs[gatewayStr]
	if ok {
		return m, nil
	}
	haddr, err := s.getHardwareAddr(srcIP, gateway)
	if err != nil {
		return nil, err
	}
	s.gatewayMACs[gatewayStr] = haddr
	return haddr, nil
}

var (
	zeroMAC = []byte{0, 0, 0, 0, 0, 0}
)

func (s *Scanner) getHardwareAddr(srcIP, dstIP net.IP) (net.HardwareAddr, error) {
	srcIPLen := len(srcIP)
	dstIPLen := len(dstIP)
	if srcIPLen != dstIPLen {
		return nil, errors.New("not the same size")
	}
	// wait 2 seconds for reply
	ihandle, err := pcap.NewInactiveHandle(s.iface.Device)
	if err != nil {
		return nil, err
	}
	defer ihandle.CleanUp()
	_ = ihandle.SetSnapLen(snaplen)
	_ = ihandle.SetPromisc(false)
	_ = ihandle.SetTimeout(2 * time.Second)
	_ = ihandle.SetImmediateMode(true)
	handle, err := ihandle.Activate()
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	// packet
	eth := layers.Ethernet{
		SrcMAC:       s.iface.MAC,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeARP,
	}
	opt := gopacket.SerializeOptions{
		FixLengths: true,
	}
	buf := gopacket.NewSerializeBuffer()
	switch srcIPLen {
	case net.IPv4len: // ARP
		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte(s.iface.MAC),
			SourceProtAddress: []byte(srcIP),
			DstHwAddress:      zeroMAC,
			DstProtAddress:    []byte(dstIP),
		}
		_ = gopacket.SerializeLayers(buf, opt, &eth, &arp)
		_ = handle.SetBPFFilter("arp[7] == 0x02") // reply
		err = handle.WritePacketData(buf.Bytes())
		if err != nil {
			return nil, err
		}
		var decoded []gopacket.LayerType
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)
		parser.IgnoreUnsupported = true // pass error: "No decoder for layer type Payload"
		for {
			data, _, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				return nil, err
			}
			err = parser.DecodeLayers(data, &decoded)
			if err != nil {
				continue
			}
			if net.IP(arp.SourceProtAddress).Equal(dstIP) {
				return arp.SourceHwAddress, nil
			}
		}
	case net.IPv6len: // ICMPv6

		return nil, errors.New("wait support")
	default:
		return nil, errors.New("invalid ip size")
	}
}
