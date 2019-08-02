package scanner

import (
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
		// check hash

		// send address
		for i := 0; i < len(decoded); i++ {
			switch decoded[i] {
			case layers.LayerTypeIPv4:
				select {
				case <-s.stopSignal:
				case s.Address <- ipv4.SrcIP.String() + ":" + port:
				}
			case layers.LayerTypeIPv6:
				select {
				case <-s.stopSignal:
				case s.Address <- "[" + ipv6.SrcIP.String() + "]:" + port:
				}
			}
		}
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
		// set eth
		if gateway != nil { // send to gateway
			eth.DstMAC, err = s.getGatewayHardwareAddr(srcIP, gateway)
			if err != nil {
				return
			}
			eth.SrcMAC = s.iface.MAC
		} else { // LAN

		}
		// set tcp
		tcp.SrcPort = 2020
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
			/*
				err = tcp.SetNetworkLayerForChecksum(ipv4)
				fmt.Println("1", err)
				err = buf.Clear()
				fmt.Println("2", err)
				err = gopacket.SerializeLayers(buf, opt, eth, ipv4, tcp)
				fmt.Println("3", err)
				err = handle.WritePacketData(buf.Bytes())
				fmt.Println("4", err)
			*/
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
	// get hardware addrress
	if len(gateway) == net.IPv4len { // ipv4
		haddr, err := s.getHardwareAddrv4(srcIP, gateway)
		if err != nil {
			return nil, err
		}
		s.gatewayMACs[gatewayStr] = haddr
		return haddr, nil
	} else { // ipv6
		haddr, err := s.getHardwareAddrv6(srcIP, gateway)
		if err != nil {
			return nil, err
		}
		s.gatewayMACs[gatewayStr] = haddr
		return haddr, nil
	}
}

var (
	zeroMAC = []byte{0, 0, 0, 0, 0, 0}
)

func (s *Scanner) getHardwareAddrv4(srcIP, dstIP net.IP) ([]byte, error) {
	start := time.Now()
	eth := layers.Ethernet{
		SrcMAC:       s.iface.MAC,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeARP,
	}
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
	opt := gopacket.SerializeOptions{
		FixLengths: true,
	}
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, opt, &eth, &arp)
	handle, err := pcap.OpenLive(s.iface.Device, snaplen, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	_ = handle.SetBPFFilter("arp")
	// send
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)
	// TODO
	parser.IgnoreUnsupported = true
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
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
}

func (s *Scanner) getHardwareAddrv6(srcIP, dstIP net.IP) ([]byte, error) {
	return nil, errors.New("wait")
}
