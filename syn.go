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

func (s *Scanner) newSenderHandle() (*pcap.Handle, error) {
	ihandle, err := pcap.NewInactiveHandle(s.iface.Device)
	if err != nil {
		return nil, err
	}
	defer ihandle.CleanUp()
	_ = ihandle.SetSnapLen(snaplen)
	_ = ihandle.SetPromisc(false)
	_ = ihandle.SetTimeout(1) // only send
	_ = ihandle.SetImmediateMode(true)
	return ihandle.Activate()
}

func (s *Scanner) synCapturer(handle *pcap.Handle) {
	defer s.wg.Done()
	var (
		data []byte
		err  error
	)
	// _ = handle.SetBPFFilter("tcp[13] = 0x12")
	defer close(s.packetChan) // synParser will close
	for {
		data, _, err = handle.ZeroCopyReadPacketData()
		if err != nil {
			return
		}
		d := make([]byte, len(data))
		copy(d, data)
		s.packetChan <- d
	}
}

func (s *Scanner) synParser(handle *pcap.Handle) {
	defer func() {
		handle.Close()
		s.wg.Done()
	}()
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
	parser.IgnoreUnsupported = true
	// for send RST
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buf := gopacket.NewSerializeBuffer()
	for data = range s.packetChan {
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			continue
		}
		// check port
		port := strconv.Itoa(int(tcp.SrcPort))
		if _, ok := s.ports[port]; !ok {
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
					// send RST
					result := ipv4.SrcIP.String() + ":" + port
					// swap
					eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC
					ipv4.SrcIP, ipv4.DstIP = ipv4.DstIP, ipv4.SrcIP
					tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
					tcp.Seq, tcp.Ack = tcp.Ack, tcp.Seq+1
					// set flag
					tcp.SYN = false
					tcp.ACK = false
					tcp.RST = true
					// send packet
					_ = tcp.SetNetworkLayerForChecksum(&ipv4)
					_ = buf.Clear()
					_ = gopacket.SerializeLayers(buf, opt, &eth, &ipv4, &tcp)
					_ = handle.WritePacketData(buf.Bytes())
					select {
					case <-s.stopSignal:
						return
					case s.Result <- result:
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
				if uint16(tcp.DstPort) == binary.BigEndian.Uint16(hash[:2]) &&
					tcp.Ack-1 == binary.BigEndian.Uint32(hash[2:6]) {
					// send RST
					result := "[" + ipv6.SrcIP.String() + "]:" + port
					// swap
					eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC
					ipv6.SrcIP, ipv6.DstIP = ipv6.DstIP, ipv6.SrcIP
					tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
					tcp.Seq, tcp.Ack = tcp.Ack, tcp.Seq+1
					// set flag
					tcp.SYN = false
					tcp.ACK = false
					tcp.RST = true
					// send packet
					_ = tcp.SetNetworkLayerForChecksum(&ipv6)
					_ = buf.Clear()
					_ = gopacket.SerializeLayers(buf, opt, &eth, &ipv6, &tcp)
					_ = handle.WritePacketData(buf.Bytes())
					select {
					case <-s.stopSignal:
						return
					case s.Result <- result:
					}
				}
				goto getNewData
			}
		}
	getNewData:
	}
}

func (s *Scanner) synScanner(wg *sync.WaitGroup, handle *pcap.Handle) {
	defer func() {
		handle.Close()
		wg.Done()
	}()
	var (
		target  net.IP
		port    string
		gateway net.IP
		srcIP   net.IP
		err     error
	)
	eth := layers.Ethernet{}
	ipv4 := layers.IPv4{
		Version:  4,
		Flags:    layers.IPv4DontFragment,
		TTL:      128,
		Protocol: layers.IPProtocolTCP,
	}
	ipv6 := layers.IPv6{
		Version:    6,
		HopLimit:   128,
		NextHeader: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
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
		// set dst MAC
		if gateway != nil { // send to gateway
			eth.DstMAC, err = s.getGatewayHardwareAddr(srcIP, gateway)
		} else { // LAN
			eth.DstMAC, err = s.getHardwareAddr(srcIP, target)
		}
		if err != nil {
			return
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
			_ = tcp.SetNetworkLayerForChecksum(&ipv4)
			_ = buf.Clear()
			_ = gopacket.SerializeLayers(buf, opt, &eth, &ipv4, &tcp)
		case net.IPv6len:
			eth.EthernetType = layers.EthernetTypeIPv6
			ipv6.SrcIP = srcIP
			ipv6.DstIP = target
			_ = tcp.SetNetworkLayerForChecksum(&ipv6)
			_ = buf.Clear()
			_ = gopacket.SerializeLayers(buf, opt, &eth, &ipv6, &tcp)
		}
		// send packet
		_ = handle.WritePacketData(buf.Bytes())
	}
	portsLen := len(s.ports)
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
					target.IsMulticast() {
					for i := 0; i < portsLen; i++ {
						s.addScanned()
					}
					goto getIP
				}
				// scan loopback
				if target.IsLoopback() {
					s.simpleScan(target, port)
					goto getIP
				}
				// get route
				gateway, srcIP, err = s.route.route(target)
				if err != nil {
					if err == errRouteSelf {
						s.simpleScan(target, port)
						goto getIP
					}
					s.addScanned()
					goto getIP
				}
				scan()
				s.addScanned()
			}
		case <-s.stopSignal:
			return
		}
	}
}

func (s *Scanner) simpleScan(ip net.IP, port string) {
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
	case s.Result <- address:
		s.addScanned()
	}
}

func (s *Scanner) getGatewayHardwareAddr(srcIP, gateway net.IP) (net.HardwareAddr, error) {
	s.gatewayMu.Lock()
	defer s.gatewayMu.Unlock()
	gatewayStr := gateway.String()
	if mac, ok := s.gatewayMACs[gatewayStr]; ok {
		return mac, nil
	}
	haddr, err := s.getHardwareAddr(srcIP, gateway)
	if err != nil {
		return nil, err
	}
	s.gatewayMACs[gatewayStr] = haddr
	return haddr, nil
}

var (
	zeroMAC   = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	ipv6mcast = []byte{0x33, 0x33, 0xFF, 0x00, 0x00, 0x00}
	icmpv6ns  = net.IP{0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x00}
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
	_ = ihandle.SetTimeout(time.Second)
	_ = ihandle.SetImmediateMode(true)
	handle, err := ihandle.Activate()
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	// packet
	eth := layers.Ethernet{
		SrcMAC: s.iface.MAC,
	}
	opt := gopacket.SerializeOptions{
		FixLengths: true,
	}
	buf := gopacket.NewSerializeBuffer()
	switch srcIPLen {
	case net.IPv4len: // ARP
		_ = handle.SetBPFFilter("arp[7] = 0x02") // reply
		eth.DstMAC = layers.EthernetBroadcast
		eth.EthernetType = layers.EthernetTypeARP
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
		_ = handle.WritePacketData(buf.Bytes())
		// receive reply
		var decoded []gopacket.LayerType
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet, &eth, &arp)
		// pass error: "No decoder for layer type Payload"
		parser.IgnoreUnsupported = true
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
		_ = handle.SetBPFFilter("icmp6[0] = 0x88") // reply
		opt.ComputeChecksums = true
		// set dst MAC
		mac := make([]byte, 6) // MAC size
		copy(mac[:3], ipv6mcast[:3])
		mac[3] = dstIP[13]
		mac[4] = dstIP[14]
		mac[5] = dstIP[15]
		eth.DstMAC = mac
		eth.EthernetType = layers.EthernetTypeIPv6
		// set dst ip
		dIP := make([]byte, net.IPv6len)
		copy(dIP, icmpv6ns)
		dIP[13] = dstIP[13]
		dIP[14] = dstIP[14]
		dIP[15] = dstIP[15]
		ipv6 := layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   255,
			SrcIP:      srcIP,
			DstIP:      dIP,
		}
		typ := layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0)
		icmpv6 := layers.ICMPv6{
			TypeCode: typ,
		}
		ns := layers.ICMPv6NeighborSolicitation{
			TargetAddress: dstIP,
		}
		icmpv6Opt := layers.ICMPv6Option{
			Type: layers.ICMPv6OptSourceAddress,
			Data: s.iface.MAC,
		}
		ns.Options = append(ns.Options, icmpv6Opt)
		_ = icmpv6.SetNetworkLayerForChecksum(&ipv6)
		_ = gopacket.SerializeLayers(buf, opt, &eth, &ipv6, &icmpv6, &ns)
		_ = handle.WritePacketData(buf.Bytes())
		// receive reply
		var (
			decoded []gopacket.LayerType
			na      layers.ICMPv6NeighborAdvertisement
		)
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet, &eth, &ipv6, &icmpv6, &na)
		// pass error: "No decoder for layer type Payload"
		parser.IgnoreUnsupported = true
		for {
			data, _, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				return nil, err
			}
			err = parser.DecodeLayers(data, &decoded)
			if err != nil {
				continue
			}
			if ipv6.SrcIP.Equal(dstIP) {
				if len(na.Options) != 1 {
					continue
				}
				if na.Options[0].Type != layers.ICMPv6OptTargetAddress { // type
					continue
				}
				if len(na.Options[0].Data) != 6 { // MAC size
					continue
				}
				return na.Options[0].Data, nil
			}
		}
	default:
		return nil, errors.New("invalid ip size")
	}
}
