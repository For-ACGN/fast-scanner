package scanner

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snaplen = 65536
)

func (s *Scanner) synScanner(port string, errChan chan<- error) {
	// defer s.wg.Done()
	handle, err := pcap.OpenLive(s.iface.Device, snaplen, false, pcap.BlockForever)
	if err != nil {
		errChan <- err
		return
	}
	defer handle.Close()
	errChan <- nil
	var (
		target  net.IP
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
		// scan loopback
		if target.IsLoopback() {
			s.scanLoopback(target, port)
			return
		}
		gateway, srcIP, err = s.route.route(target)
		if err != nil {
			s.addScanned()
			return
		}
		// set eth
		if gateway != nil { // send to gateway
			eth.DstMAC, err = s.getGatewayHardwareAddr(srcIP, gateway)
			if err != nil {
				s.addScanned()
				return
			}
			eth.SrcMAC = s.iface.MAC
		} else { // LAN

		}
		// set tcp
		tcp.SrcPort = 1999
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
		s.addScanned()
	}
	for {
		select {
		case target = <-s.generator.IP:
			if target == nil {
				return
			}
			select {
			case <-s.tokenBucket:
			case <-s.stopSignal:
				return
			}
			if target.Equal(net.IPv4bcast) ||
				target.IsUnspecified() ||
				target.IsMulticast() ||
				target.IsLinkLocalUnicast() {
				s.addScanned()
				continue
			}
			scan()
		case <-s.stopSignal:
			return
		}
	}
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
	// TODO _ = handle.SetBPFFilter("arp")
	// send
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)
	parser.IgnoreUnsupported = true
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		// receive
		data, _, err := handle.ReadPacketData()
		if err != nil {
			return nil, err
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			continue
		}
		if net.IP(arp.SourceProtAddress).Equal(dstIP) {
			fmt.Println("mac", arp.SourceHwAddress)
			return arp.SourceHwAddress, nil
		}
	}
}

func (s *Scanner) getHardwareAddrv6(srcIP, dstIP net.IP) ([]byte, error) {
	return nil, errors.New("wait")
}

func (s *Scanner) synCapturer(port string, errChan chan<- error) {
	handle, err := pcap.OpenLive(s.iface.Device, snaplen, false, pcap.BlockForever)
	if err != nil {
		errChan <- err
		return
	}
	errChan <- nil
	defer handle.Close()
	// tcp.flags.syn == 1 and tcp.flags.ack == 1
	_ = handle.SetBPFFilter("tcp[13] = 0x12 and tcp port " + port)
	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			return
		}
		d := make([]byte, len(data))
		copy(d, data)
		s.packetChan <- d
	}
}

func (s *Scanner) synParser(port string) {
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
	for data = range s.packetChan {
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			continue
		}
		fmt.Println("receive", ipv4.SrcIP, tcp.SrcPort)
	}
}
