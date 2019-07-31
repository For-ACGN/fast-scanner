package scanner

import (
	"net"
)

func (s *Scanner) connectScanner() {
	defer s.wg.Done()
	for {
		select {
		case ip := <-s.generator.IP:
			if ip == nil {
				return
			}
			for _, port := range s.ports {
				select {
				case <-s.tokenBucket:
				case <-s.stopSignal:
					return
				}
				s.connect(ip, port)
			}
		case <-s.stopSignal:
			return
		}
	}
}

func (s *Scanner) connect(ip net.IP, port string) {
	var address string
	if len(ip) == net.IPv4len {
		address = ip.String() + ":" + port
	} else {
		address = "[" + ip.String() + "]:" + port
	}
	address, err := s.dialer.Dial("tcp", address)
	if err != nil {
		return
	}
	select {
	case <-s.stopSignal:
		return
	case s.Address <- address:
	}
}
