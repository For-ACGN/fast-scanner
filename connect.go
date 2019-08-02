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
			for port := range s.ports {
				select {
				case <-s.tokenBucket:
				case <-s.stopSignal:
					return
				}
				// scan
				var address string
				if len(ip) == net.IPv4len {
					address = ip.String() + ":" + port
				} else {
					address = "[" + ip.String() + "]:" + port
				}
				address, err := s.dialer.Dial("tcp", address)
				if err != nil {
					s.addScanned()
					continue
				}
				select {
				case <-s.stopSignal:
				case s.Address <- address:
					s.addScanned()
				}
			}
		case <-s.stopSignal:
			return
		}
	}
}
