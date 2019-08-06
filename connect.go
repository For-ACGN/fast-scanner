package scanner

import (
	"net"
)

func (s *Scanner) connectScanner() {
	defer s.wg.Done()
	var (
		ip      net.IP
		port    string
		address string
		conn    net.Conn
		err     error
	)
	for {
		ip = <-s.generator.IP
		if ip == nil {
			return
		}
		for port = range s.ports {
			// get token
			select {
			case <-s.tokenBucket:
			case <-s.stopSignal:
				return
			}
			// scan
			if len(ip) == net.IPv4len {
				address = ip.String() + ":" + port
			} else {
				address = "[" + ip.String() + "]:" + port
			}
			conn, err = s.dialer.Dial("tcp", address)
			if err != nil {
				s.addScanned()
				continue
			}
			address = conn.RemoteAddr().String()
			_ = conn.Close()
			select {
			case s.Result <- address:
				s.addScanned()
			case <-s.stopSignal:
				return
			}
		}
	}
}
