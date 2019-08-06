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
			s.addScanned()
			if err != nil {
				continue
			}
			ip := conn.RemoteAddr().(*net.TCPAddr).IP
			_ = conn.Close()
			if s.addResult(ip, port) {
				return
			}
		}
	}
}
