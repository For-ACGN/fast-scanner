package scanner

import (
	"net"
	"strconv"
	"sync"
)

const (
	minPort = 1024
	maxPort = 65535
)

type laddr struct {
	address string
	port    uint16
	mu      sync.Mutex
}

func (s *Scanner) getLocalAddr() *net.TCPAddr {
	// not set loacl address
	if s.laddrsEnd == -1 {
		return nil
	}
	s.laddrsM.Lock()
	i := s.laddrsIndex
	// add s.laddrIndex
	if s.laddrsIndex == s.laddrsEnd {
		s.laddrsIndex = 0
	} else {
		s.laddrsIndex += 1
	}
	s.laddrsM.Unlock()
	laddr := s.laddrs[i]
	laddr.mu.Lock()
	port := laddr.port
	if laddr.port == maxPort {
		laddr.port = minPort
	} else {
		laddr.port += 1
	}
	laddr.mu.Unlock()
	address := laddr.address + ":" + strconv.Itoa(int(port))
	addr, _ := net.ResolveTCPAddr("tcp", address)
	return addr
}

func (s *Scanner) dialer(ips <-chan net.IP) {
	defer func() {
		s.wg.Done()
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		case ip := <-ips:
			raddr, _ := net.ResolveTCPAddr("tcp", ip.String())
			conn, err := net.DialTCP("tcp", s.getLocalAddr(), raddr)
			if err != nil {

			}
			s.Conns <- conn
		}
	}
}
