package scanner

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
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
			if ip == nil {
				return
			}
			for _, port := range s.ports {
				s.dial(ip, port)
			}
		}
	}
}

func (s *Scanner) dial(ip net.IP, port string) {
	var address string
	if len(ip) == net.IPv4len {
		address = ip.String() + ":" + port
	} else {
		address = "[" + ip.String() + "]:" + port
	}
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			d := &net.Dialer{
				Timeout: s.opts.DialTimeout,
			}
			laddr := s.getLocalAddr()
			if laddr != nil {
				d.LocalAddr = laddr
			}
			conn, err := d.Dial("tcp", address)
			if err != nil {
				if isLocalError(err) {
					time.Sleep(250 * time.Millisecond)
					continue
				} else {
					return
				}
			}
			s.Conns <- conn.(*net.TCPConn)
			return
		}
	}
}

func isLocalError(err error) bool {
	syscallErr, ok := err.(*net.OpError).Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errno := syscallErr.Err.(syscall.Errno)
	switch int(errno) {
	case 10013:
		// An attempt was made to access a socket in a way
		// forbidden by its access permissions.
	case 10048:
		// Only one usage of each socket address
		// (protocol/network address/port) is normally permitted
	case 10055:
		// An operation on a socket could not be
		// performed because the system lacked sufficient
		// buffer space or because a queue was full.
	default:
		panic(fmt.Sprintln(int(errno), errno))
		return false
	}
	return true
}
