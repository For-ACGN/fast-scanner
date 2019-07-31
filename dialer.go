package scanner

import (
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

type addr struct {
	ip   string
	port int
	mu   sync.Mutex
}

type Dialer struct {
	timeout     time.Duration
	laddrs      []*addr
	laddrsEnd   int // len(laddrs) - 1
	laddrsIndex int
	laddrsM     sync.Mutex
}

func NewDialer(localIPs string, timeout time.Duration) (*Dialer, error) {
	d := &Dialer{
		timeout: timeout,
	}
	if localIPs != "" {
		g, err := NewGenerator(split(localIPs))
		if err != nil {
			return nil, err
		}
		for ip := range g.IP {
			var dst string
			if len(ip) == net.IPv4len {
				dst = ip.String()
			} else {
				dst = "[" + ip.String() + "]"
			}
			addr := &addr{
				ip:   dst,
				port: minPort,
			}
			d.laddrs = append(d.laddrs, addr)
		}
		d.laddrsEnd = len(d.laddrs) - 1
	} else {
		d.laddrsEnd = -1
	}
	return d, nil
}

func (d *Dialer) getLocalAddr() *net.TCPAddr {
	// not set loacl ip
	if d.laddrsEnd == -1 {
		return nil
	}
	d.laddrsM.Lock()
	i := d.laddrsIndex
	// add d.laddrIndex
	if d.laddrsIndex == d.laddrsEnd {
		d.laddrsIndex = 0
	} else {
		d.laddrsIndex += 1
	}
	d.laddrsM.Unlock()
	laddr := d.laddrs[i]
	laddr.mu.Lock()
	port := laddr.port
	if laddr.port == maxPort {
		laddr.port = minPort
	} else {
		laddr.port += 1
	}
	laddr.mu.Unlock()
	address := laddr.ip + ":" + strconv.Itoa(port)
	addr, _ := net.ResolveTCPAddr("tcp", address)
	return addr
}

func (d *Dialer) Dial(network, address string) (*net.TCPConn, error) {
	for {
		dialer := &net.Dialer{
			Timeout: d.timeout,
		}
		laddr := d.getLocalAddr()
		if laddr != nil {
			dialer.LocalAddr = laddr
		}
		conn, err := dialer.Dial(network, address)
		if err != nil {
			if isLocalError(err) {
				time.Sleep(10 * time.Millisecond)
				continue
			} else {
				return nil, err
			}
		}
		return conn.(*net.TCPConn), nil
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
		// Only one usage of each socket ip
		// (protocol/network ip/port) is normally permitted
	case 10055:
		// An operation on a socket could not be
		// performed because the system lacked sufficient
		// buffer space or because a queue was full.
	default:
		return false
	}
	return true
}
