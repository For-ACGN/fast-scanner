package scanner

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
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
	timeout       time.Duration
	laddrsv4      []*addr
	laddrsv4End   int // len(laddrsv4) - 1
	laddrsv4Index int
	laddrsv4Mutex sync.Mutex
	laddrsv6      []*addr
	laddrsv6End   int // len(laddrsv6) - 1
	laddrsv6Index int
	laddrsv6Mutex sync.Mutex
}

func NewDialer(localIPs []string, timeout time.Duration) (*Dialer, error) {
	d := &Dialer{
		timeout: timeout,
	}
	if localIPs != nil {
		g, err := NewGenerator(localIPs)
		if err != nil {
			return nil, err
		}
		for ip := range g.IP {
			if ip.IsGlobalUnicast() {
				if len(ip) == net.IPv4len {
					addr := &addr{
						ip:   ip.String(),
						port: minPort,
					}
					d.laddrsv4 = append(d.laddrsv4, addr)
				} else {
					addr := &addr{
						ip:   "[" + ip.String() + "]",
						port: minPort,
					}
					d.laddrsv6 = append(d.laddrsv6, addr)
				}
			}
		}
	}
	d.laddrsv4End = len(d.laddrsv4) - 1
	d.laddrsv6End = len(d.laddrsv6) - 1
	return d, nil
}

func (d *Dialer) getLocalAddrv4() *net.TCPAddr {
	// not set loacl ip
	if d.laddrsv4End == -1 {
		return nil
	}
	d.laddrsv4Mutex.Lock()
	i := d.laddrsv4Index
	// add d.laddrIndex
	if d.laddrsv4Index == d.laddrsv4End {
		d.laddrsv4Index = 0
	} else {
		d.laddrsv4Index += 1
	}
	d.laddrsv4Mutex.Unlock()
	laddr := d.laddrsv4[i]
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

func (d *Dialer) getLocalAddrv6() *net.TCPAddr {
	// not set loacl ip
	if d.laddrsv6End == -1 {
		return nil
	}
	d.laddrsv6Mutex.Lock()
	i := d.laddrsv6Index
	// add d.laddrIndex
	if d.laddrsv6Index == d.laddrsv6End {
		d.laddrsv6Index = 0
	} else {
		d.laddrsv6Index += 1
	}
	d.laddrsv6Mutex.Unlock()
	laddr := d.laddrsv6[i]
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

func (d *Dialer) Dial(network, address string) (string, error) {
	for {
		raddr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return "", err
		}
		ip := raddr.IP
		if ip.Equal(net.IPv4bcast) ||
			ip.IsUnspecified() ||
			ip.IsMulticast() ||
			ip.IsLinkLocalUnicast() {
			return "", errors.New("invalid ip")
		}
		dialer := &net.Dialer{
			Timeout: d.timeout,
		}
		if !ip.IsLoopback() {
			var laddr *net.TCPAddr
			if strings.Index(address, "[") == -1 { // ipv4
				laddr = d.getLocalAddrv4()
			} else {
				laddr = d.getLocalAddrv6()
			}
			if laddr != nil {
				dialer.LocalAddr = laddr
			}
		}
		conn, err := dialer.Dial(network, address)
		if err != nil {
			if isLocalError(err) {
				time.Sleep(10 * time.Millisecond)
				continue
			} else {
				return "", err
			}
		}
		address := conn.RemoteAddr().String()
		_ = conn.Close()
		return address, nil
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
