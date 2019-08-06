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

type addrPool struct {
	addrs      []*addr
	addrsEnd   int // len(laddrsv4) - 1
	addrsIndex int
	addrsMutex sync.Mutex
}

func newaddrPool() *addrPool {
	return &addrPool{addrsEnd: -1}
}

func (ap *addrPool) add(addr *addr) {
	ap.addrs = append(ap.addrs, addr)
	ap.addrsEnd = len(ap.addrs) - 1
}

func (ap *addrPool) get() *net.TCPAddr {
	// not set loacl ip
	if ap.addrsEnd == -1 {
		return nil
	}
	ap.addrsMutex.Lock()
	i := ap.addrsIndex
	// add d.laddrIndex
	if ap.addrsIndex == ap.addrsEnd {
		ap.addrsIndex = 0
	} else {
		ap.addrsIndex += 1
	}
	ap.addrsMutex.Unlock()
	laddr := ap.addrs[i]
	// add port
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

type Dialer struct {
	timeout time.Duration
	ipv4GU  *addrPool // GlobalUnicast    "192.168.0.1", "1.1.1.1"
	ipv4LLU *addrPool // LinkLocalUnicast "169.254.0.1"
	ipv6GU  *addrPool // GlobalUnicast    "240c::1"
	ipv6LLU *addrPool // LinkLocalUnicast "fe80::1"
}

func NewDialer(localIPs []string, timeout time.Duration) (*Dialer, error) {
	d := &Dialer{
		timeout: timeout,
		ipv4GU:  newaddrPool(),
		ipv4LLU: newaddrPool(),
		ipv6GU:  newaddrPool(),
		ipv6LLU: newaddrPool(),
	}
	if localIPs != nil {
		g, err := NewGenerator(localIPs)
		if err != nil {
			return nil, err
		}
		for ip := range g.IP {
			if ip.Equal(net.IPv4bcast) ||
				ip.IsUnspecified() ||
				ip.IsMulticast() ||
				ip.IsLoopback() {
				continue
			}
			if len(ip) == net.IPv4len {
				addr := &addr{
					ip:   ip.String(),
					port: minPort,
				}
				if ip.IsGlobalUnicast() {
					d.ipv4GU.add(addr)
				} else {
					d.ipv4LLU.add(addr)
				}
			} else {
				addr := &addr{
					ip:   "[" + ip.String() + "]",
					port: minPort,
				}
				if ip.IsGlobalUnicast() {
					d.ipv6GU.add(addr)
				} else {
					d.ipv6LLU.add(addr)
				}
			}
		}
	}
	return d, nil
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	for {
		raddr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, err
		}
		ip := raddr.IP
		if ip.Equal(net.IPv4bcast) ||
			ip.IsUnspecified() ||
			ip.IsMulticast() {
			return nil, errors.New("invalid ip")
		}
		dialer := &net.Dialer{
			Timeout: d.timeout,
		}
		if !ip.IsLoopback() {
			var laddr *net.TCPAddr
			if strings.Index(address, "[") == -1 { // ipv4
				if ip.IsGlobalUnicast() {
					laddr = d.ipv4GU.get()
				} else {
					laddr = d.ipv4LLU.get()
				}
			} else { // ipv6
				if ip.IsGlobalUnicast() {
					laddr = d.ipv6GU.get()
				} else {
					laddr = d.ipv6LLU.get()
				}
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
				return nil, err
			}
		}
		return conn, nil
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
