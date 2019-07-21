package Scanner

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
)

// ParseAddress is used to parse target like
// "192.168.1.1,192.168.1.1/24,192.168.1.1-192.168.1.254"
// to address slice []string{"192.168.1.1", "192.168.1.0/24",
// "192.168.1.1-192.168.1.254"}
func ParseTarget(str string) []string {
	addrs := strings.Split(str, ",")
	for i := 0; i < len(addrs); i++ {
		addrs[i] = strings.Replace(addrs[i], " ", "", -1)
	}
	return addrs
}

func GetIP(ctx context.Context, targets []string) (<-chan net.IP, error) {
	l := len(targets)
	ipChan := make(chan net.IP, l)
	wg := &sync.WaitGroup{}
	for i := 0; i < l; i++ {
		hyphen := strings.Index(targets[i], "-")
		dash := strings.Index(targets[i], "/")
		switch {
		case hyphen+dash == -2: // "192.168.1.1"
			ipChan <- net.ParseIP(targets[i])
		case hyphen != -1 && dash == -1: // "192.168.1.1-192.168.1.2"
			// same ip type
			// start < stop
			wg.Add(1)
			go func(target string) {
				defer func() {
					wg.Done()
				}()
				genIPWithHyphen(ctx, ipChan, targets[i])
			}(targets[i])
		case hyphen == -1 && dash != -1: // "192.168.1.1/24"
			wg.Add(1)
			go func(target string) {
				defer func() {
					wg.Done()
				}()
				genIPWithDash(ctx, ipChan, targets[i])
			}(targets[i])
		case hyphen != -1 && dash != -1: // "192.168.1.1-192.168.1.2/24"
			return nil, errors.New("invalid target: " + targets[i])
		}
	}
	go func() {
		wg.Wait()
		close(ipChan)
	}()
	return ipChan, nil
}

// Range
func genIPWithHyphen(ctx context.Context, ipChan chan<- net.IP, target string) {
	ips := strings.Split(target, "-")
	delta := big.NewInt(1)
	ip := net.ParseIP(ips[0]).To4()
	if ip != nil { // ipv4
		startIP := new(big.Int).SetBytes(ip)
		stopIP := new(big.Int).SetBytes(net.ParseIP(ips[1]).To4()).Bytes()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				b := paddingSlice4(startIP.Bytes())
				ipChan <- net.IP(b)
				startIP.SetBytes(b)
				if bytes.Equal(startIP.Bytes(), stopIP) {
					return
				}
				startIP.Add(startIP, delta)
			}
		}
	} else { // ipv6
		startIP := new(big.Int).SetBytes(net.ParseIP(ips[0]).To16())
		stopIP := new(big.Int).SetBytes(net.ParseIP(ips[1]).To16()).Bytes()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				b := paddingSlice16(startIP.Bytes())
				ipChan <- net.IP(b)
				startIP.SetBytes(b)
				if bytes.Equal(startIP.Bytes(), stopIP) {
					return
				}
				startIP.Add(startIP, delta)
			}
		}
	}
}

// CIDR
func genIPWithDash(ctx context.Context, ipChan chan<- net.IP, target string) {
	ip, _, _ := net.ParseCIDR(target)
	if ip.To4() != nil { // ipv4

		//net.IPv4bcast

	} else { // ipv6

	}

	for {
		select {
		case <-ctx.Done():
			return
		default:

		}
	}
}

// []byte{1} -> []byte{0, 0, 0, 1}
func paddingSlice4(s []byte) []byte {
	l := len(s)
	if l == net.IPv4len {
		return s
	}
	p := make([]byte, net.IPv4len)
	copy(p[4-l:], s)
	return p
}

func paddingSlice16(s []byte) []byte {
	l := len(s)
	if l == 16 {
		return s
	}
	p := make([]byte, net.IPv6len)
	copy(p[net.IPv6len-l:], s)
	return p
}
