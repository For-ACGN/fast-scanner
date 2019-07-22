package Scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"net"
	"strconv"
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
		case hyphen+dash == -2: // single ip "192.168.1.1"
			ipChan <- net.ParseIP(targets[i])
		case hyphen != -1 && dash == -1: // range "192.168.1.1-192.168.1.2"
			// same ip type
			// start < stop
			wg.Add(1)
			go func(target string) {
				defer func() {
					wg.Done()
				}()
				genIPWithHyphen(ctx, ipChan, targets[i])
			}(targets[i])
		case hyphen == -1 && dash != -1: // CIDR "192.168.1.1/24"
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
	startIP := net.ParseIP(ips[0])
	stopIP := net.ParseIP(ips[1])
	ipv4 := startIP.To4()
	if ipv4 != nil { // ipv4
		// bytes to uint32
		start := binary.BigEndian.Uint32(ipv4)
		stop := binary.BigEndian.Uint32(stopIP.To4())
		for {
			select {
			case <-ctx.Done():
				return
			default:
				ipChan <- net.IP(uint32ToBytes(start))
				if start == stop {
					return
				}
				start += 1
			}
		}
	} else { // ipv6
		delta := big.NewInt(1)
		start := new(big.Int).SetBytes(startIP.To16())
		stop := new(big.Int).SetBytes(stopIP.To16()).Bytes()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				b := start.Bytes()
				ipChan <- net.IP(paddingSlice16(b))
				if bytes.Equal(b, stop) {
					return
				}
				start.Add(start, delta)
			}
		}
	}
}

// CIDR
func genIPWithDash(ctx context.Context, ipChan chan<- net.IP, target string) {
	ip, ipnet, _ := net.ParseCIDR(target)
	n, _ := strconv.Atoi(strings.Split(ipnet.String(), "/")[1])
	if ip.To4() != nil { // ipv4
		i := uint32(0)
		hostNumber := uint32(math.Pow(2, float64(net.IPv4len*8-n)))
		address := binary.BigEndian.Uint32(ipnet.IP)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				ipChan <- net.IP(uint32ToBytes(address))
				i += 1
				if i == hostNumber {
					return
				}
				address += 1
			}
		}
	} else { // ipv6
		delta := big.NewInt(1)
		i := new(big.Int)
		hostNumber := new(big.Int).Lsh(big.NewInt(1), uint(net.IPv6len*8-n))
		hostNumber.Sub(hostNumber, delta) // for loop
		hostNumberBytes := hostNumber.Bytes()
		startIP := new(big.Int).SetBytes(ipnet.IP)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				ipChan <- net.IP(paddingSlice16(startIP.Bytes()))
				if bytes.Equal(i.Bytes(), hostNumberBytes) {
					return
				}
				i.Add(i, delta)
				startIP.Add(startIP, delta)
			}
		}
	}
}

func uint32ToBytes(n uint32) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, n)
	return buffer
}

// []byte{1} -> []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
func paddingSlice16(s []byte) []byte {
	l := len(s)
	if l == 16 {
		return s
	}
	p := make([]byte, net.IPv6len)
	copy(p[net.IPv6len-l:], s)
	return p
}
