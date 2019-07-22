package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

func GenTargets(ctx context.Context, target string) (<-chan net.IP, error) {
	return GenIP(ctx, ParseTargets(target))
}

// ParseAddress is used to parse target like
// "192.168.1.1,192.168.1.1/24,192.168.1.1-192.168.1.254"
// to address slice []string{"192.168.1.1", "192.168.1.0/24",
// "192.168.1.1-192.168.1.254"}
func ParseTargets(str string) []string {
	addrs := strings.Split(str, ",")
	for i := 0; i < len(addrs); i++ {
		addrs[i] = strings.Replace(addrs[i], " ", "", -1)
	}
	return addrs
}

func GenIP(ctx context.Context, targets []string) (<-chan net.IP, error) {
	ctx, cancel := context.WithCancel(ctx)
	l := len(targets)
	ipChan := make(chan net.IP, l)
	wg := &sync.WaitGroup{}
	wait := func() {
		wg.Wait()
		close(ipChan)
	}
	interrupt := func() {
		cancel()
		wait()
	}
	for i := 0; i < l; i++ {
		hyphen := strings.Index(targets[i], "-")
		dash := strings.Index(targets[i], "/")
		switch {
		case hyphen+dash == -2: // single ip "192.168.1.1"
			ip := net.ParseIP(targets[i])
			if ip.To4() == nil {
				if ip.To16() == nil {
					interrupt()
					return nil, errors.New("invalid ip: " + targets[i])
				}
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case ipChan <- ip:
				case <-ctx.Done():
					return
				}
			}()
		case hyphen != -1 && dash == -1: // range "192.168.1.1-192.168.1.2"
			ips := strings.Split(targets[i], "-")
			if len(ips) != 2 {
				interrupt()
				return nil, errors.New("invalid target: " + targets[i])
			}
			// check is same ip type
			startIP := net.ParseIP(ips[0])
			stopIP := net.ParseIP(ips[1])
			startIPType := 0 // ipv4 = 0 ipv6 = 1
			stopIPType := 0
			if startIP.To4() == nil {
				if startIP.To16() != nil {
					startIPType = 1
				} else {
					interrupt()
					return nil, errors.New("invalid start ip: " + targets[i])
				}
			}
			if stopIP.To4() == nil {
				if stopIP.To16() != nil {
					stopIPType = 1
				} else {
					interrupt()
					return nil, errors.New("invalid stop ip: " + targets[i])
				}
			}
			if startIPType != stopIPType {
				interrupt()
				return nil, errors.New("different ip type: " + targets[i])
			}
			// start <= stop
			start := new(big.Int)
			stop := new(big.Int)
			switch startIPType {
			case 0:
				start.SetBytes(startIP.To4())
				stop.SetBytes(stopIP.To4())
			case 1:
				start.SetBytes(startIP.To16())
				stop.SetBytes(stopIP.To16())
			}
			if start.Cmp(stop) == 1 {
				interrupt()
				return nil, errors.New("start ip > stop ip: " + targets[i])
			}
			wg.Add(1)
			go func(target string) {
				defer func() {
					wg.Done()
				}()
				genIPWithHyphen(ctx, ipChan, target)
			}(targets[i])
		case hyphen == -1 && dash != -1: // CIDR "192.168.1.1/24"
			_, _, err := net.ParseCIDR(targets[i])
			if err != nil {
				interrupt()
				return nil, errors.New("invalid CIDR" + targets[i])
			}
			wg.Add(1)
			go func(target string) {
				defer func() {
					wg.Done()
				}()
				genIPWithDash(ctx, ipChan, target)
			}(targets[i])
		case hyphen != -1 && dash != -1: // "192.168.1.1-192.168.1.2/24"
			interrupt()
			return nil, errors.New("invalid target: " + targets[i])
		}
	}
	go wait()
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
			case ipChan <- net.IP(uint32ToBytes(start)):
			case <-ctx.Done():
				return
			}
			if start == stop {
				return
			}
			start += 1
		}
	} else { // ipv6
		delta := big.NewInt(1)
		start := new(big.Int).SetBytes(startIP.To16())
		stop := new(big.Int).SetBytes(stopIP.To16()).Bytes()
		for {
			b := start.Bytes()
			select {
			case ipChan <- net.IP(paddingSlice16(b)):
			case <-ctx.Done():
				return
			}
			if bytes.Equal(b, stop) {
				return
			}
			start.Add(start, delta)
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
			case ipChan <- net.IP(uint32ToBytes(address)):
			case <-ctx.Done():
				return
			}
			i += 1
			if i == hostNumber {
				return
			}
			address += 1
		}
	} else { // ipv6
		// TODO ipv6 CIDR
		/*
			delta := big.NewInt(1)
			i := new(big.Int)
			hostNumber := new(big.Int).Lsh(big.NewInt(1), uint(net.IPv6len*8-n))
			hostNumber.Sub(hostNumber, delta) // for loop
			hostNumberBytes := hostNumber.Bytes()
			startIP := new(big.Int).SetBytes(ipnet.IP)
			for {
				select {
				case ipChan <- net.IP(paddingSlice16(startIP.Bytes())):
				case <-ctx.Done():
					return
				}
				if bytes.Equal(i.Bytes(), hostNumberBytes) {
					return
				}
				i.Add(i, delta)
				startIP.Add(startIP, delta)
			}
		*/
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
