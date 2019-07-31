package scanner

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

type Generator struct {
	N    *big.Int // host number will be generate
	IP   chan net.IP
	wg   sync.WaitGroup
	once sync.Once
	stop chan struct{}
}

func (g *Generator) Close() {
	g.once.Do(func() {
		close(g.stop)
	})
	g.wg.Wait()
}

// Range
func (g *Generator) genIPWithHyphen(target string) {
	ips := strings.Split(target, "-")
	startIP := net.ParseIP(ips[0])
	stopIP := net.ParseIP(ips[1])
	ipv4 := startIP.To4()
	if ipv4 != nil { // ipv4
		// bytes to uint32
		start := binary.BigEndian.Uint32(ipv4)
		stop := binary.BigEndian.Uint32(stopIP.To4())
		// add host number
		g.N.Add(g.N, big.NewInt(int64(stop-start+1)))
		// generate
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			for {
				select {
				case g.IP <- net.IP(uint32ToBytes(start)):
				case <-g.stop:
					return
				}
				if start == stop {
					return
				}
				start += 1
			}
		}()
	} else { // ipv6
		delta := big.NewInt(1)
		start := new(big.Int).SetBytes(startIP.To16())
		stop := new(big.Int).SetBytes(stopIP.To16())
		stopBytes := stop.Bytes()
		// add host number
		g.N.Add(g.N, stop.Sub(stop, start))
		g.N.Add(g.N, delta)
		// generate
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			for {
				b := start.Bytes()
				select {
				case g.IP <- net.IP(paddingSlice16(b)):
				case <-g.stop:
					return
				}
				if bytes.Equal(b, stopBytes) {
					return
				}
				start.Add(start, delta)
			}
		}()
	}
}

// CIDR
func (g *Generator) genIPWithDash(target string) {
	ip, ipnet, _ := net.ParseCIDR(target)
	n, _ := strconv.Atoi(strings.Split(ipnet.String(), "/")[1])
	if ip.To4() != nil { // ipv4
		i := uint32(0)
		hostNumber := uint32(math.Pow(2, float64(net.IPv4len*8-n)))
		// add host number
		g.N.Add(g.N, big.NewInt(int64(hostNumber)))
		// generate
		address := binary.BigEndian.Uint32(ipnet.IP)
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			for {
				select {
				case g.IP <- net.IP(uint32ToBytes(address)):
				case <-g.stop:
					return
				}
				i += 1
				if i == hostNumber {
					return
				}
				address += 1
			}
		}()
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

func NewGenerator(targets []string) (*Generator, error) {
	l := len(targets)
	g := Generator{
		N:    big.NewInt(0),
		IP:   make(chan net.IP, l),
		stop: make(chan struct{}),
	}
	for _, target := range targets {
		hyphen := strings.Index(target, "-")
		dash := strings.Index(target, "/")
		switch {
		case hyphen+dash == -2: // single ip "192.168.1.1"
			ip := net.ParseIP(target)
			if ip == nil {
				g.Close()
				return nil, errors.New("invalid ip: " + target)
			}
			var dst net.IP
			if i := ip.To4(); i != nil {
				dst = i
			} else {
				dst = ip.To16()
			}
			// add host number
			g.N.Add(g.N, big.NewInt(1))
			// generate
			g.wg.Add(1)
			go func() {
				defer g.wg.Done()
				select {
				case g.IP <- dst:
				case <-g.stop:
					return
				}
			}()
		case hyphen != -1 && dash == -1: // range "192.168.1.1-192.168.1.2"
			const (
				ipv4 = 0
				ipv6 = 1
			)
			ips := strings.Split(target, "-")
			if len(ips) != 2 {
				g.Close()
				return nil, errors.New("invalid target: " + target)
			}
			// check is same ip type
			startIP := net.ParseIP(ips[0])
			stopIP := net.ParseIP(ips[1])
			startIPType := ipv4
			stopIPType := ipv4
			if startIP.To4() == nil {
				if startIP.To16() != nil {
					startIPType = ipv6
				} else {
					g.Close()
					return nil, errors.New("invalid start ip: " + target)
				}
			}
			if stopIP.To4() == nil {
				if stopIP.To16() != nil {
					stopIPType = ipv6
				} else {
					g.Close()
					return nil, errors.New("invalid stop ip: " + target)
				}
			}
			if startIPType != stopIPType {
				g.Close()
				return nil, errors.New("different ip type: " + target)
			}
			// check start <= stop
			start := new(big.Int)
			stop := new(big.Int)
			switch startIPType {
			case ipv4:
				start.SetBytes(startIP.To4())
				stop.SetBytes(stopIP.To4())
			case ipv6:
				start.SetBytes(startIP.To16())
				stop.SetBytes(stopIP.To16())
			}
			if start.Cmp(stop) == 1 {
				g.Close()
				return nil, errors.New("start ip > stop ip: " + target)
			}
			g.genIPWithHyphen(target)
		case hyphen == -1 && dash != -1: // CIDR "192.168.1.1/24"
			_, _, err := net.ParseCIDR(target)
			if err != nil {
				g.Close()
				return nil, errors.New("invalid CIDR" + target)
			}
			g.genIPWithDash(target)
		case hyphen != -1 && dash != -1: // "192.168.1.1-192.168.1.2/24"
			g.Close()
			return nil, errors.New("invalid target: " + target)
		}
	}
	// if all generated close ip chan
	go func() {
		g.wg.Wait()
		close(g.IP)
	}()
	return &g, nil
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
