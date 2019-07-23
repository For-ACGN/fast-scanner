package scanner

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

type Scanner struct {
	opts        *Options
	targets     []string
	ports       []string
	ctx         context.Context
	cancel      func()
	laddrsIndex int
	laddrsM     sync.Mutex
	laddrsEnd   int // len(laddrs) - 1
	laddrs      []*laddr
	Conns       chan *net.TCPConn
	startOnce   sync.Once
	stopOnce    sync.Once
	wg          sync.WaitGroup
}

func New(targets, ports string, opts *Options) (*Scanner, error) {
	if targets == "" {
		return nil, errors.New("no targets")
	}
	if ports == "" {
		return nil, errors.New("no ports")
	}
	if opts == nil {
		opts = new(Options)
	}
	opts.apply()
	s := Scanner{
		opts:  opts,
		Conns: make(chan *net.TCPConn, 128*opts.Goroutines),
	}
	targets = strings.Replace(targets, " ", "", -1)
	s.targets = strings.Split(targets, ",")
	// check ports range
	ports = strings.Replace(ports, " ", "", -1)
	s.ports = strings.Split(ports, ",")
	for _, port := range s.ports {
		n, err := strconv.Atoi(port)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if n < 1 || n > 65535 {
			return nil, errors.New("no ports")
		}
	}
	// add local address
	if opts.LocalAddrs != "" {
		str := strings.Replace(opts.LocalAddrs, " ", "", -1)
		addrs := strings.Split(str, ",")
		l := len(addrs)
		s.laddrsEnd = l - 1
		s.laddrs = make([]*laddr, l)
		for i := 0; i < l; i++ {
			ip := net.ParseIP(addrs[i])
			if ip == nil {
				return nil, errors.Errorf("invalid ip: %s", addrs[i])
			}
			var dst string
			if i := ip.To4(); i != nil {
				dst = i.String()
			} else {
				dst = "[" + ip.To16().String() + "]"
			}
			s.laddrs[i] = &laddr{
				address: dst,
				port:    minPort,
			}
		}
	} else {
		s.laddrsEnd = -1
	}
	return &s, nil
}

func (s *Scanner) Start() error {
	var err error
	s.startOnce.Do(func() {
		var ips <-chan net.IP
		s.ctx, s.cancel = context.WithCancel(context.Background())
		ips, err = GenIP(s.ctx, s.targets)
		if err != nil {
			return
		}
		for i := 0; i < s.opts.Goroutines; i++ {
			s.wg.Add(1)
			go s.dialer(ips)
		}
		go func() {
			s.wg.Wait()
			close(s.Conns)
		}()
	})
	return err
}

func (s *Scanner) Stop() {
	s.stopOnce.Do(func() {
		s.cancel()
		s.wg.Wait()
	})
}
