package scanner

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

type Scanner struct {
	targets     string
	ports       string
	opts        *Options
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
		targets: targets,
		ports:   ports,
		opts:    opts,
		Conns:   make(chan *net.TCPConn, 128*opts.Goroutines),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	// add local address
	if opts.LocalAddrs != "" {
		str := strings.Replace(opts.LocalAddrs, " ", "", -1)
		addrs := strings.Split(str, ",")
		l := len(addrs)
		s.laddrsEnd = l - 1
		s.laddrs = make([]*laddr, l)
		for i := 0; i < l; i++ {
			s.laddrs[i] = &laddr{
				address: addrs[i],
				port:    minPort,
			}
		}
	} else {
		s.laddrsEnd = -1
	}
	return &s, nil
}

func (s *Scanner) Start() error {
	s.startOnce.Do(func() {
		ips, err := GenTargets(s.ctx, s.targets)
		if err != nil {
			return
		}
		for i := 0; i < s.opts.Goroutines; i++ {
			s.wg.Add(1)
			go s.dialer(ips)
		}
	})

	return nil
}

func (s *Scanner) Stop() {
	s.stopOnce.Do(func() {
		s.cancel()
		s.wg.Wait()
	})
}
