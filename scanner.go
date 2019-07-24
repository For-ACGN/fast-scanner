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
	targets   []string
	ports     []string
	opts      *Options
	ctx       context.Context
	cancel    func()
	Dialer    *Dialer
	Address   chan string
	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
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
		targets: split(targets),
		opts:    opts,
		Address: make(chan string, 128*opts.Goroutines),
	}
	// add port
	for _, port := range split(ports) {
		ports := strings.Split(port, "-")
		if len(ports) == 1 { // single port
			err := checkPort(ports[0])
			if err != nil {
				return nil, err
			}
			s.ports = append(s.ports, ports[0])
		} else { // with "-"
			err := checkPort(ports[0])
			if err != nil {
				return nil, err
			}
			err = checkPort(ports[1])
			if err != nil {
				return nil, err
			}
			start, _ := strconv.Atoi(ports[0])
			stop, _ := strconv.Atoi(ports[1])
			if stop > start {
				return nil, errors.New("invalid port: " + port)
			}
			for {
				s.ports = append(s.ports, strconv.Itoa(start))
				if start == stop {
					break
				}
				start += 1
			}
		}
	}
	dialer, err := NewDialer(opts.LocalIP, opts.Timeout)
	if err != nil {
		return nil, err
	}
	s.dialer = dialer
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
			go s.scanner(ips)
		}
		go func() {
			s.wg.Wait()
			close(s.Address)
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

func (s *Scanner) scanner(ips <-chan net.IP) {
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
				s.scan(ip, port)
			}
		}
	}
}

func (s *Scanner) scan(ip net.IP, port string) {
	var address string
	if len(ip) == net.IPv4len {
		address = ip.String() + ":" + port
	} else {
		address = "[" + ip.String() + "]:" + port
	}
	conn, err := s.dialer.Dial("tcp", address)
	if err != nil {
		return
	}
	address = conn.RemoteAddr().String()
	_ = conn.Close()
	select {
	case <-s.ctx.Done():
		return
	case s.Address <- address:
	}
}

func checkPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil {
		return errors.WithStack(err)
	}
	if n < 1 || n > 65535 {
		return errors.New("invalid port")
	}
	return nil
}
