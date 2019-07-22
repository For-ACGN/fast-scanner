package scanner

import (
	"context"
	"net"
	"runtime"
	"time"
)

type Options struct {
	LocalAddrs   string
	Goroutines   int
	Dialer       Dialer
	DialTimeout  time.Duration
	ConnDeadline time.Duration
}

func (opt *Options) apply() {
	if opt.Goroutines < 1 {
		opt.Goroutines = 8 * runtime.NumCPU()
	}
	if opt.DialTimeout < 1 {
		opt.DialTimeout = 3 * time.Second
	}
	if opt.Dialer == nil {
		opt.Dialer = &net.Dialer{Timeout: opt.DialTimeout}
	}
}

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
