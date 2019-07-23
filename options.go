package scanner

import (
	"runtime"
	"time"
)

type Options struct {
	LocalAddrs   string
	Goroutines   int
	DialTimeout  time.Duration
	ConnDeadline time.Duration
}

func (opt *Options) apply() {
	if opt.Goroutines < 1 {
		opt.Goroutines = 4096 * runtime.NumCPU()
	}
	if opt.DialTimeout < 1 {
		opt.DialTimeout = 3 * time.Second
	}
	if opt.ConnDeadline < 1 {
		opt.ConnDeadline = 3 * time.Second
	}
}
