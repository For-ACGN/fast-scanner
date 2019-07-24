package scanner

import (
	"runtime"
	"time"
)

type Options struct {
	LocalIP    string
	Goroutines int
	Timeout    time.Duration
}

func (opt *Options) apply() {
	if opt.Goroutines < 1 {
		opt.Goroutines = 512 * runtime.NumCPU()
	}
	if opt.Timeout < 1 {
		opt.Timeout = 3 * time.Second
	}
}
