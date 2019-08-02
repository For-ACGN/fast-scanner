package scanner

import (
	"runtime"
	"strings"
	"time"
)

const (
	MethodSYN     = "syn"
	MethodConnect = "connect"
)

type Options struct {
	Method  string // "syn", "connect"
	Device  string
	Rate    int
	Timeout time.Duration
	Workers int
}

func (opt *Options) apply() {
	if opt.Method == "" {
		opt.Method = MethodSYN
	}
	if opt.Rate < 1 {
		opt.Rate = 1000
	}
	if opt.Timeout < 1 {
		opt.Timeout = 10 * time.Second
	}
	if opt.Workers < 1 {
		switch opt.Method {
		case MethodConnect:
			opt.Workers = 512 * runtime.NumCPU()
		case MethodSYN:
			opt.Workers = 8 * runtime.NumCPU()
		}
	}
}

func split(str string) []string {
	str = strings.Replace(str, " ", "", -1)
	return strings.Split(str, ",")
}
