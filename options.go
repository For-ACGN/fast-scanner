package scanner

import (
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
}

func split(str string) []string {
	str = strings.Replace(str, " ", "", -1)
	return strings.Split(str, ",")
}
