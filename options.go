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
	// "syn", "connect"
	Method  string
	Device  string
	Rate    int
	Timeout time.Duration
	// "connect": connectScanner() goroutine number
	// "syn": synScanner() and synParser() goroutine number
	Workers int
	// packetSender number useless for "connect"
	Senders int
	// if true scanner will not handle duplicate result,
	// it will use less memory
	// default will handle duplicate result
	Raw bool
}

func (opt *Options) apply() {
	if opt.Method == "" {
		opt.Method = MethodSYN
	}
	if opt.Rate < 1 {
		opt.Rate = 1000
	}
	if opt.Timeout < 1 {
		switch opt.Method {
		case MethodConnect:
			opt.Timeout = 5 * time.Second
		case MethodSYN:
			opt.Timeout = 2 * time.Second
		}
	}
	if opt.Workers < 1 {
		switch opt.Method {
		case MethodConnect:
			opt.Workers = 64 * runtime.NumCPU()
		case MethodSYN:
			opt.Workers = 32 * runtime.NumCPU()
		}
	}
	if opt.Senders < 1 {
		switch runtime.GOOS {
		case "windows":
			opt.Senders = 2 // "magic send packet speed"
		case "linux":
			opt.Senders = 1 // "one goroutine will get full speed"
		default:
			opt.Senders = 1
		}
	}
}

func split(str string) []string {
	str = strings.Replace(str, " ", "", -1)
	return strings.Split(str, ",")
}
