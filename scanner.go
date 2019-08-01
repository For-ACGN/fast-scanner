package scanner

import (
	"math/big"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var (
	buffer = 128 * runtime.NumCPU()
)

type Scanner struct {
	method      string
	targets     []string
	ports       []string
	opts        *Options
	generator   *Generator
	hostNum     *big.Int
	scannedNum  *big.Int
	delta       *big.Int
	numMutex    sync.Mutex
	dialer      *Dialer       // for connect
	tokenBucket chan struct{} // for rate
	Address     chan string
	startOnce   sync.Once
	stopOnce    sync.Once
	stopSignal  chan struct{}
	wg          sync.WaitGroup
}

func New(targets, ports string, opts *Options) (*Scanner, error) {
	if targets == "" {
		return nil, errors.New("no target")
	}
	if ports == "" {
		return nil, errors.New("no port")
	}
	if opts == nil {
		opts = new(Options)
	}
	opts.apply()
	s := Scanner{
		method:      opts.Method,
		targets:     split(targets),
		opts:        opts,
		tokenBucket: make(chan struct{}, buffer),
		delta:       big.NewInt(1),
		Address:     make(chan string, buffer),
		stopSignal:  make(chan struct{}),
	}
	// set ports
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

	return &s, nil
}

func (s *Scanner) Start() error {
	var err error
	s.startOnce.Do(func() {
		s.generator, err = NewGenerator(s.targets)
		if err != nil {
			return
		}
		// calculate host number
		n := s.generator.N
		s.hostNum = n.Mul(n, big.NewInt(int64(len(s.ports))))
		go s.addTokenLoop()
		switch s.method {
		case MethodSYN:

		case MethodConnect:
			var localIPs []string
			if s.opts.Device != "" {
				iface, e := selectInterface(s.opts.Device)
				if e != nil {
					err = e
					return
				}
				l := len(iface.IPNets)
				localIPs = make([]string, l)
				for i := 0; i < l; i++ {
					localIPs[i] = iface.IPNets[i].IP.String()
				}
			}
			s.dialer, err = NewDialer(localIPs, s.opts.Timeout)
			if err != nil {
				return
			}
			workers := 512 * runtime.NumCPU()
			for i := 0; i < workers; i++ {
				s.wg.Add(1)
				go s.connectScanner()
			}
		default:
			err = errors.New("invalid method")
		}
		go func() {
			s.wg.Wait()
			close(s.Address)
			s.stopOnce.Do(func() {
				close(s.stopSignal)
			})
		}()
	})
	return err
}

func (s *Scanner) Stop() {
	s.stopOnce.Do(func() {
		s.generator.Close()
		close(s.stopSignal)
		s.wg.Wait()
	})
}

func (s *Scanner) addTokenLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			for i := 0; i < s.opts.Rate; i++ {
				select {
				case s.tokenBucket <- struct{}{}:
				case <-s.stopSignal:
					return
				}
			}
		case <-s.stopSignal:
			return
		}
	}
}

func (s *Scanner) addScanned() {
	s.numMutex.Lock()
	s.scannedNum.Add(s.scannedNum, s.delta)
	s.numMutex.Unlock()
}

func (s *Scanner) HostNumber() *big.Int {
	n := big.Int{}
	n.SetBytes(s.hostNum.Bytes())
	return &n
}

func (s *Scanner) ScannedNumber() *big.Int {
	n := big.Int{}
	s.numMutex.Lock()
	n.SetBytes(s.scannedNum.Bytes())
	s.numMutex.Unlock()
	return &n
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
