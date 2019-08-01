package scanner

import (
	"math/big"
	"math/rand"
	"net"
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
	numMu       sync.Mutex
	dialer      *Dialer    // for connect and syn
	iface       *Interface // for syn
	route       *route
	salt        []byte
	packetChan  chan []byte
	gatewayMACs map[string]net.HardwareAddr
	gatewayMu   sync.Mutex
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
		scannedNum:  big.NewInt(0),
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
		// token bucket
		go s.addTokenLoop()
		handleErr := func(e error) {
			s.Stop()
			err = e
		}
		switch s.method {
		case MethodSYN:
			if initErr != nil {
				handleErr(initErr)
				return
			}
			s.iface, err = selectInterface(s.opts.Device)
			if err != nil {
				handleErr(err)
				return
			}
			s.route, err = newRouter(s.iface)
			if err != nil {
				handleErr(err)
				return
			}
			s.packetChan = make(chan []byte, 1024*runtime.NumCPU())
			s.gatewayMACs = make(map[string]net.HardwareAddr, 2)
			workers := 1 // 4 * runtime.NumCPU()
			errChan := make(chan error, workers)
			// init salt for validate
			random := rand.New(rand.NewSource(time.Now().UnixNano()))
			s.salt = make([]byte, 16)
			for i := 0; i < 16; i++ {
				s.salt[0] = byte(random.Intn(256))
			}
			s.wg.Add(1)
			go func() {
				for _, port := range s.ports {
					// init listener
					go s.synCapturer(port, errChan)
					e := <-errChan
					if e != nil {
						handleErr(e)
						return
					}
					// init scanner
					for i := 0; i < workers; i++ {
						s.wg.Add(1)
						go s.synScanner(port, errChan)
					}
					for i := 0; i < workers; i++ {
						e = <-errChan
						if e != nil {
							handleErr(e)
							return
						}
					}
					go s.synParser(port)
				}
			}()

			// close(errChan)
		case MethodConnect:
			var localIPs []string
			if s.opts.Device != "" {
				iface, e := selectInterface(s.opts.Device)
				if e != nil {
					handleErr(e)
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
				handleErr(err)
				return
			}
			workers := 512 * runtime.NumCPU()
			for i := 0; i < workers; i++ {
				s.wg.Add(1)
				go s.connectScanner()
			}
		default:
			handleErr(errors.New("invalid method"))
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
	s.numMu.Lock()
	s.scannedNum.Add(s.scannedNum, s.delta)
	s.numMu.Unlock()
}

func (s *Scanner) HostNumber() *big.Int {
	n := big.Int{}
	n.SetBytes(s.hostNum.Bytes())
	return &n
}

func (s *Scanner) ScannedNumber() *big.Int {
	n := big.Int{}
	s.numMu.Lock()
	n.SetBytes(s.scannedNum.Bytes())
	s.numMu.Unlock()
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
