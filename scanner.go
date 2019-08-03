package scanner

import (
	"math/big"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

type Scanner struct {
	method      string
	targets     []string
	ports       map[string]struct{}
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
	Result      chan string
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
		ports:       make(map[string]struct{}, 1),
		opts:        opts,
		tokenBucket: make(chan struct{}, opts.Rate),
		scannedNum:  big.NewInt(0),
		delta:       big.NewInt(1),
		Result:      make(chan string, 16*opts.Workers),
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
			s.ports[ports[0]] = struct{}{}
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
			if start > stop {
				return nil, errors.New("invalid port: " + port)
			}
			for {
				s.ports[strconv.Itoa(start)] = struct{}{}
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
		switch s.method {
		case MethodSYN:
			if initErr != nil {
				err = initErr
				s.Stop()
				return
			}
			s.iface, err = SelectInterface(s.opts.Device)
			if err != nil {
				s.Stop()
				return
			}
			s.route, err = newRouter(s.iface)
			if err != nil {
				s.Stop()
				return
			}
			s.packetChan = make(chan []byte, 1024*s.opts.Workers)
			s.gatewayMACs = make(map[string]net.HardwareAddr, 2)
			// init salt for validate
			random := rand.New(rand.NewSource(time.Now().UnixNano()))
			s.salt = make([]byte, 16)
			for i := 0; i < 16; i++ {
				s.salt[i] = byte(random.Intn(256))
			}
			var (
				ihandle   *pcap.InactiveHandle
				capHandle *pcap.Handle // capturer
				parHandle *pcap.Handle // parser
				sanHanlde *pcap.Handle // scanner
			)
			// start capturer
			ihandle, err = pcap.NewInactiveHandle(s.iface.Device)
			if err != nil {
				s.Stop()
				return
			}
			_ = ihandle.SetSnapLen(snaplen)
			_ = ihandle.SetPromisc(false)
			_ = ihandle.SetTimeout(pcap.BlockForever)
			_ = ihandle.SetImmediateMode(true)
			capHandle, err = ihandle.Activate()
			ihandle.CleanUp()
			if err != nil {
				s.Stop()
				return
			}
			s.wg.Add(1)
			go s.synCapturer(capHandle)
			// start parser
			for i := 0; i < s.opts.Workers; i++ {
				parHandle, err = s.newSenderHandle()
				if err != nil {
					capHandle.Close()
					s.Stop()
					return
				}
				s.wg.Add(1)
				go s.synParser(parHandle)
			}
			// wait to prepare read
			time.Sleep(250 * time.Millisecond)
			// start scanner
			scannerWG := new(sync.WaitGroup)
			for i := 0; i < s.opts.Workers; i++ {
				sanHanlde, err = s.newSenderHandle()
				if err != nil {
					capHandle.Close()
					s.Stop()
					return
				}
				scannerWG.Add(1)
				go s.synScanner(scannerWG, sanHanlde)
				time.Sleep(10 * time.Millisecond)
			}
			// wait finish
			s.wg.Add(1)
			go func() {
				// wait scanner
				scannerWG.Wait()
				select {
				case <-s.stopSignal: // stop
				default: // send finish and wait
					time.Sleep(s.opts.Timeout)
				}
				// close capturer
				capHandle.Close()
				s.wg.Done()
			}()
		case MethodConnect:
			var localIPs []string
			if s.opts.Device != "" {
				iface, e := SelectInterface(s.opts.Device)
				if e != nil {
					err = e
					s.Stop()
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
				s.Stop()
				return
			}
			for i := 0; i < s.opts.Workers; i++ {
				s.wg.Add(1)
				go s.connectScanner()
			}
		default:
			err = errors.New("invalid method")
			s.Stop()
			return
		}
		// token bucket
		go s.addTokenLoop() // not set wg
		// wait to finish
		go func() {
			s.wg.Wait()
			close(s.Result)
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

// auto return
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
