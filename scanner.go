package scanner

import (
	"encoding/binary"
	"math/big"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

type Scanner struct {
	method    string
	targets   []string
	ports     map[string]struct{}
	opts      *Options
	generator *Generator
	// about count
	hostNum    *big.Int
	scannedNum *big.Int
	delta      *big.Int
	numMu      sync.Mutex
	// about handle duplicate result
	resultsv4   map[[net.IPv4len + 2]byte]struct{} // ip+port
	resultsv4Mu sync.Mutex
	resultsv6   map[[net.IPv6len + 2]byte]struct{}
	resultsv6Mu sync.Mutex
	// about scanning
	Result      chan string
	dialer      *Dialer    // connect
	iface       *Interface // syn
	route       *router
	salt        []byte
	sendQueue   chan []byte // sendPacket
	recvQueue   chan []byte // synCapturer -> synParser
	gatewayMACs map[string]net.HardwareAddr
	gatewayMu   sync.Mutex
	tokenBucket chan struct{} // rate
	// control
	started    int32
	stopped    int32
	stopSignal chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup
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
	if !opts.Raw { // handle duplicate result
		s.resultsv4 = make(map[[net.IPv4len + 2]byte]struct{})
		s.resultsv6 = make(map[[net.IPv6len + 2]byte]struct{})
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
	if !atomic.CompareAndSwapInt32(&s.started, 0, 1) {
		return errors.New("started")
	}
	var err error
	s.generator, err = NewGenerator(s.targets)
	if err != nil {
		return err
	}
	// calculate host number
	n := s.generator.N
	s.hostNum = n.Mul(n, big.NewInt(int64(len(s.ports))))
	switch s.method {
	case MethodSYN:
		if initErr != nil {
			s.Stop()
			return initErr
		}
		s.iface, err = SelectInterface(s.opts.Device)
		if err != nil {
			s.Stop()
			return err
		}
		s.route, err = newRouter(s.iface)
		if err != nil {
			s.Stop()
			return err
		}
		s.sendQueue = make(chan []byte, 1024*s.opts.Workers)
		s.recvQueue = make(chan []byte, 1024*s.opts.Workers)
		s.gatewayMACs = make(map[string]net.HardwareAddr, 2)
		// init salt for validate
		random := rand.New(rand.NewSource(time.Now().UnixNano()))
		s.salt = make([]byte, 16)
		for i := 0; i < 16; i++ {
			s.salt[i] = byte(random.Intn(256))
		}
		var (
			sendersWG  sync.WaitGroup
			parsersWG  sync.WaitGroup
			scannersWG sync.WaitGroup
		)
		errWait := func() {
			sendersWG.Wait()
			parsersWG.Wait()
			scannersWG.Wait()
		}
		// start packetSenders
		for i := 0; i < s.opts.Senders; i++ {
			handle, err := s.newSenderHandle()
			if err != nil {
				s.Stop()
				errWait()
				return err
			}
			sendersWG.Add(1)
			go s.packetSender(&sendersWG, handle)
		}
		// start capturer
		iHandle, err := pcap.NewInactiveHandle(s.iface.Device)
		if err != nil {
			s.Stop()
			errWait()
			return err
		}
		_ = iHandle.SetSnapLen(snaplen)
		_ = iHandle.SetPromisc(false)
		_ = iHandle.SetTimeout(pcap.BlockForever)
		_ = iHandle.SetImmediateMode(true)
		capHandle, err := iHandle.Activate()
		iHandle.CleanUp()
		if err != nil {
			s.Stop()
			errWait()
			return err
		}
		parsersWG.Add(1)
		go s.synCapturer(&parsersWG, capHandle)
		// start parsers
		for i := 0; i < s.opts.Workers; i++ {
			handle, err := s.newSenderHandle()
			if err != nil {
				capHandle.Close()
				s.Stop()
				errWait()
				return err
			}
			parsersWG.Add(1)
			go s.synParser(&parsersWG, handle)
		}
		// wait to prepare read
		time.Sleep(250 * time.Millisecond)
		// start scanners
		for i := 0; i < s.opts.Workers; i++ {
			handle, err := s.newSenderHandle()
			if err != nil {
				capHandle.Close()
				s.Stop()
				errWait()
				return err
			}
			scannersWG.Add(1)
			go s.synScanner(&scannersWG, handle)
		}
		// wait
		s.wg.Add(1)
		go func() {
			// wait scanner
			scannersWG.Wait()
			// check is s.Stop() or send finish
			select {
			case <-s.stopSignal:
			default: // send finish and wait
				time.Sleep(s.opts.Timeout)
			}
			// close capturer
			capHandle.Close()
			// wait parsers
			parsersWG.Wait()
			// wait senders
			close(s.sendQueue)
			sendersWG.Wait()
			// wait addTokenLoop return
			s.closeOnce.Do(func() {
				close(s.stopSignal)
			})
			s.wg.Done()
			close(s.Result)
		}()
	case MethodConnect:
		var localIPs []string
		if s.opts.Device != "" {
			iface, err := SelectInterface(s.opts.Device)
			if err != nil {
				s.Stop()
				return err
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
			return err
		}
		workersWG := sync.WaitGroup{}
		for i := 0; i < s.opts.Workers; i++ {
			workersWG.Add(1)
			go s.connectScanner(&workersWG)
		}
		// wait
		s.wg.Add(1)
		go func() {
			// wait connectScanners
			workersWG.Wait()
			// wait addTokenLoop return
			s.closeOnce.Do(func() {
				close(s.stopSignal)
			})
			s.wg.Done()
			close(s.Result)
		}()
	default:
		s.Stop()
		return errors.New("invalid method")
	}
	s.wg.Add(1)
	go s.addTokenLoop()
	return err
}

func (s *Scanner) Stop() {
	if atomic.CompareAndSwapInt32(&s.stopped, 0, 1) {
		s.generator.Close()
		s.closeOnce.Do(func() {
			close(s.stopSignal)
		})
		s.wg.Wait()
	}
}

func (s *Scanner) addTokenLoop() {
	ticker := time.NewTicker(time.Second)
	defer func() {
		ticker.Stop()
		s.wg.Done()
	}()
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

// handle duplicate result
func (s *Scanner) addResult(ip net.IP, port string) (stop bool) {
	if s.opts.Raw {
		var address string
		if ipv4 := ip.To4(); ipv4 != nil {
			address = ipv4.String() + ":" + port
		} else {
			address = "[" + ip.String() + "]:" + port
		}
		select {
		case s.Result <- address:
		case <-s.stopSignal:
			stop = true
		}
	} else {
		pn, _ := strconv.Atoi(port) // port number
		pb := make([]byte, 2)       // port slice
		binary.BigEndian.PutUint16(pb, uint16(pn))
		if ipv4 := ip.To4(); ipv4 != nil { // ipv4
			var array [net.IPv4len + 2]byte
			copy(array[:], ipv4)
			copy(array[net.IPv4len:], pb)
			s.resultsv4Mu.Lock()
			if _, ok := s.resultsv4[array]; ok {
				s.resultsv4Mu.Unlock()
			} else {
				s.resultsv4[array] = struct{}{}
				s.resultsv4Mu.Unlock()
				// send result
				select {
				case s.Result <- ipv4.String() + ":" + port:
				case <-s.stopSignal:
					stop = true
				}
			}
		} else { // ipv6
			var array [net.IPv6len + 2]byte
			copy(array[:], ip)
			copy(array[net.IPv6len:], pb)
			s.resultsv6Mu.Lock()
			if _, ok := s.resultsv6[array]; ok {
				s.resultsv6Mu.Unlock()
			} else {
				s.resultsv6[array] = struct{}{}
				s.resultsv6Mu.Unlock()
				// send result
				select {
				case s.Result <- "[" + ip.String() + "]:" + port:
				case <-s.stopSignal:
					stop = true
				}
			}
		}
	}
	return
}

func (s *Scanner) addScanned() {
	s.numMu.Lock()
	s.scannedNum.Add(s.scannedNum, s.delta)
	s.numMu.Unlock()
}

func (s *Scanner) HostNum() *big.Int {
	n := big.Int{}
	n.SetBytes(s.hostNum.Bytes())
	return &n
}

func (s *Scanner) Scanned() *big.Int {
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
