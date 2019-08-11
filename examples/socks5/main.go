package main

import (
	"bufio"
	"bytes"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"time"

	"github.com/For-ACGN/fast-scanner"
)

type auth struct {
	Username string
	Password string
}

type logger struct {
	file *os.File
}

func (l *logger) Write(p []byte) (n int, err error) {
	_, _ = os.Stderr.Write(p)
	return l.file.Write(p)
}

func main() {
	var (
		targets  string
		ports    string
		method   string
		device   string
		rate     int
		timeout  time.Duration
		workers  int
		senders  int
		save     string
		crackers int
		username string
		password string
	)
	tu := bytes.Buffer{}
	tu.WriteString("192.168.1.1, fe80::1\n")
	tu.WriteString("192.168.1.1-192.168.1.3, fe80::1-fe80::1\n")
	tu.WriteString("192.168.1.1/24")
	flag.StringVar(&targets, "targets", "", tu.String())
	flag.StringVar(&ports, "ports", "", "80, 81-82")
	flag.StringVar(&method, "method", scanner.MethodSYN, "connect or syn")
	flag.StringVar(&device, "device", "", "interface name Ethernet0, eth0")
	flag.IntVar(&rate, "rate", 1000, "send packet rate")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "timeout")
	flag.IntVar(&workers, "workers", 0, "scanner number")
	flag.IntVar(&senders, "senders", 0, "packet sender number")
	flag.StringVar(&save, "save", "", "result file path")
	flag.IntVar(&crackers, "crackers", 16*runtime.NumCPU(), "crackers number")
	flag.StringVar(&username, "username", "", "username file fath")
	flag.StringVar(&password, "password", "", "password file fath")
	flag.Parse()
	opts := scanner.Options{
		Method:  method,
		Device:  device,
		Rate:    rate,
		Timeout: timeout,
		Workers: workers,
		Senders: senders,
	}
	if save != "" {
		file, err := os.OpenFile(save, os.O_CREATE|os.O_APPEND, 644)
		if err != nil {
			log.Println(err)
			return
		}
		log.SetOutput(&logger{file: file})
	}
	// read username password
	var (
		usernames []string
		passwords []string
	)
	if username != "" {
		file, err := os.Open(username)
		if err != nil {
			log.Println(err)
			return
		}
		reader := bufio.NewReader(file)
		for {
			username, _, err := reader.ReadLine()
			if err != nil {
				break
			}
			if username != nil {
				usernames = append(usernames, string(username))
			}
		}
	}
	if password != "" {
		file, err := os.Open(password)
		if err != nil {
			log.Println(err)
			return
		}
		reader := bufio.NewReader(file)
		for {
			password, _, err := reader.ReadLine()
			if err != nil {
				break
			}
			if password != nil {
				passwords = append(passwords, string(password))
			}
		}
	}
	// make password directory
	usernamesLen := len(usernames)
	passwordsLen := len(passwords)
	authsLen := usernamesLen * (passwordsLen + 1)
	auths := make([]*auth, authsLen) // NULL
	index := 0
	for i := 0; i < usernamesLen; i++ {
		// add NULL
		auths[index] = &auth{Username: usernames[i]}
		index += 1
		for j := 0; j < len(passwords); j++ {
			auths[index] = &auth{
				Username: usernames[i],
				Password: passwords[j],
			}
			index += 1
		}
	}
	// init scanner
	s, err := scanner.New(targets, ports, &opts)
	if err != nil {
		log.Fatalln(err)
	}
	start := time.Now()
	err = s.Start()
	if err != nil {
		log.Fatalln(err)
	}
	stopSignal := make(chan struct{})
	wg := sync.WaitGroup{}
	go func() {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Kill, os.Interrupt)
		<-signalChan
		s.Stop()
		close(stopSignal)
		wg.Wait()
		log.Print("stop scanner.\r\n")
	}()
	// init crackers
	// more localIPs can lift scan speed
	// > 65536 conns at the same time
	iface, err := scanner.SelectInterface(device)
	if err != nil {
		log.Fatalln(err)
	}
	l := len(iface.IPNets)
	localIPs := make([]string, l)
	for i := 0; i < l; i++ {
		localIPs[i] = iface.IPNets[i].IP.String()
	}
	dialer, err := scanner.NewDialer(localIPs, timeout)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; i < crackers; i++ {
		c := cracker{
			address:    s.Result,
			dialer:     dialer,
			timeout:    timeout,
			auths:      auths,
			authsLen:   authsLen,
			stopSignal: stopSignal,
			wg:         &wg,
		}
		wg.Add(1)
		go c.Do()
	}
	wg.Wait()
	log.Printf("scan finished. time: %s\r\n", time.Since(start))
}
