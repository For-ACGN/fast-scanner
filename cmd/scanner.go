package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/For-ACGN/fast-scanner"
)

type logger struct {
	file *os.File
}

func (l *logger) Write(p []byte) (n int, err error) {
	_, _ = os.Stderr.Write(p)
	return l.file.Write(p)
}

func main() {
	var (
		targets string
		ports   string
		method  string
		device  string
		rate    int
		timeout time.Duration
		workers int
		senders int
		save    string
	)
	tu := bytes.Buffer{}
	tu.WriteString("host: 192.168.1.1, fe80::1\n")
	tu.WriteString("192.168.1.1-192.168.1.3, fe80::1-fe80::1\n")
	tu.WriteString("192.168.1.1/24")
	flag.StringVar(&targets, "h", "", tu.String())
	flag.StringVar(&ports, "p", "", "ports: 80, 81-82")
	flag.StringVar(&method, "m", scanner.MethodSYN, "method connect or syn")
	flag.StringVar(&device, "d", "", "device: interface name Ethernet0, eth0")
	flag.IntVar(&rate, "r", 1000, "send packet rate")
	flag.DurationVar(&timeout, "t", 5*time.Second, "timeout")
	flag.IntVar(&workers, "worker", 0, "scanner number")
	flag.IntVar(&senders, "sender", 0, "packet sender number")
	flag.StringVar(&save, "save", "", "result file path")
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
		file, err := os.OpenFile(save, os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalln(err)
		}
		log.SetOutput(&logger{file: file})
	}
	s, err := scanner.New(targets, ports, &opts)
	if err != nil {
		log.Fatalln(err)
	}
	start := time.Now()
	err = s.Start()
	if err != nil {
		log.Fatalln(err)
	}
	go func() {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Kill, os.Interrupt)
		<-signalChan
		s.Stop()
		log.Print("stop scanner.\r\n")
	}()
	var scanned int
	for address := range s.Result {
		scanned += 1
		log.Print(address + "\r\n")
	}
	log.Printf("scan finished. total: %d time: %s\r\n", scanned, time.Since(start))
}
