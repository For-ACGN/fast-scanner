package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	"scanner"
)

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
	targetsUsage := bytes.Buffer{}
	targetsUsage.WriteString("192.168.1.1, fe80::1\n")
	targetsUsage.WriteString("192.168.1.1-192.168.1.3, fe80::1-fe80::1\n")
	targetsUsage.WriteString("192.168.1.1/24")
	flag.StringVar(&targets, "targets", "", targetsUsage.String())
	flag.StringVar(&ports, "ports", "", "80, 81-82")
	flag.StringVar(&method, "method", scanner.MethodSYN, "connect or syn")
	flag.StringVar(&device, "device", "", "interface name Ethernet0, eth0")
	flag.IntVar(&rate, "rate", 1000, "send packet rate")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "timeout")
	flag.IntVar(&workers, "workers", 0, "scanner number")
	flag.IntVar(&senders, "senders", 0, "packet sender number")
	flag.StringVar(&save, "save", "", "save scan result")
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
	start := time.Now()
	s, err := scanner.New(targets, ports, &opts)
	if err != nil {
		log.Fatalln(err)
	}
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

type logger struct {
	file *os.File
}

func (l *logger) Write(p []byte) (n int, err error) {
	_, _ = os.Stderr.Write(p)
	return l.file.Write(p)
}
