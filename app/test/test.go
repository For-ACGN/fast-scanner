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
		save    string
	)
	targetsUsage := bytes.Buffer{}
	targetsUsage.WriteString("192.168.1.1, fe80::1, ")
	targetsUsage.WriteString("192.168.1.1-192.168.1.3, fe80::1-fe80::1, ")
	targetsUsage.WriteString("192.168.1.1/24")
	flag.StringVar(&targets, "targets", "127.0.0.1", targetsUsage.String())
	flag.StringVar(&ports, "ports", "80", "80, 80-82")
	flag.StringVar(&method, "method", scanner.MethodSYN, "connect or syn")
	flag.StringVar(&device, "device", "", "interface name Ethernet0, eth0")
	flag.IntVar(&rate, "rate", 1000, "packet send per second")
	flag.DurationVar(&timeout, "timeout", 0, "timeout")
	flag.IntVar(&workers, "workers", 0, "scanner number. usually don't need set")
	flag.StringVar(&save, "save", "", "save scan result")
	flag.Parse()
	opts := &scanner.Options{
		Method:  method,
		Device:  device,
		Rate:    rate,
		Timeout: timeout,
		Workers: workers,
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
	s, err := scanner.New(targets, ports, opts)
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
		log.Print("stop scanner\r\n")
	}()
	result := make(map[string]struct{})
	for address := range s.Result {
		_, ok := result[address]
		if ok {
			log.Printf("duplicate: %s\r\n", address)
			continue
		}
		result[address] = struct{}{}
	}
	log.Printf("scan finished. total: %d time: %s\r\n", len(result), time.Since(start))
}

type logger struct {
	file *os.File
}

func (l *logger) Write(p []byte) (n int, err error) {
	_, _ = os.Stderr.Write(p)
	return l.file.Write(p)
}
