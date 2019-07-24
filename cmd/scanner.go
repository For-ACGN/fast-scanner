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
		targets     string
		ports       string
		localAddrs  string
		goroutines  int
		dialTimeout time.Duration
	)
	targetsUsage := bytes.Buffer{}
	targetsUsage.WriteString("192.168.1.1, fe80::1, ")
	targetsUsage.WriteString("192.168.1.1-192.168.1.3, fe80::1-fe80::1, ")
	targetsUsage.WriteString("192.168.1.1/24")
	flag.StringVar(&targets, "targets", "127.0.0.1", targetsUsage.String())
	portsUsage := "80, 80-82"
	flag.StringVar(&ports, "ports", "80", portsUsage)
	localAddrsUsage := "192.168.1.1, fe80::1"
	flag.StringVar(&localAddrs, "local", "", localAddrsUsage)
	flag.IntVar(&goroutines, "goroutines", 0, "")
	flag.DurationVar(&dialTimeout, "timeout", 0, "")
	flag.Parse()
	opts := &scanner.Options{
		LocalIP:    localAddrs,
		Goroutines: goroutines,
		Timeout:    dialTimeout,
	}
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
		log.Println("stop")
	}()
	for addr := range s.Address {
		log.Println(addr)
	}
	log.Println("scan finished")
}
