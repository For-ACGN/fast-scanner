package main

import (
	"bytes"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
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
		LocalAddrs:  localAddrs,
		Goroutines:  goroutines,
		DialTimeout: dialTimeout,
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
	for i := 0; i < 4096*runtime.NumCPU(); i++ {
		go handleConn(s.Conns)
	}
	handleConn(s.Conns)
	log.Println("scan finished")
}

func handleConn(conn <-chan *net.TCPConn) {
	for conn := range conn {
		log.Println(conn.RemoteAddr())
		_ = conn.Close()
	}
}
