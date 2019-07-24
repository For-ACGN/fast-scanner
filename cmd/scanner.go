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
		targets    string
		ports      string
		localIPs   string
		goroutines int
		timeout    time.Duration
		save       string
	)
	targetsUsage := bytes.Buffer{}
	targetsUsage.WriteString("192.168.1.1, fe80::1, ")
	targetsUsage.WriteString("192.168.1.1-192.168.1.3, fe80::1-fe80::1, ")
	targetsUsage.WriteString("192.168.1.1/24")
	flag.StringVar(&targets, "targets", "127.0.0.1", targetsUsage.String())
	portsUsage := "80, 80-82"
	flag.StringVar(&ports, "ports", "80", portsUsage)
	localAddrsUsage := "192.168.1.1, fe80::1"
	flag.StringVar(&localIPs, "local", "", localAddrsUsage)
	flag.IntVar(&goroutines, "goroutines", 0, "")
	flag.DurationVar(&timeout, "timeout", 0, "")
	flag.StringVar(&save, "save", "", "")
	flag.Parse()
	opts := &scanner.Options{
		LocalIP:    localIPs,
		Goroutines: goroutines,
		Timeout:    timeout,
	}
	if save != "" {
		file, err := os.OpenFile(save, os.O_CREATE|os.O_APPEND, 644)
		if err != nil {
			log.Println(err)
			return
		}
		log.SetOutput(&logger{file: file})
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
		log.Print("stop scanner\r\n")
	}()
	for addr := range s.Address {
		log.Print(addr + "\r\n")
	}
	log.Print("scan finished\r\n")
}

type logger struct {
	file *os.File
}

func (l *logger) Write(p []byte) (n int, err error) {
	_, _ = os.Stderr.Write(p)
	return l.file.Write(p)
}
