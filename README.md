# fast-scanner
[![Build Status](https://travis-ci.org/For-ACGN/fast-scanner.svg?branch=master)](https://travis-ci.org/For-ACGN/fast-scanner)
[![Go Report Card](https://goreportcard.com/badge/github.com/For-ACGN/fast-scanner)](https://goreportcard.com/report/github.com/For-ACGN/fast-scanner)
[![GoDoc](https://godoc.org/github.com/For-ACGN/fast-scanner?status.svg)](http://godoc.org/github.com/For-ACGN/fast-scanner)
[![license](https://img.shields.io/github/license/For-ACGN/fast-scanner.svg)](https://github.com/For-ACGN/fast-scanner/blob/master/LICENSE)
\
fast-scanner can make it easy for you to develop scanners
## Features
* Support CONNECT & SYN method
* SYN scanning method is similar to masscan stateless scanning
* Support IPv4 & IPv6
* Support Windows & Linux
* Scan result is a string channal
## Install
``````
windows: 
  Winpcap or Npcap
linux:
  apt-get libpcap-dev
  yum install libpcap-devel
``````
## Parameter
``````
targets:
  "1.1.1.1, 1.1.1.2-1.1.1.3, 1.1.1.1/24"
  "2606:4700:4700::1001, 2606:4700:4700::1002-2606:4700:4700::1003"
ports:
  "80, 81-82"
Options:
  see options.go
``````
## Example
``````go
s, err := scanner.New("1.1.1.1-1.1.1.2, 2606:4700:4700::1001", "53-54", nil)
if err != nil {
    log.Fatalln(err)
}
err = s.Start()
if err != nil {
    log.Fatalln(err)
}
for address := range s.Result {
    log.Print(address + "\r\n")
}
``````
``````
1.1.1.1:53
[2606:4700:4700::1001]:53
``````
## TODO
``````
1. target support ipv6 CIDR
2. BPFFilter for IPv6
     _ = handle.SetBPFFilter("tcp[13] = 0x12")
     is not support ipv6
3. PF_RING
``````
