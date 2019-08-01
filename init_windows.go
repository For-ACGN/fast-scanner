package scanner

import (
	"github.com/google/gopacket/pcap"
)

var initErr error

func init() {
	initErr = pcap.LoadWinPCAP()
}
