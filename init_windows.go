package scanner

import (
	"github.com/google/gopacket/pcap"
)

func init() {
	initErr = pcap.LoadWinPCAP()
}
