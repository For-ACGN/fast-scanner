package scanner

import (
	"fmt"
	
	"github.com/google/gopacket/pcap"
)

type synScanner struct {
}

func newSYNScanner() (*synScanner, error) {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	fmt.Println(ifs[0].Name)

	for i := 0; i < 8; i++ {
		go func() {
			handle, err := pcap.OpenLive(ifs[0].Name, 65536, false, pcap.BlockForever)
			if err != nil {
				return
			}
			for {
				err = handle.WritePacketData([]byte{0, 0, 0, 0})
				if err != nil {
					return
				}
			}

		}()
	}

	handle, err := pcap.OpenLive(ifs[0].Name, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	for {
		err = handle.WritePacketData([]byte{0, 0, 0, 0})
		if err != nil {
			return nil, err
		}
	}
	handle.Close()
	s := &synScanner{}
	return s, nil
}
