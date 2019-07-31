package scanner

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func selectInterface(name string) (*Interface, error) {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	iface := make(map[string]*pcap.Interface)
	for i := 0; i < len(ifs); i++ {
		iface[ifs[i].Name] = &ifs[i]
	}
	var selected []*pcap.Interface
	for _, name := range names {
		i := iface[name]
		if i == nil {
			return nil, fmt.Errorf("interface: %s doesn't exist", name)
		}
		selected = append(selected, i)
	}
	return selected, nil
}
