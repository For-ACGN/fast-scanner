package scanner

import (
	"net"

	"github.com/google/gopacket/pcap"
)

type Interface struct {
	Device    string
	MAC       net.HardwareAddr
	Addresses []pcap.InterfaceAddress
	Gateways  []net.IP
}
