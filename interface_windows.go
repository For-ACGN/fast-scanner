package scanner

import (
	"fmt"
	"net"

	"github.com/StackExchange/wmi"
	"github.com/google/gopacket/pcap"
)

func selectInterfaces(name string) (*Interface, error) {
	type Win32NetworkAdapter struct {
		NetConnectionID string
		GUID            string
		MACAddress      string
	}
	var adapters []Win32NetworkAdapter
	q := "SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled = TRUE"
	err := wmi.Query(q, &adapters)
	if err != nil {
		return nil, err
	}
	type Win32NetworkAdapterConfiguration struct {
		SettingID        string
		DefaultIPGateway []string
	}
	var configs []Win32NetworkAdapterConfiguration
	q = "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"
	err = wmi.Query(q, &configs)
	if err != nil {
		return nil, err
	}
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	ifaces := make(map[string]*Interface)
	for _, adapter := range adapters {
		iface := &Interface{
			Device: "\\Device\\NPF_" + adapter.GUID,
		}
		iface.MAC, _ = net.ParseMAC(adapter.MACAddress)
		ifaces[adapter.NetConnectionID] = iface
		for i := 0; i < len(configs); i++ {
			if configs[i].SettingID == adapter.GUID {
				for _, gateway := range configs[i].DefaultIPGateway {
					iface.Gateways = append(iface.Gateways, net.ParseIP(gateway))
				}
				break
			}
		}
		for i := 0; i < len(ifs); i++ {
			if ifs[i].Name == iface.Device {
				iface.Addresses = ifs[i].Addresses
				break
			}

		}
	}
	i := ifaces[name]
	if i == nil {
		return nil, fmt.Errorf("interface: %s doesn't exist", name)
	}
	return i, nil
}
