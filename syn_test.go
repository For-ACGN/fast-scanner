package scanner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSynScanner(t *testing.T) {
	// targets := "8.8.8.8-8.8.8.10, 2606:4700:4700::1001-2606:4700:4700::1003"
	// targets := "192.168.1.1-192.168.1.254"
	targets := "123.206.1.1-123.206.255.254"
	ports := "1080"
	opt := Options{
		Timeout: 3 * time.Second,
		Rate:    2000,
		Workers: 16,
	}
	scanner, err := New(targets, ports, &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	result := make(map[string]struct{})
	for address := range scanner.Address {
		result[address] = struct{}{}
		t.Log(address)
	}
	t.Log("result", len(result))
	require.Equal(t, scanner.HostNumber().String(), "254")
	require.Equal(t, scanner.ScannedNumber().String(), "254")
}

func TestSynScannerAccuracy(t *testing.T) {
	targets := "123.206.1.1-123.206.255.254"
	ports := "1080"
	opt := Options{
		Device:  "Ethernet0",
		Method:  MethodConnect,
		Timeout: 5 * time.Second,
		Rate:    500,
	}
	// connect
	start := time.Now()
	scanner, err := New(targets, ports, &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	connectResult := make(map[string]struct{})
	for address := range scanner.Address {
		connectResult[address] = struct{}{}
	}
	t.Log("tcp ok", time.Since(start))
	time.Sleep(2 * opt.Timeout)
	// syn
	start = time.Now()
	opt.Method = MethodSYN
	opt.Rate = 2000
	opt.Workers = 8
	scanner, err = New(targets, ports, &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	synResult := make(map[string]struct{})
	for address := range scanner.Address {
		synResult[address] = struct{}{}
	}
	t.Log("syn ok", time.Since(start))
	// compare
	var synScanned int
	for address := range connectResult {
		_, ok := synResult[address]
		if ok {
			synScanned += 1
		} else {
			t.Log(address, "is lost")
		}
	}
	connectResultL := len(connectResult)
	synResultL := len(synResult)
	t.Logf("connect: %d syn: %d", connectResultL, synResultL)
	accuracy := float64(synScanned) / float64(connectResultL) * 100
	t.Logf("accuracy: %f%%", accuracy)
}
