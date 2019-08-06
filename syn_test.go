package scanner

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSynScanner(t *testing.T) {
	start := time.Now()
	targets := "8.8.8.8-8.8.8.10, 2606:4700:4700::1001-2606:4700:4700::1003"
	ports := "53,54,55-57"
	opt := Options{
		Timeout: 5 * time.Second,
		Rate:    2000,
		Workers: 2,
	}
	scanner, err := New(targets, ports, &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	result := make(map[string]struct{})
	for address := range scanner.Result {
		result[address] = struct{}{}
		t.Log(address)
	}
	expected := []string{
		"8.8.8.8:53",
		"[2606:4700:4700::1001]:53",
	}
	for i := 0; i < len(expected); i++ {
		if _, ok := result[expected[i]]; !ok {
			t.Fatal(expected[i], "is lost")
		}
	}
	t.Log("result:", len(result), "time:", time.Since(start))
	require.Equal(t, scanner.HostNum().String(), "30")
	require.Equal(t, scanner.Scanned().String(), "30")
}

func TestSynScanner_simple(t *testing.T) {
	start := time.Now()
	targets := "127.0.0.1, ::1"
	port := testListener(t)
	scanner, err := New(targets, port, nil)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	result := make(map[string]struct{})
	for address := range scanner.Result {
		result[address] = struct{}{}
		t.Log(address)
	}
	expected := []string{
		"127.0.0.1:" + port,
		"[::1]:" + port,
	}
	for i := 0; i < len(expected); i++ {
		if _, ok := result[expected[i]]; !ok {
			t.Fatal(expected[i], "is lost")
		}
	}
	t.Log("result:", len(result), "time:", time.Since(start))
	require.Equal(t, scanner.HostNum().String(), "2")
	require.Equal(t, scanner.Scanned().String(), "2")
}

func TestSynScanner_Stop(t *testing.T) {
	targets := "8.8.8.8/16"
	ports := "53,54,55-57"
	opt := Options{
		Timeout: 10 * time.Second,
		Rate:    10,
	}
	scanner, err := New(targets, ports, &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	go func() {
		err = scanner.Start()
		require.Error(t, err)
	}()
	time.Sleep(2 * time.Second)
	scanner.Stop()
	go func() { scanner.Stop() }()
	time.Sleep(250 * time.Millisecond)
	require.Equal(t, 2, runtime.NumGoroutine())
}

func TestSynScanner_Duplicate(t *testing.T) {
	start := time.Now()
	targets := "123.206.1.1/16"
	ports := "80"
	opt := Options{
		Timeout: 5 * time.Second,
		Rate:    30000,
	}
	scanner, err := New(targets, ports, &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	result := make(map[string]struct{})
	for address := range scanner.Result {
		if _, ok := result[address]; ok {
			t.Fatal("duplicate:", address)
		}
		result[address] = struct{}{}
	}
	t.Log("result:", len(result), "time:", time.Since(start))
	require.Equal(t, scanner.HostNum().String(), "65536")
	require.Equal(t, scanner.Scanned().String(), "65536")
}

func TestSynScanner_Raw(t *testing.T) {
	start := time.Now()
	targets := "123.206.1.1/16"
	ports := "80"
	opt := Options{
		Timeout: 5 * time.Second,
		Rate:    2800,
		Raw:     true,
	}
	scanner, err := New(targets, ports, &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	result := make(map[string]struct{})
	for address := range scanner.Result {
		if _, ok := result[address]; ok {
			t.Log("duplicate:", address)
			continue
		}
		result[address] = struct{}{}
	}
	t.Log("result:", len(result), "time:", time.Since(start))
	require.Equal(t, scanner.HostNum().String(), "65536")
	require.Equal(t, scanner.Scanned().String(), "65536")
}

func TestSynScannerAccuracy(t *testing.T) {
	targets := "123.206.1.1/16"
	ports := "80"
	opt := Options{
		Device:  "Ethernet0",
		Method:  MethodConnect,
		Timeout: 5 * time.Second,
		Rate:    1000,
	}
	// connect
	start := time.Now()
	scanner, err := New(targets, ports, &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	connectResult := make(map[string]struct{})
	for address := range scanner.Result {
		connectResult[address] = struct{}{}
	}
	t.Log("tcp ok", time.Since(start))
	time.Sleep(2 * opt.Timeout)
	// syn
	start = time.Now()
	opt.Method = MethodSYN
	opt.Rate = 2000
	opt.Workers = 16
	scanner, err = New(targets, ports, &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	synResult := make(map[string]struct{})
	for address := range scanner.Result {
		synResult[address] = struct{}{}
	}
	t.Log("syn ok", time.Since(start))
	// compare
	var synScanned int
	for address := range connectResult {
		if _, ok := synResult[address]; ok {
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
