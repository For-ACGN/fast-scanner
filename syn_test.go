package scanner

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSynScanner(t *testing.T) {
	// targets := "8.8.8.8-8.8.8.10, 2606:4700:4700::1001-2606:4700:4700::1003"
	targets := "123.206.1.1-123.206.255.254"
	opt := Options{
		Timeout: 5 * time.Second,
	}
	scanner, err := New(targets, "1080", &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	expected := bytes.Buffer{}
	expected.WriteString("8.8.8.8:53\n")
	expected.WriteString("[2606:4700:4700::1001]:53\n")
	actual := &bytes.Buffer{}
	for address := range scanner.Address {
		actual.WriteString(address + "\n")
	}
	require.True(t, expected.String() == actual.String())
	require.True(t, scanner.HostNumber().String() == "6")
	require.True(t, scanner.ScannedNumber().String() == "6")
}

func TestSynScanner1(t *testing.T) {
	c, err := net.Dial("tcp", "[2606:4700:4700::1001]:53")
	require.NoError(t, err)
	c.Close()
}
