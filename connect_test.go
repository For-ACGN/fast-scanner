package scanner

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConnectScanner(t *testing.T) {
	targets := "8.8.8.8-8.8.8.10, 2606:4700:4700::1001-2606:4700:4700::1003"
	opt := Options{
		Method:  MethodConnect,
		Timeout: 5 * time.Second,
	}
	scanner, err := New(targets, "53", &opt)
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
