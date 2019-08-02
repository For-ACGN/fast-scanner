package scanner

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConnectScanner(t *testing.T) {
	targets := "8.8.8.8-8.8.8.10, 2606:4700:4700::1001-2606:4700:4700::1003"
	opt := Options{
		Method:  MethodConnect,
		Timeout: 3 * time.Second,
	}
	scanner, err := New(targets, "53", &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	expected := []string{
		"8.8.8.8:53\n",
		"[2606:4700:4700::1001]:53\n",
	}
	actual := bytes.Buffer{}
	for address := range scanner.Address {
		actual.WriteString(address + "\n")
	}
	result := actual.String()
	for _, address := range expected {
		if strings.Index(result, address) == -1 {
			t.Fatal("invalid result:\n", result)
		}
	}
	require.Equal(t, scanner.HostNumber().String(), "6")
	require.Equal(t, scanner.ScannedNumber().String(), "6")
}
