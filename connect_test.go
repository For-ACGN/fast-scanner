package scanner

import (
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
	scanner, err := New(targets, "53,54,55-57", &opt)
	require.NoError(t, err)
	err = scanner.Start()
	require.NoError(t, err)
	result := make(map[string]struct{})
	for address := range scanner.Result {
		result[address] = struct{}{}
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
	require.Equal(t, scanner.HostNumber().String(), "30")
	require.Equal(t, scanner.ScannedNumber().String(), "30")
}
