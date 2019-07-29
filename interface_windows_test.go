package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectInterfaces(t *testing.T) {
	iface, err := selectInterfaces("Ethernet0")
	require.Nil(t, err)
	t.Log(iface)
}
