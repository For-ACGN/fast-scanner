package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectInterfaces(t *testing.T) {
	iface, err := selectInterface("")
	require.NoError(t, err)
	t.Log(iface)
}
