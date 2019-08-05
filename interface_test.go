package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectInterfaces(t *testing.T) {
	iface, err := SelectInterface("")
	require.NoError(t, err)
	t.Log(iface)
}
