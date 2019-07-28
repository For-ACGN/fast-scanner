package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSyn(t *testing.T) {
	_, err := newSYNScanner()
	require.Nil(t, err)
}
