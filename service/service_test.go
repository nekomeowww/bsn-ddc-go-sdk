package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDidDocument(t *testing.T) {
	require := require.New(t)

	didDocument, err := NewDidDocument()
	require.NoError(err)
	require.NotNil(didDocument)

	data, err := json.MarshalIndent(didDocument, "", "  ")
	require.NoError(err)
	require.NotEmpty(data)
}

func TestNewAndStoreDidDocumentOnChain(t *testing.T) {
	require := require.New(t)

	err := NewAndStoreDidDocumentOnChain(true)
	require.NoError(err)
}
