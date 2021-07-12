package tcrsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPreparePssDocumentHash(t *testing.T) {
	var (
		pssEncodeTestMessage = "Hello World , Pss Encoding"
		pssEncodingLeyLength = 4096
	)
	docHash := sha256.Sum256([]byte(pssEncodeTestMessage))

	docPss, err := PreparePssDocumentHash(pssEncodingLeyLength, docHash[:], nil, &rsa.PSSOptions{
		SaltLength: 0,
		Hash:       crypto.SHA256,
	})
	assert.NoError(t, err)
	assert.Equal(t, pssEncodingLeyLength/8, len(docPss))

	// test salt length
	salt := sha256.Sum256([]byte("dddsss"))
	_, err = PreparePssDocumentHash(pssEncodingLeyLength, docHash[:], salt[:], &rsa.PSSOptions{
		SaltLength: 0,
		Hash:       crypto.SHA256,
	})
	assert.NoError(t, err)

	//
	salt02 := make([]byte, 30)
	_, err = PreparePssDocumentHash(pssEncodingLeyLength, docHash[:], salt02[:], &rsa.PSSOptions{
		SaltLength: 0,
		Hash:       crypto.SHA256,
	})
	assert.Equal(t, "salt length too short", err.Error())
}
