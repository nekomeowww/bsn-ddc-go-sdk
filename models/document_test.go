package diddocument

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/BSNDA/bsn-sdk-crypto/crypto/secp256k1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyToDecimal(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	primaryKeyPair, err := secp256k1.NewSecp256k1Key()
	require.NoError(err)
	require.NotNil(primaryKeyPair)

	data, err := publicKeyToDecimal(&primaryKeyPair.PublicKey)
	require.NoError(err)
	require.NotEmpty(data)
	assert.Len(data, 155)
}

func TestNewProof(t *testing.T) {
	require := require.New(t)

	// rawData := `{"created":"2022-02-16 11:00:33","recovery":{"publicKey":"2981297355480444164124100784475474475659893558292516572493283170142891596147936711333389653064984676036815535341352098205520488823686058230477238945385559","type":"Secp256k1"},"updated":"2022-02-16 11:00:33","version":"1","did":"did:bsn:27V2H3Xn42Dh6nZMJcSFDZPnik1m","authentication":{"publicKey":"13294413587568124760425299250395629294113540352316065109957239991827123143585790148300288190276981031222333996957896478254729160803494633117624817734302311","type":"Secp256k1"}}`

	publicKeyData := "80036126624133098177387164487001377602111324284052133874180384351325067524406"
	publicKey, ok := new(big.Int).SetString(publicKeyData, 10)
	require.True(ok)

	// oidPublicKeyECDSA := asn1.ObjectIdentifier{1, 3, 132, 0, 10}

	type pkixPublicKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}

	var pk pkixPublicKey
	data, err := asn1.Unmarshal(publicKey.Bytes(), &pk)
	require.NoError(err)
	require.NotNil(data)

	x, y := elliptic.Unmarshal(secp256k1.SECP256K1(), data)
	require.NotNil(x)
	require.NotNil(y)

	// r, s, err := ecdsa.Sign(rand.Reader, privateKey, jsonData)
	// if err != nil {
	// 	return nil, err
	// }

	// signature, err := asn1.Marshal(ECDSASignature{r, s})
	// if err != nil {
	// 	return nil, err
	// }
}
