package diddocument

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/BSNDA/bsn-sdk-crypto/crypto/secp256k1"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common/math"
	ethsecp256k1 "github.com/ethereum/go-ethereum/crypto/secp256k1"
	solsha3 "github.com/miguelmota/go-solidity-sha3"
	"golang.org/x/crypto/ripemd160"

	selfecdsa "github.com/nekomeowww/bsn-ddc-go-sdk/ecdsa"
)

const (
	// W3CFormatAddress W3C format standard address
	W3CFormatAddress = "https://w3id.org/did/v1"
	// DidPrefix Did prefix
	DidPrefix = "did"
	// DidProjectName Did project name
	DidProjectName = "bsn"
	// DidSeparator Did separator
	DidSeparator = ":"
)

// BaseDidDocument 基础 DID 文档
type BaseDidDocument struct {
	Context        string     `json:"context,omitempty"`
	Recovery       *PublicKey `json:"recovery"`
	Authentication *PublicKey `json:"authentication"`

	PrimaryKeyPair   *ecdsa.PrivateKey `json:"-"`
	AlternateKeyPair *ecdsa.PrivateKey `json:"-"`
}

// NewBaseDidDocument creates new DID document
func NewBaseDidDocument(primaryKeyPair, alternateKeyPair *ecdsa.PrivateKey) (*BaseDidDocument, error) {
	primaryPublicKeyData, err := publicKeyToDecimal(&primaryKeyPair.PublicKey)
	if err != nil {
		return nil, err
	}

	alternatePublicKeyData, err := publicKeyToDecimal(&alternateKeyPair.PublicKey)
	if err != nil {
		return nil, err
	}

	return &BaseDidDocument{
		Context: W3CFormatAddress,
		Authentication: &PublicKey{
			Type:      selfecdsa.TYPE,
			PublicKey: primaryPublicKeyData,
		},
		Recovery: &PublicKey{
			Type:      selfecdsa.TYPE,
			PublicKey: alternatePublicKeyData,
		},
		PrimaryKeyPair:   primaryKeyPair,
		AlternateKeyPair: alternateKeyPair,
	}, nil
}

func publicKeyToDecimal(publicKey *ecdsa.PublicKey) (string, error) {
	bytes, _, err := marshalPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	publicKeyData := new(big.Int).SetBytes(bytes)
	return publicKeyData.String(), nil
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	oidNamedCurveS256 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	case secp256k1.SECP256K1():
		return oidNamedCurveS256, true
	}
	return nil, false
}

func marshalPublicKey(pub *ecdsa.PublicKey) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	oid, ok := oidFromNamedCurve(pub.Curve)
	if !ok {
		return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
	}
	publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
	var paramBytes []byte
	paramBytes, err = asn1.Marshal(oid)
	if err != nil {
		return
	}
	publicKeyAlgorithm.Parameters.FullBytes = paramBytes

	return publicKeyBytes, publicKeyAlgorithm, nil
}

// NewDidIdentifierByBaseDidDocument creates new DID identifier by base DID document
func NewDidIdentifierByBaseDidDocument(baseDidDocument *BaseDidDocument) (string, error) {
	jsonData, err := json.Marshal(baseDidDocument)
	if err != nil {
		return "", err
	}

	data, _ := json.MarshalIndent(baseDidDocument, "", "  ")
	fmt.Println(string(data))

	sha256Hasher := sha256.New()
	sha256Hasher.Write(jsonData)
	sha256Data := sha256Hasher.Sum(nil)

	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(sha256Data)
	ripemd160Data := ripemd160Hasher.Sum(nil)

	return base58.Encode(ripemd160Data), nil
}

// NewDidFromDidIdentifier creates new DID from DID identifier
func NewDidFromDidIdentifier(identifier string) string {
	prefix := fmt.Sprintf("%s%s%s%s", DidPrefix, DidSeparator, DidProjectName, DidSeparator)
	return fmt.Sprintf("%s%s", prefix, identifier)
}

// DidDocument DID 文档
type DidDocument struct {
	Created        string     `json:"created" example:"2006-01-02 15:04:05"`
	Recovery       *PublicKey `json:"recovery"`
	Updated        string     `json:"updated" example:"2006-01-02 15:04:05"`
	Version        string     `json:"version" example:"1"`
	Did            string     `json:"did" example:"did:bsn:3wxYHXwAm57grc9JUr2zrPHt9HC"`
	Authentication *PublicKey `json:"authentication"`
	Proof          *Proof     `json:"proof,omitempty"`
}

// NewDidDocumentFromBaseDocument creates new DID document from base DID document
func NewDidDocumentFromBaseDocument(did string, baseDidDocument *BaseDidDocument) *DidDocument {
	baseDidDocument.Context = ""

	return &DidDocument{
		Did:            did,
		Version:        "1",
		Created:        time.Now().Format("2006-01-02 15:04:05"),
		Updated:        time.Now().Format("2006-01-02 15:04:05"),
		Recovery:       baseDidDocument.Recovery,
		Authentication: baseDidDocument.Authentication,
	}
}

// Proof 证明
type Proof struct {
	Type           string `json:"type" example:"Secp256k1"`
	Creator        string `json:"creator" example:"did:bsn:3wxYHXwAm57grc9JUr2zrPHt9HC"`
	SignatureValue string `json:"signatureValue" example:"zD5nt+P/Ga/CRG2hJU/SMRXy210CLdvATsxQdPxTEy9Mc9Y0OSFpE3Yu5k2+OjQKVOtu5of9VFbgO3Zljw/vQxs="`
}

// NewProof creates new proof
func NewProof(did string, privateKey *ecdsa.PrivateKey, signData interface{}) (*Proof, error) {
	jsonData, err := json.Marshal(signData)
	if err != nil {
		return nil, err
	}

	hashedData := solsha3.SoliditySHA3(solsha3.String(jsonData))
	signature, err := ethsecp256k1.Sign(hashedData, math.PaddedBigBytes(privateKey.D, 32))
	if err != nil {
		return nil, err
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	return &Proof{
		Type:           selfecdsa.TYPE,
		Creator:        did,
		SignatureValue: signatureBase64,
	}, nil
}
