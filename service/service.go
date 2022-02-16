package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/BSNDA/bsn-sdk-crypto/crypto/secp256k1"
	diddocument "github.com/nekomeowww/bsn-ddc-go-sdk/models"
)

// API Endpoints
const (
	// URL of create did service endpoint in BSN
	PutDidOnChain = "/did/putDoc"
	// URL of query did document service endpoint in BSN
	GetDidDocument = "/did/getDoc"
	// URL of reset did document main authenticate service endpoint in BSN
	ResetDidAuth = "/did/resetDidAuth"
	// URL of verify did identifier sign service endpoint in BSN
	VerifyDidSign = "/did/verifyDIdSign"
)

// 服务参数
const (
	// DidServiceURL did service request url
	DidServiceURL = "https://didservice.bsngate.com:18602"
	// DidServiceProjectID did service request project Id
	DidServiceProjectID = "8320935187"
	// DidServiceAPIToken did service request token
	DidServiceAPIToken = "3wxYHXwAm57grc9JUr2zrPHt9HC"
)

// NewDid creates new DID
func NewDid() (interface{}, error) {
	return nil, nil
}

// NewDidDocument creates new DID document
func NewDidDocument() (*diddocument.DidDocument, error) {
	primaryKeyPair, err := secp256k1.NewSecp256k1Key()
	if err != nil {
		return nil, err
	}

	alternateKeyPair, err := secp256k1.NewSecp256k1Key()
	if err != nil {
		return nil, err
	}

	baseDidDocument, err := diddocument.NewBaseDidDocument(primaryKeyPair, alternateKeyPair)
	if err != nil {
		return nil, err
	}

	didIdentifier, err := diddocument.NewDidIdentifierByBaseDidDocument(baseDidDocument)
	if err != nil {
		return nil, err
	}

	did := diddocument.NewDidFromDidIdentifier(didIdentifier)
	didDocument := diddocument.NewDidDocumentFromBaseDocument(did, baseDidDocument)
	didDocument.Proof, err = diddocument.NewProof(did, primaryKeyPair, didDocument)
	if err != nil {
		return nil, err
	}

	return didDocument, nil
}

type dataParam struct {
	DidDoc interface{} `json:"didDoc"`
}

func (d dataParam) Data() interface{} {
	return d.DidDoc
}

type iDataParam interface {
	Data() interface{}
}

type putDidParam struct {
	ProjectID string     `json:"projectId"`
	Did       string     `json:"did"`
	Data      iDataParam `json:"data"`
	Sign      string     `json:"sign"`
}

type putDidResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

// NewAndStoreDidDocumentOnChain creates new DID document and store on chain
func NewAndStoreDidDocumentOnChain(storeOnChain bool) error {
	didDocument, err := NewDidDocument()
	if err != nil {
		return err
	}

	dataParam := dataParam{
		DidDoc: didDocument,
	}
	param := putDidParam{
		ProjectID: DidServiceProjectID,
		Did:       didDocument.Did,
		Data:      dataParam,
	}

	paramData, _ := json.Marshal(param)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s%s", DidServiceURL, PutDidOnChain), bytes.NewBuffer(paramData))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("token", DidServiceAPIToken)
	req.Header.Add("projectId", DidServiceProjectID)

	httpClient := http.Client{}
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	data, _ := ioutil.ReadAll(res.Body)
	var putRes putDidResponse
	_ = json.Unmarshal(data, &putRes)
	if res.StatusCode != http.StatusOK {
	} else if putRes.Code != 0 {
		return fmt.Errorf("code: %d, message: %s", putRes.Code, putRes.Message)
	}

	return nil
}
