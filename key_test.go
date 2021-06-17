package tcrsa_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/everFinance/tcrsa"
	"math/big"
	"testing"
)

const keyTestK = 3
const keyTestL = 5

const keyTestFixedSize = 512
const keyTestFixedP = "132TWiSEqNNnfiF5AZjS2R8SwUszMGnHSKTYAtWckuc="
const keyTestFixedQ = "f8PooDmAlOUFf3BdAxPCOy8p5ArfLHs6ODFWTFnpUxM="
const keyTestFixedR = "UfF0MWqXf+K4GjmcWhxdK3CH/XVsDxm8r+CqBenL7TfdWNAD4rpUMIHzhqb0WV6KAAJfGEBlHyj1JH2rr9LiUA=="
const keyTestFixedU = "CpJe+VzsAI3FcPioeMXklkxFFb+M9MaN1VzuScOs+7bwvczarYABZhyjPFC8McXCFAJIvaKTZwTlpylwJPumZw=="

const keyTestHashType = crypto.SHA256
const keyTestSize = 512
const keyTestMessage = "Hello world"

func TestGenerateKeys_differentKeys(t *testing.T) {
	keyShares, _, err := tcrsa.NewKey(keyTestSize, keyTestK, keyTestL, &tcrsa.KeyMetaArgs{})
	if err != nil {
		t.Errorf("couldn't create keys")
	}

	for i := 0; i < len(keyShares); i++ {
		key1 := keyShares[i]
		for j := i + 1; j < len(keyShares); j++ {
			key2 := keyShares[j]
			if key1.EqualsSi(key2) {
				t.Errorf("key shares are equal: k%d=%s, k%d=%s", i, key1.ToBase64(), j, key2.ToBase64())
			}
		}
	}
}

func TestGenerateKeys_validRandom(t *testing.T) {
	k := uint16(keyTestK)
	l := uint16(keyTestL)

	keyMetaArgs := &tcrsa.KeyMetaArgs{}

	keyShares, keyMeta, err := tcrsa.NewKey(keyTestSize, uint16(k), uint16(l), keyMetaArgs)
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}
	docHash := sha256.Sum256([]byte(keyTestMessage))

	docPKCS1, err := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), keyTestHashType, docHash[:])
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

	sigShares := make(tcrsa.SigShareList, l)

	var i uint16
	for i = 0; i < l; i++ {
		sigShares[i], err = keyShares[i].Sign(docPKCS1, keyTestHashType, keyMeta)
		if err != nil {
			t.Errorf(fmt.Sprintf("%v", err))
		}
		if err := sigShares[i].Verify(docPKCS1, keyMeta); err != nil {
			t.Errorf(fmt.Sprintf("%v", err))
		}
	}
	signature, err := sigShares.Join(docPKCS1, keyMeta)
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, keyTestHashType, docHash[:], signature); err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

}

func TestGenerateKeys_validFixed(t *testing.T) {

	k := uint16(keyTestK)
	l := uint16(keyTestL)
	keyMetaArgs := &tcrsa.KeyMetaArgs{}

	pBig, err := base64.StdEncoding.DecodeString(keyTestFixedP)
	if err != nil {
		t.Errorf("could not decode b64 key for p")
	}
	qBig, err := base64.StdEncoding.DecodeString(keyTestFixedQ)
	if err != nil {
		t.Errorf("could not decode b64 key for q")
	}
	rBig, err := base64.StdEncoding.DecodeString(keyTestFixedR)
	if err != nil {
		t.Errorf("could not decode b64 key for R")
	}
	vkuBig, err := base64.StdEncoding.DecodeString(keyTestFixedU)
	if err != nil {
		t.Errorf("could not decode b64 key for vk_u")
	}
	keyMetaArgs.P = new(big.Int).SetBytes(pBig)
	keyMetaArgs.Q = new(big.Int).SetBytes(qBig)
	keyMetaArgs.R = new(big.Int).SetBytes(rBig)
	keyMetaArgs.U = new(big.Int).SetBytes(vkuBig)

	keyShares, keyMeta, err := tcrsa.NewKey(keyTestFixedSize, uint16(k), uint16(l), keyMetaArgs)
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}
	docHash := sha256.Sum256([]byte(keyTestMessage))

	docPKCS1, err := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), keyTestHashType, docHash[:])
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

	sigShares := make(tcrsa.SigShareList, l)

	var i uint16
	for i = 0; i < l; i++ {
		sigShares[i], err = keyShares[i].Sign(docPKCS1, keyTestHashType, keyMeta)
		if err != nil {
			t.Errorf(fmt.Sprintf("%v", err))
		}
		if err := sigShares[i].Verify(docPKCS1, keyMeta); err != nil {
			t.Errorf(fmt.Sprintf("%v", err))
		}
	}
	signature, err := sigShares.Join(docPKCS1, keyMeta)

	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

	sigB64 := base64.StdEncoding.EncodeToString(signature)

	if sigB64 != "BUNv4j1NkVFNwx6v0GVG6CfN1Y7yhOBG2Tyy7ci7VK+AVYukZdiajnaYPALHLsEwngDLgNPK40o6HhbWT+ikXQ==" {
		t.Errorf("signature is not as expected.")
	}

	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, keyTestHashType, docHash[:], signature); err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

}
