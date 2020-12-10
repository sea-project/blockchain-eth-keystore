
package keystore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/sea-project/crypto-aes"
	"github.com/sea-project/crypto-hash-sha3"
	"golang.org/x/crypto/scrypt"
	"io"
	"math/big"

	"github.com/sea-project/crypto-signature-ecdsa"
	"github.com/sea-project/stdlib-math"
)

// KeyJSON keyStore结构体
type KeyJSON struct {
	ID           string       `json:"id"`
	Address      string       `json:"address"`
	Version      int          `json:"version"`
	ScryptParams ScryptParams `json:"crypto"`
}

type ScryptParams struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

var (
	version      = 3
	scryptN      = 1 << 12
	scryptP      = 6
	scryptR      = 8
	scryptDKLen  = 32
	keyHeaderKDF = "scrypt"
)

//截取字符串 start 起点下标 length 需要截取的长度
func Substr(str string, start int, length int) string {
	rs := []rune(str)
	rl := len(rs)
	end := 0

	if start < 0 {
		start = rl - 1 + start
	}
	end = start + length

	if start > end {
		start, end = end, start
	}

	if start < 0 {
		start = 0
	}
	if start > rl {
		start = rl
	}
	if end < 0 {
		end = 0
	}
	if end > rl {
		end = rl
	}

	return string(rs[start:end])
}

// encryptKey 生成keystore算法
func GenerateKeyStore(prvKeyHex string, password string) (string, error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("io.ReadFull err:%v", err)
	}

	srcKey := prvKeyHex
	if len(prvKeyHex) > 64 {
		srcKey = Substr(prvKeyHex, len(prvKeyHex) - 64, 64)
	}
	prv, err := ecdsa.HexToPrvKey(srcKey)
	if err != nil {
		return "", fmt.Errorf("ecdsa.HexToPrvKey err:%v", err)
	}
	addrHex := prv.ToPubKey().ToAddress().Hex()
	address := Substr(addrHex, len(addrHex)-ecdsa.ETHAddressLength * 2, ecdsa.ETHAddressLength * 2)

	derivedKey, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return "", err
	}

	encryptKey := derivedKey[:16]
	d, b := new(big.Int).SetString(prvKeyHex, 16)
	if !b {
		return "", errors.New("prvKeyHex is not hex")
	}
	//keyBytes := math.PaddedBigBytes(prvKey.D, scryptDKLen)
	keyBytes := math.PaddedBigBytes(d, scryptDKLen)
	iv := GetEntropyCSPRNG(16)
	cipherText, err := aes.AesCTRXOR(encryptKey, keyBytes, iv)
	if err != nil {
		return "", err
	}

	mac := sha3.Keccak256(derivedKey[16:32], cipherText)
	scryptParamsJSON := make(map[string]interface{}, 5)
	scryptParamsJSON["n"] = scryptN
	scryptParamsJSON["r"] = scryptR
	scryptParamsJSON["p"] = scryptP
	scryptParamsJSON["dklen"] = scryptDKLen
	scryptParamsJSON["salt"] = hex.EncodeToString(salt)
	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	scryptParams := ScryptParams{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          keyHeaderKDF,
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
	}

	randomId, _ := uuid.NewUUID()
	keyJson := &KeyJSON{
		ID:           randomId.String(),
		Address:      address,
		Version:      version,
		ScryptParams: scryptParams,
	}
	jsonByte, err := JsonMarshal(keyJson)
	if err != nil {
		return "", err
	}
	return string(jsonByte), nil
}

func DecryptKeyStoreStr(keystore string, password string) ([]byte, error) {
	keyJson := new(KeyJSON)
	//err := json.Unmarshal([]byte(keystore), &keyJson)
	err := JsonUnMarshal([]byte(keystore), &keyJson)
	if err != nil {
		return nil, err
	}
	return DecryptKeyStore(keyJson, password)
}

// decryptKeyStore 解密keystore
func DecryptKeyStore(keyJson *KeyJSON, password string) ([]byte, error) {
	if keyJson.ScryptParams.Cipher != "aes-128-ctr" {
		return nil, fmt.Errorf("Cipher not supported: %v", keyJson.ScryptParams.Cipher)
	}

	dkLen := ensureInt(keyJson.ScryptParams.KDFParams["dklen"])
	n := ensureInt(keyJson.ScryptParams.KDFParams["n"])
	r := ensureInt(keyJson.ScryptParams.KDFParams["r"])
	p := ensureInt(keyJson.ScryptParams.KDFParams["p"])
	salt, err := hex.DecodeString(keyJson.ScryptParams.KDFParams["salt"].(string))
	if err != nil {
		return nil, err
	}
	derivedKey, err := scrypt.Key([]byte(password), salt, n, r, p, dkLen)
	if err != nil {
		return nil, err
	}
	cipherText, err := hex.DecodeString(keyJson.ScryptParams.CipherText)
	if err != nil {
		return nil, err
	}

	calculatedMAC := sha3.Keccak256(derivedKey[16:32], cipherText) //验证时输入密码获得的mac
	mac, err := hex.DecodeString(keyJson.ScryptParams.MAC)         //生成keystore时输入密码获得的mac
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(calculatedMAC, mac) { //两次mac相等，则证明密码正确
		return nil, errors.New("could not decrypt key with given passphrase")
	}

	// 使用验证过的、正确的密码把cipherText还原为“原文”，并得到私钥
	iv, err := hex.DecodeString(keyJson.ScryptParams.CipherParams.IV)
	if err != nil {
		return nil, err
	}

	encryptKey := derivedKey[:16]
	plainText, err := aes.AesCTRXOR(encryptKey, cipherText, iv[:16])
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}
