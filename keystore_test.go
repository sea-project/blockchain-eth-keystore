
package keystore

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestGenerateKeyStore(t *testing.T) {
	prvKey := "84bddb7a58350d555191602200116174c21df108645daf4fb7d642b8bc4b2c37"
	keyStore, err := GenerateKeyStore(prvKey, "12345678")
	if err != nil {
		panic(err)
	}
	fmt.Println(keyStore)

	prv, err := DecryptKeyStoreStr(keyStore, "12345678")
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(prv))
}
