
package keystore

import (
	"crypto/rand"
	"io"
)

// GetEntropyCSPRNG 生成随机指定位数byte
func GetEntropyCSPRNG(n int) []byte {
	mainBuff := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, mainBuff)
	if err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	return mainBuff
}
