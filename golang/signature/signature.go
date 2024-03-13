package signature

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

func Sha256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	hashBytes := h.Sum(nil)

	return hex.EncodeToString(hashBytes)
}

func GenerateNonce(length int) (string, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	nonce := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		nonce[i] = letters[num.Int64()]
	}

	return string(nonce), nil
}

func HmacSha256(key []byte, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	hmacBytes := h.Sum(nil)

	return hex.EncodeToString(hmacBytes)
}

func GenerateSignature(requestMethod string, path string, parameters string) (string, int64, string, error) {
	nonce, err := GenerateNonce(32)
	if err != nil {
		return "", 0, "", err
	}
	timestamp := time.Now().Unix()
	randStr := fmt.Sprintf(
		"debank-api\n%s\n%d",
		nonce,
		timestamp,
	)
	randStrHash := Sha256(randStr)

	requestParams := fmt.Sprintf(
		"%s\n%s\n%s",
		strings.ToUpper(requestMethod),
		strings.ToLower(path),
		strings.ToLower(parameters),
	)
	requestParamsHash := Sha256(requestParams)

	signature := HmacSha256(
		[]byte(randStrHash),
		[]byte(requestParamsHash),
	)
	return nonce, timestamp, signature, nil
}
