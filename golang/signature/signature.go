package signature

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"time"
)

func sortQueryString(queryString string) string {

	params, _ := url.ParseQuery(queryString)

	var paramKeys []string
	for paramKey := range params {
		paramKeys = append(paramKeys, paramKey)
	}
	sort.Strings(paramKeys)

	var sortedQueryParams []string
	for _, paramKey := range paramKeys {
		sortedQueryParams = append(sortedQueryParams, fmt.Sprintf("%s=%s", paramKey, params[paramKey][0]))
	}
	return strings.Join(sortedQueryParams, "&")
}

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

	return "n_" + string(nonce), nil
}

func HmacSha256(key []byte, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	hmacBytes := h.Sum(nil)

	return hex.EncodeToString(hmacBytes)
}

func GenerateSignature(requestMethod string, path string, parameters string) (string, int64, string, error) {
	nonce, err := GenerateNonce(40)
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
		sortQueryString(strings.ToLower(parameters)),
	)
	requestParamsHash := Sha256(requestParams)

	signature := HmacSha256(
		[]byte(randStrHash),
		[]byte(requestParamsHash),
	)
	return nonce, timestamp, signature, nil
}
