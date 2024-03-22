package main

import (
	"fmt"
	"signature/signature"
)

func main() {
	nonce, timestamp, signature, _ := signature.GenerateSignature(
		"GET",
		"/token/balance_list",
		"user_addr=0xe8c19db00287e3536075114b2576c70773e039bd&chain=op")
	fmt.Println(nonce, timestamp, signature)
}
