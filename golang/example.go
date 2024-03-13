package main

import (
	"fmt"
	"signature/signature"
)

func main() {
    nonce, timestamp, signature, _ := signature.GenerateSignature("GET", "/user/config", "id=0xe8c19db00287e3536075114b2576c70773e039bd")
    fmt.Println(nonce, timestamp, signature)
}