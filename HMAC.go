package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	hmac_string := ComputeHmac256("80b4a0820965bd51184e3f987ac808e39f5fcf7fc425d06156d4560b92a8913a", "fc3705b649dcfd23d5c0fcd382c34c6f")

	fmt.Println("The computed HMAC is: ", hmac_string)
	
}
