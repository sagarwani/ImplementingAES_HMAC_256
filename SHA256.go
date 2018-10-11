package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
)

func main() {
	h := sha256.New()
	h.Write([]byte("h\n"))
	fmt.Printf("%x", h.Sum(nil))

	var gh uint8
	gh := h.Sum(nil)
	fmt.Println("The value of gh is: ", gh)
	fmt.Println("Type of gh is: ", reflect.TypeOf(gh))
	fmt.Println()
	fmt.Println("Type of h.Sum is: ", reflect.TypeOf(h.Sum(nil)))
	fmt.Println("The value of h.Sum is: ", h.Sum(nil))
	fmt.Println()
	kmac := []uint8(h.Sum(nil))
	fmt.Println("Type of kmac is: ", reflect.TypeOf(kmac))
	fmt.Printf("%x",kmac)
	//kmac_repeat := strings.Repeat("#", 16)

}