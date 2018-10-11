package main

import (
	"fmt"
	"reflect"
	"strings"
)

func main() {

	/*mode := os.Args[1]
	fmt.Println("The mode being used is: ", mode)

	var ip string
	flag.Var(&ip, "namex", "Enter your name")
	fmt.Println("The number entered is: ", ip)*/

	a := "91ee5e9f42ba3d34e414443b36a27b797a56a47aad6bb1e4c1769e69c77ce0ca"
	ax := []uint8(a)
	fmt.Println(reflect.TypeOf(ax))

	bx := strings.Repeat("0x5c", 8)
	fmt.Println(reflect.TypeOf(bx))
	fmt.Println(bx)

	d := 0x5c6e4b
	e := 0x36
	cx := d ^ e
	fmt.Println(reflect.TypeOf(d))
	fmt.Println(cx)

	p := "56B9@pYwOW3MbmN@CaR!%28^U8@T8TJt"
	px := make([]byte, len(p))
	px = []byte(p)
	q := "Johns Hopkins is located in Baltimore, Maryland."
	qx := make([]byte, len(q))
	fmt.Println("Type of qx is: ", reflect.TypeOf(qx))
	qx = []byte(q)
	fmt.Println("The value of p is: ", p)
	fmt.Println("The value of px is: ", px)
	fmt.Println("Length of px is: ", len(px))
	fmt.Println("The value of q is: ", qx)








}
