package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func XorByteArray(bytearray1 []byte, bytearray2 []byte) []byte {
	bytearrayfinal := make([]byte, len(bytearray1))
	for i := 0 ; i < len(bytearray1); i++{
		bytearrayfinal[i] = bytearray1[i] ^ bytearray2[i]
	}
	return bytearrayfinal
}

func DivideIntoBlocks(bytearray []byte, AESBlockSize int) [][]byte{
	AESBlockSize = 16
	numberofblocks := len(bytearray) / AESBlockSize
	start := 0
	stop := AESBlockSize
	bytearrayblocks := make([][]byte, numberofblocks)
	for i := 0; i < numberofblocks; i++ {
		bytearrayblocks[i] = bytearray[start:stop]
		start += AESBlockSize
		stop += AESBlockSize
	}
	return bytearrayblocks
}

func hmac_sha256(message []byte, kmacx []byte) []byte {
	var result []byte

	kmac := make([]byte, 64)
	for j := 0; j < len(kmacx); j++ {
		kmac[j] = kmacx[j]
	}

	//Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
	if (len(kmac) == 64) {

		opad_xor1 := strings.Repeat( "\\", 64)
		opad := make([]byte, len(opad_xor1))
		opad = []byte(opad_xor1)

		ipad_xor := strings.Repeat("6", 64)
		ipad := make([]byte, len(ipad_xor))
		ipad = []byte(ipad_xor)


		innerhash := XorByteArray(kmac, ipad)
		for i := 0; i < len(message); i++ {
			innerhash = append(innerhash, message[i])
		}

		sha256z := sha256.Sum256(innerhash)
		outerhash := XorByteArray(kmac, opad)

		for i := 0; i < len(sha256z); i++ {
			outerhash = append(outerhash, sha256z[i])
		}

		finalsha256 := sha256.Sum256(outerhash)
		result = finalsha256[:]

	}
	return result
}

func encrypt(messageinbytes []byte, iv []byte, kenc []byte, kmac []byte, outputfilename string) []byte {

	//Calculate HMAC - SHA256 of the data
	hmac := hmac_sha256(messageinbytes, kmac)

	//M' = M || Y
	for i := 0; i < len(hmac); i++ {
		messageinbytes = append(messageinbytes, hmac[i])
	}

	//M'' = M' || Padding - PKCS#5----------------------------------------------------------------------
	n := len(messageinbytes) % 16
	if n != 0{
		size := 16 - n
		for m := 0; m < size; m++{
			messageinbytes = append(messageinbytes, byte(size))
		}
	}
	if n == 0 {
		size := 16
		for m := 0; m < size; m++{
			messageinbytes = append(messageinbytes, byte(size))
		}

	}
	//==================================================================================================

	//Dividing message into blocks of 16
	numberofblocks := len(messageinbytes) / 16
	datablocks := make([][]byte, numberofblocks)
	start := 0
	stop := 16
	for i := 0; i < numberofblocks; i++ {
		datablocks[i] = messageinbytes[start:stop]
		start += 16
		stop += 16
	}

	//XOR IV and 1st Block of message.
	xorinput := make([]byte, 16)
	for i := 0; i < 16; i++{
		xorinput[i] = datablocks[0][i] ^ iv[i]
	}

	kencinbytes := make([]byte, len(kenc))
	for j := 0; j < len(kenc); j++ {
		kencinbytes[j] = kenc[j]
	}

	//Encrypt 1st Block.
	BlockEncrypt, _ := aes.NewCipher(kencinbytes)

	ct0 := make([]byte, 16)
	BlockEncrypt.Encrypt(ct0, xorinput)

	//Encrypt Rest of the blocks.
	ctx := make([][]byte, numberofblocks)
	ctx[0] = ct0
	for k := 1; k <numberofblocks; k++ {
		xorvalue := make([]byte, 16)
		temp := make([]byte, 16)
		for i := 0; i < 16; i++ {
			xorvalue[i] = ctx[k-1][i] ^ datablocks[k][i]
		}
		BlockEncrypt.Encrypt(temp, xorvalue)
		ctx[k] = temp
	}
	cipher := make([]byte, numberofblocks * 16)
	r := 0
	for p := 0; p<numberofblocks; p++{
		for q := 0; q < 16; q++{
			cipher[r] = ctx[p][q]
			r++
		}
	}
	for s := 0; s < len(cipher); s++{
		iv = append(iv, cipher[s])
	}
	return iv
}

func decrypt(kencx []byte, kmacx []byte, ciphertextx []byte) []byte {

	var ciphertext []byte

	//Get the IV
	iv := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++{
		iv[i] = ciphertextx[i]
	}

	//Get the ciphertext
	for i := aes.BlockSize; i < len(ciphertextx); i++{
		ciphertext = append(ciphertext, ciphertextx[i])
	}

	kenc := make([]byte, len(kencx))
	for j := 0; j < len(kencx); j++ {
		kenc[j] = kencx[j]
	}

	//Dividing ciphertext into blocks
	numberofblocks := len(ciphertext) / 16
	start := 0
	stop := 16
	cipherblocks := make([][]byte, numberofblocks)
	for i := 0; i < numberofblocks; i++ {
		cipherblocks[i] = ciphertext[start:stop]
		start += 16
		stop += 16
	}

	//Decrypt 1st block.
	BlockDecrypt, _ := aes.NewCipher(kenc)
	plaintextblocks := make([][]byte, numberofblocks)

	xorvalue := make([]byte, 16)
	BlockDecrypt.Decrypt(xorvalue, cipherblocks[0])

	pt0 := make([]byte, 16)
	for i := 0; i < 16; i++{
		pt0[i] = xorvalue[i] ^ iv[i]
	}
	plaintextblocks[0] = pt0
	//fmt.Println("The value of first block of plaintext is: ", pt0)

	//Decrypt all blocks.
	for k := 1; k <numberofblocks; k++ {
		plainvalue := make([]byte, 16)
		temp := make([]byte, 16)
		BlockDecrypt.Decrypt(temp, cipherblocks[k])
		for i := 0; i < 16; i++{
			plainvalue[i] = temp[i] ^ cipherblocks[k-1][i]
		}
		plaintextblocks[k] = plainvalue
	}
	//fmt.Println("The plaintext blocks are: ", plaintextblocks)

	//Get a single plaintext block from blocks of plaintext
	datablock := make([]byte, numberofblocks * 16)
	r := 0
	for p := 0; p<numberofblocks; p++{
		for q := 0; q < 16; q++{
			datablock[r] = plaintextblocks[p][q]
			r++
		}
	}
	//Padding check
	lastbytevalue := datablock[len(datablock) - 1]
	if int(lastbytevalue) != 0 {
		for i := len(datablock) - 1; i >= len(datablock)-int(lastbytevalue); i-- {
			if datablock[i] != lastbytevalue {
				fmt.Println("INVALID PADDING")
				os.Exit(1)
			}
		}
	} else {
		fmt.Println("INVALID PADDING")
		os.Exit(1)
	}
	//fmt.Println("This is debug. #################################")

	//HMAC Test
	hmac := make([]byte, 32)
	last := len(datablock) - 1 - int(lastbytevalue)
	//Taking value of HMAC from plaintext byteArray.
	for i := 0; i < 32; i++{
		hmac[31 - i] = datablock[last]
		last--
	}

	//Creating byteArray stripping HMAC.
	datablockwithouthmac := make([]byte, len(datablock) - len(hmac) - int(lastbytevalue))
	for j := 0; j < last+1; j++ {
		datablockwithouthmac[j] = datablock[j]
	}

	//Calculate HMAC of the plaintext byteArray.
	originalhmac := hmac_sha256(datablockwithouthmac, kmacx)

	//compare hmac
	for i := 0; i < 32; i++{
		if originalhmac[i] != hmac[i] {
			fmt.Println("INVALID MAC")
			os.Exit(1)
		}
	}
	return datablockwithouthmac
}

func main() {

	if len(os.Args) < 7{
		fmt.Println("" +
			"" +
			"\n\nUsage: encrypt-auth <mode> -k <key> -i <input file> -o <output file>\n" +
			"Mode = encrypt or decrypt\n" +
			"-k = Enter the 32-byte key for encryption/decryption in hexadecimal\n" +
			"-i = Enter the name of input file\n" +
			"-o Enter the name of output file.")
		os.Exit(1)
	}

	//Taking command line arguments
	mode := os.Args[1]
	key := os.Args[3]
	input_file := os.Args[5]
	output_file := os.Args[7]

	//Making the Kencryption and Kmac
	kencz := key[0:32]
	kmacz := key[32:64]
	kenc, _ := hex.DecodeString(kencz)
	kmac, _ := hex.DecodeString(kmacz)

	//Simply reading the text file and taking contents into a variable.
	file, err := os.Open(input_file)
	if err != nil {
		log.Fatal(err)
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()
	file.Close()

	var ciphertext []byte
	if mode == "encrypt" {
		//Generate Random IV
		iv := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		}

		//Explicitly defining inputs to the program.

		/*
		strx := "1111111111111111" //IV
		for i := 0; i < 16; i++{
			iv[i] = strx[i]
		}
		*/
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		}


		//Calling the encryption function
		ciphertext = encrypt(data, iv, kenc, kmac, output_file)
		err_write := ioutil.WriteFile(output_file, ciphertext, 0644)
		if err_write!=nil {
			fmt.Println("ERROR: ", err_write)
		}
	} else {

		//Decryption
		plaintext := decrypt(kenc, kmac, data)
		err_write := ioutil.WriteFile(output_file, plaintext, 0644)
		if err_write!=nil {
			fmt.Println("ERROR: ", err_write)
		}
	}
	//End of Main()
}
