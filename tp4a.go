package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"fmt"
)

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

func main() {
	var str string
	flag.StringVar(&str, "s", "", "input your passwd")
	flag.Parse()

	if flag.NFlag() == 0 {
		fmt.Print("  -s string\n        input your passwd\n")
		return
	}

	strbytes := []byte(str)
	decoded, _ := base64.StdEncoding.DecodeString(string(strbytes))
	decodestr := string(decoded)
	key := []byte{0xd6, 0xb6, 0x6e, 0x3b, 0x41, 0xc4, 0x33, 0x13, 0xaa, 0x61, 0xc9, 0x47, 0x82, 0xfc, 0x84, 0x50,
		0x85, 0x53, 0x3a, 0x01, 0x97, 0x2d, 0xca, 0xba, 0x87, 0xbc, 0x27, 0x20, 0x29, 0xde, 0x87, 0x67}
	origin, _ := AesDecrypt([]byte(decodestr), key)
	origin = origin[16:]
	fmt.Println(string(origin))
	return
}
