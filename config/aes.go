package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	encKey []byte = nil
	iv     []byte = nil
)

func SetEnc(key string, ivStr string) (error) {
	if (key == "" || ivStr == "") {
		return fmt.Errorf("aes key and iv is empty")
	}
	encKey = []byte(key)
	iv = []byte(ivStr)
	_, err := AesEncrypt([]byte("Hello"))
	if err != nil {
		return fmt.Errorf("aes config error : %v", err)
	}
	return nil
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData []byte) (string, error) {
	if nil == encKey {
		return "", errors.New("no encKey provided")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	cryptHex := base64.StdEncoding.EncodeToString(crypted)
	return cryptHex, nil
}

func AesDecrypt(cryptHex string) ([]byte, error) {
	if nil == encKey {
		return nil, errors.New("no encKey provided")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	crypted, err := base64.StdEncoding.DecodeString(cryptHex)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}