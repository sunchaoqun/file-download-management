package main

import (
    "crypto"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/aes"
    "crypto/x509"
    "encoding/pem"
    // "encoding/base64"
    "os"
    "crypto/rand"
    "io/ioutil"
    // "fmt"
    "log"
)

type AesTool struct {
	Key       []byte
	BlockSize int
}
 
func NewAesTool(key []byte, blockSize int) *AesTool {
	return &AesTool{Key: key, BlockSize: blockSize}
}
 
func (at *AesTool) unPadding(src []byte) []byte {
	size := len(src)
	return src[:(size-int(src[size-1]))]
}
 
func (at *AesTool) Decrypt(src []byte) []byte {
	//key只能是 16 24 32长度
	block, err := aes.NewCipher(at.Key)
	if err != nil {
		log.Fatal(err)
	}
	//返回加密结果
	decryptData := make([]byte, len(src))
	//存储每次加密的数据
	tmpData := make([]byte, at.BlockSize)
 
	//分组分块加密
	for index := 0; index < len(src); index += at.BlockSize {
		block.Decrypt(tmpData, src[index:index+at.BlockSize])
		copy(decryptData[index:index+at.BlockSize], tmpData)
	}

	return at.unPadding(decryptData)
}

func main() {
    BlockSize := 32
    encrypted_file_name := "ENCRYPTED_FILE_NAME"
    // 加载 PEM 格式的私钥
    pemData, pk_error := os.ReadFile("private_key.pem")

    if pk_error != nil {
        panic("please provide your private key in current folder with name 'private_key.pem'")
    }
    
    block, _ := pem.Decode(pemData)
    
    // fmt.Println(block.Type)

    if block == nil {
        panic("failed to decode PEM block containing the key")
    }

    var privKey crypto.PrivateKey

    // 解析私钥
    // privKey, _ := x509.ParseECPrivateKey(block.Bytes)
    if block.Type == "PRIVATE KEY" {
        privKey, _ = x509.ParsePKCS8PrivateKey(block.Bytes)
    } else if block.Type == "RSA PRIVATE KEY" {
        privKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
    } else {
        panic("Do not support current private key")
    }

    // 类型断言，例如对于 RSA 私钥：
    rsaKey, ok := privKey.(*rsa.PrivateKey)
    if !ok {
        // 密钥不是 *rsa.PrivateKey 类型，处理错误
        panic("Not an RSA private key")
    }

    // 读取加密的 AES 密钥
    encryptedData, _ := os.ReadFile(encrypted_file_name + "_encrypted_aes_key_file.bin")

    // 解密 AES 密钥
    decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, encryptedData, []byte(nil))
    if err != nil {
		panic(err)
	}

    // 输出或处理解密后的数据
    // ...
    // base64Str := base64.StdEncoding.EncodeToString(decryptedData)
	
    // 打印 Base64 字符串
    // fmt.Println("Base64 Encoded String:", base64Str)

    // Reading ciphertext file
	cipherText, err := ioutil.ReadFile(encrypted_file_name + "_encrypted_file.bin")
	if err != nil {
		log.Fatal(err)
	}

    read_key := decryptedData[:BlockSize]
    // base64Str1 := base64.StdEncoding.EncodeToString(read_key)

    // fmt.Println("Base64 Encoded String:", base64Str1)
    
    tool := NewAesTool(read_key, 16)

    // Writing decryption content
    err = ioutil.WriteFile("OUTPUT_FILE", tool.Decrypt(cipherText), 0755)
    if err != nil {
        log.Fatalf("write file err: %v", err.Error())
    }
}