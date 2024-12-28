package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Encryptor 定义了加密器接口
type Encryptor interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

// AESEncryptor AES加密器实现
type AESEncryptor struct {
	block cipher.Block
}

// NewAESEncryptor 创建新的AES加密器
func NewAESEncryptor(key []byte) (Encryptor, error) {
	// 确保密钥长度为32字节
	if len(key) > 32 {
		key = key[:32]
	} else if len(key) < 32 {
		newKey := make([]byte, 32)
		copy(newKey, key)
		for i := len(key); i < 32; i++ {
			newKey[i] = byte(i)
		}
		key = newKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建AES加密器失败: %v", err)
	}

	return &AESEncryptor{block: block}, nil
}

// Encrypt 加密数据
func (e *AESEncryptor) Encrypt(data []byte) ([]byte, error) {
	// 创建随机IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("生成IV失败: %v", err)
	}

	// 创建加密器
	stream := cipher.NewCFBEncrypter(e.block, iv)

	// 加密数据
	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	// 返回IV+加密数据
	result := make([]byte, len(iv)+len(encrypted))
	copy(result, iv)
	copy(result[len(iv):], encrypted)

	return result, nil
}

// Decrypt 解密数据
func (e *AESEncryptor) Decrypt(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("数据长度不足")
	}

	// 提取IV
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	// 创建解密器
	stream := cipher.NewCFBDecrypter(e.block, iv)

	// 解密数据
	decrypted := make([]byte, len(data))
	stream.XORKeyStream(decrypted, data)

	return decrypted, nil
}
