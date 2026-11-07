package crypto

import (
	"bytes"
	"sync"
	"testing"
)

func TestAESStreams(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	iv := bytes.Repeat([]byte{2}, 16)
	data := bytes.Repeat([]byte{3}, 64)
	for _, kind := range []string{"ctr", "cbc"} {
		var enc, dec Cipher
		if kind == "ctr" {
			enc = NewAESCTR(key, Uint128FromBytes(iv))
			dec = NewAESCTR(key, Uint128FromBytes(iv))
		} else {
			enc = NewAESCBC(key, iv)
			dec = NewAESCBC(key, iv)
		}
		for i := 0; i < 4; i++ {
			ciphertext := enc.Encrypt(data)
			if bytes.Equal(ciphertext, data) || !bytes.Equal(dec.Decrypt(ciphertext), data) {
				t.Fatal(kind)
			}
		}
	}
}
func TestRandomConcurrent(t *testing.T) {
	r := NewCryptoRand()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b := r.Bytes(16)
				if len(b) != 16 {
					t.Error("bad length")
				}
				n := r.Intn(7)
				if n < 0 || n >= 7 {
					t.Error("out of range")
				}
			}
		}()
	}
	wg.Wait()
}
func TestIntnRejectsInvalid(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Intn(0) accepted")
		}
	}()
	GlobalRand.Intn(0)
}
