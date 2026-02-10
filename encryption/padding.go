package encryption

import (
	"bytes"
	"fmt"
)

// pkcs7Pad appends PKCS#7 padding to src so that its length is a multiple of
// blockSize.  blockSize must be between 1 and 255 (AES uses 16).
//
// If len(src) is already a multiple of blockSize, a full extra block of padding
// is appended so that the padding can always be unambiguously removed.
func pkcs7Pad(src []byte, blockSize int) []byte {
	padding := blockSize - (len(src) % blockSize)
	return append(src, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

// pkcs7Unpad removes PKCS#7 padding from src and returns the original data.
//
// Security note: this function is only called after HMAC verification succeeds,
// so it is not exposed to padding-oracle attacks.  The check is still performed
// carefully to avoid returning incorrect data on pathological inputs.
func pkcs7Unpad(src []byte, blockSize int) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrDecryptionFailed)
	}
	if length%blockSize != 0 {
		return nil, fmt.Errorf("%w: ciphertext length %d is not a multiple of block size %d",
			ErrDecryptionFailed, length, blockSize)
	}

	padding := int(src[length-1])
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("%w: invalid PKCS#7 padding byte value %d",
			ErrDecryptionFailed, padding)
	}
	if padding > length {
		return nil, fmt.Errorf("%w: padding length %d exceeds input length %d",
			ErrDecryptionFailed, padding, length)
	}

	// Verify every padding byte.
	for i := length - padding; i < length; i++ {
		if src[i] != byte(padding) {
			return nil, fmt.Errorf("%w: malformed PKCS#7 padding at byte %d",
				ErrDecryptionFailed, i)
		}
	}
	return src[:length-padding], nil
}
