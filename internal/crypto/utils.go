package crypto

import (
	"encoding/binary"
	"runtime"

	"golang.org/x/crypto/blake2b"
)

func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func HashPublicKey(edPK []byte) []byte {
	hash := blake2b.Sum256(edPK)
	return hash[:10]
}

func ConcatBytes(fields ...[]byte) []byte {
	totalLen := 0
	for _, f := range fields {
		totalLen += 4 + len(f)
	}

	res := make([]byte, totalLen)
	offset := 0
	for _, f := range fields {
		binary.BigEndian.PutUint32(res[offset:offset+4], uint32(len(f)))
		offset += 4
		copy(res[offset:], f)
		offset += len(f)
	}
	return res
}
