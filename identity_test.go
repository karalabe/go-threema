package threema

import (
	"testing"
)

// Tests loading a sample encrypted identity. Don't get overly excited, the data
// is a fake account, not a live one generated by Threema.
func TestNewIdentity(t *testing.T) {
	var (
		testExport    = "A4G3-BF25-JEN4-EA7Q-XSMG-AIYL-A2W6-CCTW-VYGW-HT3L-KVA7-TTG7-VF2G-RHMY-YB5I-ER7S-WQMU-XF4Y-PZLU-XJFN"
		testPass      = "1337speak"
		testIdentity  = "DEADBEEF"
		testSecretKey = [secretLength]byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
		testPublicKey = [publicLength]byte{0x48, 0x44, 0x11, 0x8d, 0xb6, 0xd4, 0x30, 0xd1, 0x39, 0xe7, 0x5e, 0x2b, 0xe5, 0x7a, 0x9d, 0x68, 0x29, 0xff, 0x70, 0xf7, 0xad, 0xdb, 0x5e, 0xf5, 0x6e, 0x72, 0x12, 0x77, 0x17, 0xe1, 0x02, 0x4d}
	)
	id, err := Identify(testExport, testPass)
	if err != nil {
		t.Fatalf("Failed to decrypt exported identity: %v", err)
	}
	if id.identity != testIdentity {
		t.Errorf("Threema identity mismatch: have %v, want %v", id.identity, testIdentity)
	}
	if *id.secretKey != testSecretKey {
		t.Errorf("Threema secret key mismatch: have %x, want %x", id.secretKey, testSecretKey)
	}
	if *id.publicKey != testPublicKey {
		t.Errorf("Threema public key mismatch: have %x, want %x", id.publicKey, testPublicKey)
	}
}
