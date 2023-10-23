package ed25519_test

import (
       "bytes"
       stded25519 "crypto/ed25519"
       "crypto/rand"
       "crypto/x509"
       "encoding/base64"
       "testing"

       voided25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"

       "github.com/dashpay/tenderdash/crypto/ed25519"
)

func TestSignAndValidateEd25519(t *testing.T) {

       privKey := ed25519.GenPrivKey()
       pubKey := privKey.PubKey()

       msg := make([]byte, 128)
       if _, err := rand.Read(msg); err != nil {
               panic(err)
       }
       sig, err := privKey.SignDigest(msg)
       if err != nil {
               t.Fatal("err not nil")
       }

       // Test the signature
       if !pubKey.VerifySignature(msg, sig) {
               t.Fail()
       }

       // Mutate the signature, just one bit.
       // TODO: Replace this with a much better fuzzer, tendermint/ed25519/issues/10
       sig[7] ^= byte(0x01)

       if pubKey.VerifySignature(msg, sig) {
               t.Fail()
       }
}

func TestFromDer(t *testing.T) {
       var testCases = []struct {
               privkeyBase64Der        string
               expectedPubkeyBase64Der string
       }{
               {
                       privkeyBase64Der:        "MC4CAQAwBQYDK2VwBCIEIB/3MZ9V0e8JidiOiDtN3Nk3sGnwohSgaAmIFuScDfOy",
                       expectedPubkeyBase64Der: "MCowBQYDK2VwAyEAcpYVXaxQmDGUnlpgTe71OKv4cUcbw8k+/IeW8cZF4W4=",
               },
       }

       for _, tc := range testCases {
               t.Run("", func(t *testing.T) {
                       privkeyDer, err := base64.StdEncoding.DecodeString(tc.privkeyBase64Der)
                       if err != nil {
                               t.Fatal("err not nil")
                       }
                       expectedPubkeyDer, err := base64.StdEncoding.DecodeString(tc.expectedPubkeyBase64Der)
                       if err != nil {
                               t.Fatal("err not nil")
                       }

                       expectedPubkeyStd, err := x509.ParsePKIXPublicKey(expectedPubkeyDer)
                       if err != nil {
                               t.Fatal("err not nil")
                       }
                       expectedPubkey := []byte(expectedPubkeyStd.(stded25519.PublicKey))

                       privkey, err := ed25519.FromDER(privkeyDer)
                       if err != nil {
                               t.Fatal("err not nil")
                       }
                       if len(privkey) != ed25519.PrivateKeySize {
                               t.Fatal("privkey wrong size")
                       }
                       if !bytes.Equal(expectedPubkey, privkey.PubKey().Bytes()) {
                               t.Fatal("bytes are not the same")
                       }
               })
       }
}

// TestEd25519StdlibCompat ensures that key format in "crypto/ed25519" is compatible with
// the keys in "github.com/oasisprotocol/curve25519-voi" (which we use).
// The intention of this test is to detect when external dependencies change the key format, breaking FromDER() logic.
func TestEd25519StdlibCompat(t *testing.T) {
       seed := make([]byte, ed25519.SeedSize)
       if _, err := rand.Read(seed); err != nil {
               panic(err)
       }

       voiPrivkey := voided25519.NewKeyFromSeed(seed)
       voiPubkey := voiPrivkey.Public()
       stdPrivkey := stded25519.NewKeyFromSeed(seed)
       stdPubkey := stdPrivkey.Public().(stded25519.PublicKey)

       if stdPrivkey.Equal(voiPrivkey) {
                               t.Fatal("priv keys are not equal")
       }
       if !bytes.Equal(voiPrivkey.Seed(), stdPrivkey.Seed()) {
                               t.Fatal("seeds are not equal")
       }
       if stdPubkey.Equal(voiPubkey) {
                               t.Fatal("pub keys are not equal")
       }
}
