package ed25519

import (
       "bytes"
       stded25519 "crypto/ed25519"
       "crypto/rand"
       "crypto/sha256"
       "crypto/subtle"
       "crypto/x509"
       "encoding/hex"
       "fmt"
       "io"

       "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
       "github.com/oasisprotocol/curve25519-voi/primitives/ed25519/extra/cache"

       "github.com/dashpay/tenderdash/crypto"
)

//-------------------------------------

var (
       _ crypto.PrivKey = PrivKey{}

       // curve25519-voi's Ed25519 implementation supports configurable
       // verification behavior, and tendermint uses the ZIP-215 verification
       // semantics.
       verifyOptions = &ed25519.Options{
               Verify: ed25519.VerifyOptionsZIP_215,
       }

       cachingVerifier = cache.NewVerifier(cache.NewLRUCache(cacheSize))
)

const (
       PrivKeyName = "tendermint/PrivKeyEd25519"
       PubKeyName  = "tendermint/PubKeyEd25519"
       // PubKeySize is is the size, in bytes, of public keys as used in this package.
       PubKeySize = 32
       // PrivateKeySize is the size, in bytes, of private keys as used in this package.
       PrivateKeySize = 64
       // Size of an Edwards25519 signature. Namely the size of a compressed
       // Edwards25519 point, and a field element. Both of which are 32 bytes.
       SignatureSize = 64
       // SeedSize is the size, in bytes, of private key seeds. These are the
       // private key representations used by RFC 8032.
       SeedSize = 32

       KeyType = "ed25519"

       // cacheSize is the number of public keys that will be cached in
       // an expanded format for repeated signature verification.
       //
       // TODO/perf: Either this should exclude single verification, or be
       // tuned to `> validatorSize + maxTxnsPerBlock` to avoid cache
       // thrashing.
       cacheSize = 4096
)

// PrivKey implements crypto.PrivKey.
type PrivKey []byte

// Bytes returns the privkey byte format.
func (privKey PrivKey) Bytes() []byte {
       return []byte(privKey)
}

// Sign produces a signature on the provided message.
// This assumes the privkey is wellformed in the golang format.
// The first 32 bytes should be random,
// corresponding to the normal ed25519 private key.
// The latter 32 bytes should be the compressed public key.
// If these conditions aren't met, Sign will panic or produce an
// incorrect signature.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
       signatureBytes := ed25519.Sign(ed25519.PrivateKey(privKey), msg)
       return signatureBytes, nil
}

// Sign produces a signature on the provided message.
// This assumes the privkey is wellformed in the golang format.
// The first 32 bytes should be random,
// corresponding to the normal ed25519 private key.
// The latter 32 bytes should be the compressed public key.
// If these conditions aren't met, Sign will panic or produce an
// incorrect signature.
func (privKey PrivKey) SignDigest(msg []byte) ([]byte, error) {
       signatureBytes := ed25519.Sign(ed25519.PrivateKey(privKey), msg)
       return signatureBytes, nil
}

// PubKey gets the corresponding public key from the private key.
//
// Panics if the private key is not initialized.
func (privKey PrivKey) PubKey() crypto.PubKey {
       // If the latter 32 bytes of the privkey are all zero, privkey is not
       // initialized.
       initialized := false
       for _, v := range privKey[32:] {
               if v != 0 {
                       initialized = true
                       break
               }
       }

       if !initialized {
               panic("Expected ed25519 PrivKey to include concatenated pubkey bytes")
       }

       pubkeyBytes := make([]byte, PubKeySize)
       copy(pubkeyBytes, privKey[32:])
       return PubKey(pubkeyBytes)
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
       if otherEd, ok := other.(PrivKey); ok {
               return subtle.ConstantTimeCompare(privKey[:], otherEd[:]) == 1
       }

       return false
}

func (privKey PrivKey) Type() string {
       return KeyType
}

func (privKey PrivKey) TypeValue() crypto.KeyType {
       return crypto.Ed25519
}

// GenPrivKey generates a new ed25519 private key.
// It uses OS randomness in conjunction with the current global random seed
// in tendermint/libs/common to generate the private key.
func GenPrivKey() PrivKey {
       return genPrivKey(rand.Reader)
}

// genPrivKey generates a new ed25519 private key using the provided reader.
func genPrivKey(rand io.Reader) PrivKey {
       _, priv, err := ed25519.GenerateKey(rand)
       if err != nil {
               panic(err)
       }

       return PrivKey(priv)
}

// GenPrivKeyFromSecret hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyFromSecret(secret []byte) PrivKey {
       seed := sha256.Sum256(secret)
       return PrivKey(ed25519.NewKeyFromSeed(seed[:]))
}

// FromDER loads ed25519 private key from DER-encoded buffer
func FromDER(der []byte) (PrivKey, error) {
       parsed, err := x509.ParsePKCS8PrivateKey(der)
       if err != nil {
               return nil, fmt.Errorf("cannot parse private key: %w", err)
       }

       // As x509 uses stdlib crypto/ed25519, we have to convert it to curve25519-voi
       // Fortunately, they are compatible (at least for now)
       privkey, ok := parsed.(stded25519.PrivateKey)
       if !ok {
               return nil, fmt.Errorf("cannot convert %T to ED25519 private key", parsed)
       }

       return PrivKey(ed25519.NewKeyFromSeed(privkey.Seed())), nil
}

//-------------------------------------

var _ crypto.PubKey = PubKey{}

// PubKey implements crypto.PubKey for the Ed25519 signature scheme.
type PubKey []byte

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKey) Address() crypto.Address {
       if len(pubKey) != PubKeySize {
               panic("pubkey is incorrect size")
       }
       return crypto.AddressHash(pubKey)
}

// Bytes returns the PubKey byte format.
func (pubKey PubKey) Bytes() []byte {
       return []byte(pubKey)
}

func (pubKey PubKey) VerifySignatureDigest(hash []byte, sig []byte) bool {
       // make sure we use the same algorithm to sign
       if len(sig) != SignatureSize {
               return false
       }

       verified := ed25519.Verify(ed25519.PublicKey(pubKey), hash, sig)
       // fmt.Printf("ed25519 verified (%t) sig %X from message %X with key %X\n", verified, sig, msg, pubKey.Bytes())
       return verified
}

func (pubKey PubKey) VerifySignature(msg []byte, sig []byte) bool {
       // make sure we use the same algorithm to sign
       if len(sig) != SignatureSize {
               return false
       }

       return cachingVerifier.VerifyWithOptions(ed25519.PublicKey(pubKey), msg, sig, verifyOptions)
}

func (pubKey PubKey) String() string {
       return fmt.Sprintf("PubKeyEd25519{%X}", []byte(pubKey))
}

// HexString returns hex-string representation of pubkey
func (pubKey PubKey) HexString() string {
       return hex.EncodeToString(pubKey)
}

func (pubKey PubKey) Type() string {
       return KeyType
}

func (pubKey PubKey) TypeValue() crypto.KeyType {
       return crypto.Ed25519
}

func (pubKey PubKey) Equals(other crypto.PubKey) bool {
       if otherEd, ok := other.(PubKey); ok {
               return bytes.Equal(pubKey[:], otherEd[:])
       }

       return false
}