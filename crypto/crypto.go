package crypto

import (
       "crypto/sha256"
       "fmt"
)

const (
       // HashSize is the size in bytes of an AddressHash.
       HashSize = sha256.Size

       // AddressSize is the size of a pubkey address.
       AddressSize        = 20
)

const (
       Ed25519 KeyType = iota
       //BLS12381
       //Secp256k1
       //KeyTypeAny
)

type Address = []byte

type KeyType int

type PubKey interface {
       Address() Address
       Bytes() []byte
       VerifySignature(msg []byte, sig []byte) bool
       VerifySignatureDigest(hash []byte, sig []byte) bool
       Equals(PubKey) bool
       Type() string

       fmt.Stringer
       HexStringer
}

// HexStringer ...
type HexStringer interface {
       HexString() string
}

type PrivKey interface {
       Bytes() []byte
       Sign(msg []byte) ([]byte, error)
       SignDigest(msg []byte) ([]byte, error)
       PubKey() PubKey
       Equals(PrivKey) bool
       Type() string
}

// BatchVerifier If a new key type implements batch verification,
// the key type must be registered in github.com/dashpay/tenderdash/crypto/batch
type BatchVerifier interface {
       // Add appends an entry into the BatchVerifier.
       Add(key PubKey, message, signature []byte) error
       // Verify verifies all the entries in the BatchVerifier, and returns
       // if every signature in the batch is valid, and a vector of bools
       // indicating the verification status of each signature (in the order
       // that signatures were added to the batch).
       Verify() (bool, []bool)
}

// AddressHash computes a truncated SHA-256 hash of bz for use as
// a peer address.
//
// See: https://docs.tendermint.com/master/spec/core/data_structures.html#address
func AddressHash(bz []byte) Address {
       h := sha256.Sum256(bz)
       return Address(h[:AddressSize])
}
