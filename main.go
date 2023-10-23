package main

import (
       "encoding/hex"
       "encoding/json"
       "fmt"
       "log"

       "github.com/dashpay/tenderdash/crypto"
       "github.com/dashpay/tenderdash/crypto/ed25519"
)

type NodeID string

// NodeKey is the persistent peer key.
// It contains the nodes private key for authentication.
type NodeKey struct {
       // Canonical ID - hex-encoded pubkey's address (IDByteLength bytes)
       ID NodeID
       // Private key
       PrivKey crypto.PrivKey
}

// GenNodeKey generates a new node key.
func GenNodeKey() NodeKey {
       privKey := ed25519.GenPrivKey()
       return NodeKey{
               ID:      NodeIDFromPubKey(privKey.PubKey()),
               PrivKey: privKey,
       }
}

// NodeIDFromPubKey creates a node ID from a given PubKey address.
func NodeIDFromPubKey(pubKey crypto.PubKey) NodeID {
       return NodeID(hex.EncodeToString(pubKey.Address()))
}

func main() {
       nodeKey := GenNodeKey()

       bz, err := json.Marshal(nodeKey)
       if err != nil {
               log.Fatalf("cannot format node key: %s", err)
       }

       fmt.Println(string(bz))

}
