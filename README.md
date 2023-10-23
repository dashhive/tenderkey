# tenderkey

platform key generator

```sh
curl https://webi.sh/go | sh
```

```sh
go run ./main.go | jq
```

```json
{
  "ID": "095e5a95c47f8baed3fe3bd26597cd83af00e8a7",
  "PrivKey": "coK/PPHUPFAFFrIhVDZFdQNMk10Snkg4RlfRaTRhZ6L5MQHfd6EJ/hfEaftdnL7BXJX2rpGFaT8i2bsm+c+ZWQ=="
}
```

needs to be formatted as

```sh
tenderdash gen-node-key
```

```json
{
  "id": "eb48976ec8ba0e4098850ddd42edfd1564e3aeb4",
  "priv_key": {
    "type": "tendermint/PrivKeyEd25519",
    "value": "+z0PtlfW+vTUFWwl+E1BfqGA0//8JGA+TlLDa5kjX5sTun26L/D2LUN+JnwQ0IFXTkp4Nh0opkQZf8jj+ruQnw=="
  }
}
```
