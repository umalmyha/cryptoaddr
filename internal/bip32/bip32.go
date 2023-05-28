package bip32

import (
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"

	dpath "github.com/umalmyha/cryptoaddr/internal/path"
)

var MainNet = &chaincfg.MainNetParams

func DeriveKeyByPath(path string, mnemonic string, password string) (*hdkeychain.ExtendedKey, error) {
	seed := bip39.NewSeed(mnemonic, password)

	rootKey, err := hdkeychain.NewMaster(seed, MainNet)
	if err != nil {
		return nil, err
	}

	drvPath, err := dpath.Parse(path)
	if err != nil {
		return nil, err
	}

	key := rootKey
	for _, p := range drvPath {
		key, err = key.Derive(p)
		if err != nil {
			return nil, err
		}
	}

	return key, nil
}
