package cip1852

import (
	"github.com/echovl/cardano-go/crypto"
	"github.com/tyler-smith/go-bip39"
	dpath "github.com/umalmyha/cryptoaddr/internal/path"
)

var CardanoStakePath, _ = dpath.Parse("m/1852'/1815'/0'/2/0")

func DerivePaymentAndStakeKeysByPath(
	path string,
	mnemonic string,
) (payment crypto.XPrvKey, stake crypto.XPrvKey, err error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, nil, err
	}

	rootKey := crypto.NewXPrvKeyFromEntropy(entropy, "")

	drvPath, err := dpath.Parse(path)
	if err != nil {
		return nil, nil, err
	}

	paymentKey := rootKey
	for _, p := range drvPath {
		paymentKey = paymentKey.Derive(p)
	}

	stakeKey := rootKey
	for _, p := range CardanoStakePath {
		stakeKey = stakeKey.Derive(p)
	}

	return paymentKey, stakeKey, nil
}
