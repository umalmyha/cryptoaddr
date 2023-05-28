package bip39

import "github.com/tyler-smith/go-bip39"

const MnemonicWords24 = 256 // 24 words

func Mnemonic(words int) (string, error) {
	entropy, err := bip39.NewEntropy(words)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}
