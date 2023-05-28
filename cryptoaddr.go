package cryptoaddr

import "github.com/umalmyha/cryptoaddr/internal/bip39"

type words int

const (
	MnemonicWords12 words = 128 // 12 words
	MnemonicWords24 words = 256 // 24 words
)

func RandomMnemonic(w words) (string, error) {
	return bip39.Mnemonic(int(w))
}
