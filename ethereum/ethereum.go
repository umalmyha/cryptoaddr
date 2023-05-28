package ethereum

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/umalmyha/cryptoaddr/internal/bip32"
	"github.com/umalmyha/cryptoaddr/internal/bip39"
)

type options struct {
	mnemonic string
	index    uint32
}

type option func(o *options)

func WithMnemonic(mnemonic string) option {
	return func(o *options) {
		o.mnemonic = mnemonic
	}
}

func WithAddrIndex(index uint32) option {
	return func(o *options) {
		o.index = index
	}
}

type Address struct {
	addr common.Address
}

func New(opts ...option) (*Address, error) {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	if o.mnemonic == "" {
		m, err := bip39.Mnemonic(bip39.MnemonicWords24)
		if err != nil {
			return nil, err
		}
		o.mnemonic = m
	}

	path := fmt.Sprintf("m/44'/60'/0'/0/%d", o.index)
	key, err := bip32.DeriveKeyByPath(path, o.mnemonic, "")
	if err != nil {
		return nil, err
	}

	privateKey, err := key.ECPrivKey()
	if err != nil {
		return nil, err
	}

	publicKey, ok := privateKey.ToECDSA().Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("unexpected error occurred while trying to extract ECDSA public key")
	}

	return &Address{addr: crypto.PubkeyToAddress(*publicKey)}, nil
}

func (a *Address) String() string {
	return a.addr.String()
}
