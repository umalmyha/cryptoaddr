package btc

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"

	"github.com/umalmyha/cryptoaddr/internal/bip32"
	"github.com/umalmyha/cryptoaddr/internal/bip39"
)

type options struct {
	mnemonic string
	password string
	index    uint32
}

type option func(o *options)

func WithMnemonic(mnemonic string) option {
	return func(o *options) {
		o.mnemonic = mnemonic
	}
}

func WithPassword(password string) option {
	return func(o *options) {
		o.password = password
	}
}

func WithAddrIndex(index uint32) option {
	return func(o *options) {
		o.index = index
	}
}

type Address struct {
	addr *btcutil.AddressPubKeyHash
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

	path := fmt.Sprintf("m/44'/0'/0'/0/%d", o.index)
	key, err := bip32.DeriveKeyByPath(path, o.mnemonic, o.password)
	if err != nil {
		return nil, err
	}

	addr, err := key.Address(bip32.MainNet)
	if err != nil {
		return nil, err
	}

	return &Address{addr: addr}, nil
}

func (a *Address) String() string {
	return a.addr.EncodeAddress()
}
