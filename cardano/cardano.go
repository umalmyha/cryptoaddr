package cardano

import (
	"fmt"

	"github.com/echovl/cardano-go"

	"github.com/umalmyha/cryptoaddr/internal/bip39"
	"github.com/umalmyha/cryptoaddr/internal/cip1852"
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
	addr cardano.Address
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

	path := fmt.Sprintf("m/1852'/1815'/0'/0/%d", o.index)
	paymentKey, stakeKey, err := cip1852.DerivePaymentAndStakeKeysByPath(path, o.mnemonic)
	if err != nil {
		return nil, err
	}

	paymentCreds, err := cardano.NewKeyCredential(paymentKey.XPubKey().PubKey())
	if err != nil {
		return nil, err
	}

	stakeCreds, err := cardano.NewKeyCredential(stakeKey.XPubKey().PubKey())
	if err != nil {
		return nil, err
	}

	addr, err := cardano.NewBaseAddress(cardano.Mainnet, paymentCreds, stakeCreds)
	if err != nil {
		return nil, err
	}

	return &Address{addr: addr}, nil
}

func (a *Address) String() string {
	return a.addr.String()
}
