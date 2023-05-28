package cryptoaddr_test

import (
	"strings"
	"testing"

	"github.com/umalmyha/cryptoaddr"
	"github.com/umalmyha/cryptoaddr/btc"
	"github.com/umalmyha/cryptoaddr/cardano"
	"github.com/umalmyha/cryptoaddr/ethereum"
)

func TestRandomMnemonic(t *testing.T) {
	mnc, err := cryptoaddr.RandomMnemonic(cryptoaddr.MnemonicWords12)
	if err != nil {
		t.Fatalf("failed to generated random 12 words: %v", err)
	}

	if ln := len(strings.Split(mnc, " ")); ln != 12 {
		t.Fatalf("expected 12 words to be generated, but got : %v", ln)
	}

	mnc, err = cryptoaddr.RandomMnemonic(cryptoaddr.MnemonicWords24)
	if err != nil {
		t.Fatalf("failed to generated random 24 words: %v", err)
	}

	if ln := len(strings.Split(mnc, " ")); ln != 24 {
		t.Fatalf("expected 24 words to be generated, but got : %v", ln)
	}
}

func TestBitcoin(t *testing.T) {
	testTable := []struct {
		name     string
		mnemonic string
		password string
		indexes  []uint32
		expected []string
	}{
		{
			name:     "1st mnemonic, 3 different indexes, no password",
			mnemonic: "neither tortoise intact clog time muscle piece increase that project cover session episode legend doll struggle heart remove avocado popular cement lock blouse whip",
			indexes:  []uint32{0, 1, 2},
			password: "",
			expected: []string{
				"1PFqiQQtssXLRkHfVqkaQveqk2VJ9DrNt2",
				"1EuSykVxndbex8xK4s6NB1vS3dZYDZVbtF",
				"13XNqf6sDfSgcDAb8T9Xdgjq41ZR3tGZtF",
			},
		},
		{
			name:     "2nd mnemonic, 3 different indexes, with password",
			mnemonic: "vote water claim nice stick torch finger water wrestle absent pig agent can silly small client assume bonus body fabric solid limb bitter shift",
			indexes:  []uint32{0, 1, 2},
			password: "secret123",
			expected: []string{
				"18xYAe2jfuSzkrmDQsNjLnwTv6imrSBRD6",
				"17VLZdtuUeGU9dG8D1uEb4oV4dFtRnyhWK",
				"12LiTgiLrR4usWg7AXNYer1MfJupuHL32Z",
			},
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			for i, index := range tt.indexes {
				addr, err := btc.New(
					btc.WithMnemonic(tt.mnemonic),
					btc.WithPassword(tt.password),
					btc.WithAddrIndex(index),
				)
				if err != nil {
					t.Fatalf("unexpected error occurred on address generation: %v", err)
				}

				if expected, actual := tt.expected[i], addr.String(); expected != actual {
					t.Fatalf("expected address %s but got %s", expected, actual)
				}
			}
		})
	}
}

func TestEthereum(t *testing.T) {
	testTable := []struct {
		name     string
		mnemonic string
		indexes  []uint32
		expected []string
	}{
		{
			name:     "1st mnemonic, 5 different indexes",
			mnemonic: "chief jump smile magic bone essay jelly catch plug dumb collect soft pledge glove correct sniff coach miss cry illegal wisdom priority sound gloom",
			indexes:  []uint32{0, 1, 2, 3, 4},
			expected: []string{
				"0x46050696bb050937671ED06A16698De9E21eCe97",
				"0xAFEF212021d10fD979dfAb2D1572cbC6450354f2",
				"0x976a03c0f4fe5F02209fC22BfD075A4238aFD103",
				"0x6B5E99CB1422D2D21e2D488D464E5C38aDe7feA2",
				"0xA090E772605A0C66931C2960f0522E313BBbf028",
			},
		},
		{
			name:     "2nd mnemonic, 5 different indexes",
			mnemonic: "couple twice cake region mercy soup picnic garage steel minimum knife churn fee cup cool harsh soccer rubber scissors install turkey panda feel clown",
			indexes:  []uint32{0, 1, 2, 3, 4},
			expected: []string{
				"0x167De7E94FDcCf423530B2976381c926E26624A8",
				"0xc7b14364d6fFDB665996784FfBAAC81793E49463",
				"0xd28e0f8bD764aafDaDbf7E7C7C88efAD53e2c07a",
				"0x04BEb4EC4e4bDfEcD53E78599A2fDb143A62FaF7",
				"0x1Bf9E95a5260766282F48BE2a8049FE8899dB505",
			},
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			for i, index := range tt.indexes {
				addr, err := ethereum.New(
					ethereum.WithMnemonic(tt.mnemonic),
					ethereum.WithAddrIndex(index),
				)
				if err != nil {
					t.Fatalf("unexpected error occurred on address generation: %v", err)
				}

				if expected, actual := tt.expected[i], addr.String(); expected != actual {
					t.Fatalf("expected address %s but got %s", expected, actual)
				}
			}
		})
	}
}

func TestCardano(t *testing.T) {
	testTable := []struct {
		name     string
		mnemonic string
		indexes  []uint32
		expected []string
	}{
		{
			name:     "1st mnemonic, 3 different indexes",
			mnemonic: "garlic pumpkin leave lab learn because brief camera mandate retreat smoke often used garage permit flash birth tumble chimney between mammal achieve picnic cluster",
			indexes:  []uint32{0, 1, 2},
			expected: []string{
				"addr1qyw3fvegyda5whnley4e3wwvd5fly6gt6tnlsj40wz6mdzcyzghs64mlv4ygtlr3tnkwa7humlm795xlh3vcsw0vpg4s72jpzf",
				"addr1qyfphcl4nlf93rw6ygf0j2kga0tr65r3v2qqavhywujxn2gyzghs64mlv4ygtlr3tnkwa7humlm795xlh3vcsw0vpg4s07329f",
				"addr1q82l465c7d4lfx4c9drztrr6kzxqk3k25m9nw2t4fv3sddgyzghs64mlv4ygtlr3tnkwa7humlm795xlh3vcsw0vpg4sc0442f",
			},
		},
		{
			name:     "2nd mnemonic, 3 different indexes",
			mnemonic: "action aim boy belt obscure nice jump kitten check brother cover decrease calm sample gym rail live sustain quality remove help cook silver orbit",
			indexes:  []uint32{0, 1, 2},
			expected: []string{
				"addr1q979x2gyeyrh0gjtywv2cxznqh9d2l9sc5y3la3m0cxv8070uagqy6jp9az0fpd3ryklawslnjyan83ea0nsgxxn25jsw6a6vn",
				"addr1q8wc29r74yuaud543w0jcls0uykekxlrprkewd6fds4adq70uagqy6jp9az0fpd3ryklawslnjyan83ea0nsgxxn25jsces2e6",
				"addr1q9f0a4aws4v02zjv6wy5hhtd6e0jgwl556dkhurluy5uzy70uagqy6jp9az0fpd3ryklawslnjyan83ea0nsgxxn25js84ee99",
				"addr1qy5feywamh5n4h2zhp5d0wmzvpzvnn5dp368egfk9wt8v8w0uagqy6jp9az0fpd3ryklawslnjyan83ea0nsgxxn25js4hepc3",
				"addr1q8ds5kc2zfwc2ms7tdpcatm9ud572k660rda2j0dg3k3nhk0uagqy6jp9az0fpd3ryklawslnjyan83ea0nsgxxn25jsh3s039",
			},
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			for i, index := range tt.indexes {
				addr, err := cardano.New(
					cardano.WithMnemonic(tt.mnemonic),
					cardano.WithAddrIndex(index),
				)
				if err != nil {
					t.Fatalf("unexpected error occurred on address generation: %v", err)
				}

				if expected, actual := tt.expected[i], addr.String(); expected != actual {
					t.Fatalf("expected address %s but got %s", expected, actual)
				}
			}
		})
	}
}
