package signature

import (
    "fmt"
    "testing"
    "encoding/hex"

    "github.com/stretchr/testify/require"
    "source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/signatures/schnorr/mina"
    "source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/pasta/fq"
)

// use pallas curve
func TestSecretKeySignTransaction(t *testing.T) {
    // See https://github.com/MinaProtocol/c-reference-signer/blob/master/reference_signer.c#L15
    pk, sk, err := mina.NewKeys()
	require.NoError(t, err)
	require.NotNil(t, sk)
	require.NotNil(t, pk)

    fmt.Println(pk.GenerateAddress())
    b, err := sk.MarshalBinary()
    require.NoError(t, err)
    fmt.Println(hex.EncodeToString(b[:]))

    require.Equal(t, pk, sk.GetPublicKey())

    sourcePk := pk
    receiverPk := new(mina.PublicKey)
	err = receiverPk.ParseAddress("B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy")
	require.NoError(t, err)

	txn := &mina.Transaction{
		Fee:        3,
		FeeToken:   1,
		Nonce:      200,
		ValidUntil: 10000,
		Memo:       "this is a memo",
		FeePayerPk: sourcePk,
		SourcePk:   sourcePk,
		ReceiverPk: receiverPk,
		TokenId:    1,
		Amount:     42,
		Locked:     false,
		Tag:        [3]bool{false, false, false},
		NetworkId:  mina.MainNet,
	}
    sig, err := sk.SignTransaction(txn)
	require.NoError(t, err)
	require.NoError(t, pk.VerifyTransaction(sig, txn))
}

func TestSecretKeySignMessage(t *testing.T) {
	// See https://github.com/MinaProtocol/c-reference-signer/blob/master/reference_signer.c#L15
	skValue := &fq.Fq{
		0xca14d6eed923f6e3, 0x61185a1b5e29e6b2, 0xe26d38de9c30753b, 0x3fdf0efb0a5714,
	}
	sk := &mina.SecretKey{}
    sk.SetFq(skValue)
	sig, err := sk.SignMessage("A test message.")
	require.NoError(t, err)
	pk := sk.GetPublicKey()
	require.NoError(t, pk.VerifyMessage(sig, "A test message."))
}