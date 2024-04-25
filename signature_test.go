package signature

import (
	"crypto/rand"
    "fmt"
    "testing"
    "encoding/hex"

    "github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/zkp/schnorr"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/accumulator"
    "source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/signatures/schnorr/mina"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
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
    fmt.Println(hex.EncodeToString(b))

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

func TestBls12381G1(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	sk, _ := new(accumulator.SecretKey).New(curve, []byte("1234567890"))
	pk, _ := sk.GetPublicKey(curve)
	skBytes, _ := sk.MarshalBinary()
	pkBytes, _ := pk.MarshalBinary()
	fmt.Println("Coinbase generates secret key and public key pair...")
	fmt.Printf("Coinbase publishes public key %v\n", hex.EncodeToString(pkBytes))
	fmt.Printf("Coinbase retains secret key %v\n", hex.EncodeToString(skBytes))
}

func TestZKPOverMultipleCurves(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
		curves.PALLAS(),
		curves.BLS12377G1(),
		curves.BLS12377G2(),
		curves.BLS12381G1(),
		curves.BLS12381G2(),
		curves.ED25519(),
		curves.BLS48581G1(),
	}
	for i, curve := range curveInstances {
		uniqueSessionId := sha3.New256().Sum([]byte("random seed"))
		prover := schnorr.NewProver(curve, nil, sha3.New256(), uniqueSessionId)

		secret := curve.Scalar.Random(rand.Reader)
		proof, err := prover.Prove(secret)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		err = schnorr.Verify(proof, curve, nil, sha3.New256(), uniqueSessionId)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}