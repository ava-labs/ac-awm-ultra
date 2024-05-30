package awmultra

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	bls12 "github.com/etrapay/awm-ultra/pairing_bls12381"
)

type BLS_bls12 struct {
	pr *bls12.Pairing
}

func NewBLS_bls12(api frontend.API) (*BLS_bls12, error) {
	pairing_bls12, err := bls12.NewPairing(api)
	if err != nil {
		return nil, fmt.Errorf("new pairing: %w", err)
	}
	return &BLS_bls12{
		pr: pairing_bls12,
	}, nil
}

// deprecated to do: remove

// func (bls BLS_bls12) AWMUltraWithPairing(pubKeys *[10]bls12.G1Affine, sig, hash *bls12.G2Affine, bitlist *[10]frontend.Variable, apk *bls12.G1Affine) {
// 	// canonical generator of the trace-zero r-torsion on BLS12-381
// 	_, _, g1, _ := bls12381.Generators()
// 	G1One := bls12.G1Affine{
// 		X: emulated.ValueOf[emulated.BLS12381Fp](g1.X),
// 		Y: emulated.ValueOf[emulated.BLS12381Fp](g1.Y),
// 	}
// 	g1n := g1.Neg(&g1)
// 	G1neg := bls12.G1Affine{
// 		X: emulated.ValueOf[emulated.BLS12381Fp](g1n.X),
// 		Y: emulated.ValueOf[emulated.BLS12381Fp](g1n.Y),
// 	}
// 	// trustedWeight_ := bls.pr.CalculateTrustedWeight(oldPublicKeys, newPublicKeys, bitlist, oldWeights)
// 	// bls.pr.Check(trustedWeight, trustedWeight_)

// 	// apkCommitment := bls.pr.ComputeAPKCommitment(oldPublicKeys, oldWeights)
// 	// bls.pr.Check(oldApkCommitment, apkCommitment)

// 	// newApkCommitment := bls.pr.ComputeAPKCommitment(newPublicKeys, newWeights)
// 	// bls.pr.Check(newCommitment, newApkCommitment)

// 	aggregated_pk := bls.pr.AggregatePublicKeys_Rotate(*pubKeys, *bitlist, G1One)

// 	bls.pr.CompareAggregatedPubKeys(*apk, aggregated_pk, G1One)

// 	// e(-G1, σ) * e(pubKey, H(m)) == 1
// 	bls.pr.PairingCheck([]*bls12.G1Affine{&G1neg, &aggregated_pk}, []*bls12.G2Affine{sig, hash})
// }

func (bls BLS_bls12) AWMUltra(pubKeys *[10]bls12.G1Affine, bitlist *[10]frontend.Variable, apk *bls12.G1Affine, oldPubKeys *[10]bls12.G1Affine, oldWeights *[10]frontend.Variable,
	trustedWeight *frontend.Variable, oldBitlist *[10]frontend.Variable, intersectionBitlist *[10]frontend.Variable, newWeights *[10]frontend.Variable, oldApkCommitment, newCommitment *frontend.Variable) {

	_, _, g1, _ := bls12381.Generators()
	G1One := bls12.G1Affine{
		X: emulated.ValueOf[emulated.BLS12381Fp](g1.X),
		Y: emulated.ValueOf[emulated.BLS12381Fp](g1.Y),
	}

	trustedWeight_ := bls.pr.CalculateTrustedWeight(*oldPubKeys, *pubKeys, *bitlist, *oldWeights, *oldBitlist, *intersectionBitlist)
	// trustedWeight_ = trustedWeight_
	bls.pr.Check(*trustedWeight, trustedWeight_)

	apkCommitment := bls.pr.ComputeAPKCommitment(*oldPubKeys, *oldWeights)
	bls.pr.Check(*oldApkCommitment, apkCommitment)

	newApkCommitment := bls.pr.ComputeAPKCommitment(*pubKeys, *newWeights)
	bls.pr.Check(*newCommitment, newApkCommitment)

	aggregated_pk := bls.pr.AggregatePublicKeys_Rotate(*pubKeys, *bitlist, G1One)
	bls.pr.CompareAggregatedPubKeys(*apk, aggregated_pk, G1One)

}
