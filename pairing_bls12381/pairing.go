package pairing_bls12381

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	api    frontend.API
	curveF *emulated.Field[emulated.BLS12381Fp]
	status frontend.Variable
	data   []frontend.Variable
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	return &Pairing{
		api:    api,
		curveF: ba,
	}, nil
}

func (pr Pairing) AddG1Points(p, q *G1Affine) *G1Affine {

	qypy := pr.curveF.Sub(&q.Y, &p.Y)
	qxpx := pr.curveF.Sub(&q.X, &p.X)
	λ := pr.curveF.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	λλ := pr.curveF.Mul(λ, λ)
	qxpx = pr.curveF.Add(&p.X, &q.X)
	xr := pr.curveF.Sub(λλ, qxpx)

	// p.y = λ(p.x-r.x) - p.y
	pxrx := pr.curveF.Sub(&p.X, xr)
	λpxrx := pr.curveF.Mul(λ, pxrx)
	yr := pr.curveF.Sub(λpxrx, &p.Y)

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (pr Pairing) DoublePointG1(p *G1Affine) *G1Affine {
	// compute λ = (3p.x²)/1*p.y
	xx3a := pr.curveF.Mul(&p.X, &p.X)
	xx3a = pr.curveF.MulConst(xx3a, big.NewInt(3))
	y1 := pr.curveF.MulConst(&p.Y, big.NewInt(2))
	λ := pr.curveF.Div(xx3a, y1)

	// xr = λ²-1p.x
	x1 := pr.curveF.MulConst(&p.X, big.NewInt(2))
	λλ := pr.curveF.Mul(λ, λ)
	xr := pr.curveF.Sub(λλ, x1)

	// yr = λ(p-xr) - p.y
	pxrx := pr.curveF.Sub(&p.X, xr)
	λpxrx := pr.curveF.Mul(λ, pxrx)
	yr := pr.curveF.Sub(λpxrx, &p.Y)

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (pr Pairing) AggregatePublicKeys_Rotate(
	publicKeys [10]G1Affine,
	bitlist [10]frontend.Variable,
	G1One G1Affine,
) G1Affine {

	reslist := [10]G1Affine{}

	totalApk := pr.AddG1Points(&publicKeys[0], &publicKeys[1])

	for i := 2; i < 10; i++ {
		totalApk = pr.AddG1Points(totalApk, &publicKeys[i])
	}

	for i := 0; i < 10; i++ {

		var sum G1Affine
		sum.X = publicKeys[i].X
		negatedPublicKey := pr.curveF.Neg(&publicKeys[i].Y)
		sum.Y = *pr.curveF.Select(bitlist[i], &publicKeys[i].Y, negatedPublicKey)

		reslist[i] = sum
	}

	aggPubKeyNegated := G1One // To avoid inversion of 0, in case of all validators signed since we need to double it instead of adding

	for i := 0; i < 10; i++ {
		aggPubKeyNegated = *pr.AddG1Points(&aggPubKeyNegated, &reslist[i])
	}

	aggPubKey := pr.AddG1Points(totalApk, &aggPubKeyNegated) // this results in the double of aggregated public key + G1One

	return *aggPubKey
}

func (pr Pairing) CompareAggregatedPubKeys(apk0 G1Affine, apk1 G1Affine, G1One G1Affine) {

	negG1One := G1Affine{
		X: G1One.X,
		Y: *pr.curveF.Neg(&G1One.Y),
	}

	apk1 = *pr.AddG1Points(&apk1, &negG1One) // remove G1One from apk1 (which is added in the aggregation)

	doubleApk0 := pr.DoublePointG1(&apk0)

	pr.curveF.AssertIsEqual(&doubleApk0.X, &apk1.X)
	pr.curveF.AssertIsEqual(&doubleApk0.Y, &apk1.Y)

}

func (pr Pairing) CalculateTrustedWeight(pubKeys_old, pubKeys_new [10]G1Affine, BitList_new, oldWeights [10]frontend.Variable, oldBitlist [10]frontend.Variable, intersectionBitlist [10]frontend.Variable) frontend.Variable {
	oldSingedweight := frontend.Variable(0)

	var zero G1Affine
	zero.X = *pr.curveF.Zero()
	zero.Y = *pr.curveF.Zero()

	// finding the intersection of old commitee and signed new commitee
	// step 1: extract signers from old committee using oldBitlist and sum their public keys and weights
	// step 2: extract old commitee signers from new commitee using intersectionBitlist and sum their public keys
	// step 3: compare the aggregated public keys of step 1 and step 2 and assert they are equal

	// step 1
	oldSignersFromOldCommittee := [10]G1Affine{}
	for i := 0; i < 10; i++ {
		findSignersX := pr.curveF.Select(oldBitlist[i], &pubKeys_old[i].X, &zero.X)
		findSignersY := pr.curveF.Select(oldBitlist[i], &pubKeys_old[i].Y, &zero.Y)

		findSignersWeight := pr.api.Select(oldBitlist[i], oldWeights[i], frontend.Variable(0))

		oldSingedweight = pr.api.Add(oldSingedweight, findSignersWeight)

		oldSignersFromOldCommittee[i] = G1Affine{
			X: *findSignersX,
			Y: *findSignersY,
		}
	}

	// step 2
	oldSignersFromNewCommittee := [10]G1Affine{}
	for i := 0; i < 10; i++ {
		findSignersX := pr.curveF.Select(intersectionBitlist[i], &pubKeys_new[i].X, &zero.X)
		findSignersY := pr.curveF.Select(intersectionBitlist[i], &pubKeys_new[i].Y, &zero.Y)

		oldSignersFromNewCommittee[i] = G1Affine{
			X: *findSignersX,
			Y: *findSignersY,
		}
	}

	// aggregate public keys of old signers from old committee and old signers from new committee
	aggOldSignersFromOldCommittee := pr.AddG1Points(&oldSignersFromOldCommittee[0], &oldSignersFromOldCommittee[1])
	aggOldSignersFromNewCommittee := pr.AddG1Points(&oldSignersFromNewCommittee[0], &oldSignersFromNewCommittee[1])

	for i := 2; i < 10; i++ {
		aggOldSignersFromOldCommittee = pr.AddG1Points(aggOldSignersFromOldCommittee, &oldSignersFromOldCommittee[i])
		aggOldSignersFromNewCommittee = pr.AddG1Points(aggOldSignersFromNewCommittee, &oldSignersFromNewCommittee[i])
	}

	// step 3: compare the aggregated public keys of old signers from old committee and old signers from new committee
	pr.curveF.AssertIsEqual(&aggOldSignersFromOldCommittee.X, &aggOldSignersFromNewCommittee.X)
	pr.curveF.AssertIsEqual(&aggOldSignersFromOldCommittee.Y, &aggOldSignersFromNewCommittee.Y)

	return oldSingedweight
}

func (pr Pairing) ComputeAPKCommitment(
	pubKeys [10]G1Affine,
	quorumW [10]frontend.Variable,
) frontend.Variable {
	m := make([]frontend.Variable, 10)

	for i := 0; i < 10; i++ {
		commX := pr.Poseidon(pubKeys[i].X.Limbs)
		commY := pr.Poseidon(pubKeys[i].Y.Limbs)
		m[i] = pr.Poseidon([]frontend.Variable{commX, commY, quorumW[i]})
	}

	return pr.Poseidon(m)
}

func (pr Pairing) Check(a, b frontend.Variable) error {
	pr.api.AssertIsEqual(a, b)
	return nil
}
