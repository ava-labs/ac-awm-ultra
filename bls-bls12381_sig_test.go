package awmultra

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"

	// mimc "github.com/consensys/gnark/std/hash/mimc"
	pp "github.com/iden3/go-iden3-crypto/poseidon"

	"github.com/consensys/gnark/test"
	bls12 "github.com/etrapay/awm-ultra/pairing_bls12381"
)

const DOMAIN_SEPERATOR = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

func PoseidonHash(inputs []*big.Int) *big.Int {
	out, err := pp.Hash(inputs)
	if err != nil {
		panic(err)
	}
	return out
}

// ----
// type AWMUltraWithPairing struct {
// 	PK  [10]bls12.G1Affine
// 	Sig bls12.G2Affine
// 	HM  bls12.G2Affine
// 	BL  [10]frontend.Variable
// 	APK bls12.G1Affine
// }

// func (c *AWMUltraWithPairing) Define(api frontend.API) error {
// 	bls, err := NewBLS_bls12(api)
// 	if err != nil {
// 		return fmt.Errorf("new pairing: %w", err)

// 	}

// 	bls.AWMUltraWithPairing(&c.PK, &c.Sig, &c.HM, &c.BL, &c.APK)
// 	return nil

// }

type AWMUltra struct {
	PK                  [10]bls12.G1Affine
	BL                  [10]frontend.Variable
	APK                 bls12.G1Affine
	OldPubKeys          [10]bls12.G1Affine
	OldWeights          [10]frontend.Variable
	TrustedWeight       frontend.Variable
	OldBitlist          [10]frontend.Variable
	IntersectionBitlist [10]frontend.Variable
	NewWeights          [10]frontend.Variable
	OldApkCommitment    frontend.Variable
	NewApkCommitment    frontend.Variable
}

func (c *AWMUltra) Define(api frontend.API) error {
	bls, err := NewBLS_bls12(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)

	}

	bls.AWMUltra(&c.PK, &c.BL, &c.APK, &c.OldPubKeys, &c.OldWeights, &c.TrustedWeight, &c.OldBitlist, &c.IntersectionBitlist, &c.NewWeights, &c.OldApkCommitment, &c.NewApkCommitment)
	return nil

}

func genPriv() *big.Int {
	// for {
	secret, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(250), nil))
	if err != nil {
		panic(err)
	}
	return secret
}

func toG1AffineArray(array []bls12381.G1Affine) *[]bls12.G1Affine {

	var res []bls12.G1Affine
	for i := 0; i < len(array); i++ {
		res = append(res, bls12.NewG1Affine(array[i]))
	}
	return &res
}

func aggregatePubKeys(pubKeys []bls12381.G1Affine, bitlist []uint8) bls12381.G1Affine {
	var res bls12381.G1Affine

	var one big.Int
	one.SetUint64(1)
	res.ScalarMultiplicationBase(big.NewInt(0))
	// fmt.Print("res: ", res)
	for i := 0; i < len(bitlist); i++ {
		if bitlist[i] == 1 {
			res.Add(&res, &pubKeys[i])
		}
	}
	return res
}

func genValidators(size int) (*[]big.Int, *[]bls12381.G1Affine) {
	var secrets []big.Int
	var pubKeys []bls12381.G1Affine
	for i := 0; i < size; i++ {
		secret := genPriv()
		secrets = append(secrets, *secret)
		var PK bls12381.G1Affine
		PK.ScalarMultiplicationBase(secret)
		pubKeys = append(pubKeys, PK)
	}
	return &secrets, &pubKeys
}

func genRandomBinaryArray(size int) []uint8 {
	for {
		var res []uint8
		hasNonZero := false
		for i := 0; i < size; i++ {
			r := genPriv()
			r.Mod(r, big.NewInt(2))
			bit := uint8(r.Uint64())
			if bit == 1 {
				hasNonZero = true
			}
			res = append(res, bit)
		}
		if hasNonZero {
			return res
		}
	}
}

func validatorSignatures(secrets *[]big.Int, HM *bls12381.G2Affine, binarray *[]uint8) (*[]bls12381.G2Affine, *bls12381.G2Affine) {

	var sigs []bls12381.G2Affine
	var aggregatedSig bls12381.G2Affine
	aggregatedSig.ScalarMultiplication(HM, big.NewInt(0))
	for i := 0; i < len(*binarray); i++ {

		if (*binarray)[i] == 1 {

			var sig bls12381.G2Affine
			sig.ScalarMultiplication(HM, &(*secrets)[i])
			sigs = append(sigs, sig)
			aggregatedSig.Add(&aggregatedSig, &sig)
		}
	}
	return &sigs, &aggregatedSig

}

func uint8ToVariableArray(array []uint8) []frontend.Variable {
	var res []frontend.Variable
	for i := 0; i < len(array); i++ {
		res = append(res, frontend.Variable(array[i]))
	}
	return res
}

func bigIntToVariableArray(array []*big.Int) []frontend.Variable {
	var res []frontend.Variable
	for i := 0; i < len(array); i++ {
		res = append(res, frontend.Variable(array[i]))
	}
	return res
}

func genWeights(size int) []*big.Int {
	var weights []*big.Int
	for i := 0; i < size; i++ {
		randomWeight, _ := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(10), nil))
		weights = append(weights, randomWeight)
	}
	return weights
}

func calculateCommitment(pubKeys []bls12381.G1Affine, weights []*big.Int) *big.Int {
	fmt.Println("len(pubKeys): ", len(pubKeys))
	fmt.Println("len(weights): ", len(weights))
	c := make([]*big.Int, 10)
	LIMBS_LENGTH := 6
	for i := 0; i < 10; i++ {
		pp := bls12.NewG1Affine(pubKeys[i])
		if len(pp.X.Limbs) != LIMBS_LENGTH {
			panic("Wrong limbs length")
		}

		arrX := make([]*big.Int, LIMBS_LENGTH)
		arrY := make([]*big.Int, LIMBS_LENGTH)

		for j := 0; j < LIMBS_LENGTH; j++ {
			arrX[j] = pp.X.Limbs[j].(*big.Int)
			arrY[j] = pp.Y.Limbs[j].(*big.Int)
		}

		cmX := PoseidonHash(arrX)
		cmY := PoseidonHash(arrY)
		c[i] = PoseidonHash([]*big.Int{cmX, cmY, weights[i]})
	}

	return PoseidonHash(c)
}

func TestRotate(t *testing.T) {
	assert := test.NewAssert(t)

	size := 10 // number of validators

	// generate number of validators that will be from the old set
	intersectionSize, err := rand.Int(rand.Reader, big.NewInt(8))
	fmt.Println("Intersection Size: ", intersectionSize)
	if err != nil {
		panic(err)
	}

	if intersectionSize.Uint64() == 0 {
		intersectionSize.SetUint64(1) // to avoid zero intersection
	}

	// generate the old set of validators with the intersection size
	oldSecrets, oldPubKeys := genValidators(int(intersectionSize.Uint64()))

	// generate the old weights
	oldWeights := genWeights(int(intersectionSize.Uint64()))
	fmt.Println("Old weights: ", oldWeights)
	// generate the trusted weight (sum of the old weights, since the old set is trusted)
	trustedWeight := big.NewInt(0)
	for i := 0; i < len(oldWeights); i++ {
		trustedWeight.Add(trustedWeight, oldWeights[i])
	}
	// calculateCommitment(*oldPubKeys, oldWeights)

	newSize := size - int(intersectionSize.Uint64())
	newSecrets, newPubKeys := genValidators(newSize)

	// combine the old and new sets
	secrets := append(*oldSecrets, *newSecrets...)
	pubKeys := append(*oldPubKeys, *newPubKeys...)

	HM, err := bls12381.HashToG2([]byte("Let there be zk!"), []byte(DOMAIN_SEPERATOR))
	if err != nil {
		panic(err)
	}

	binarray := genRandomBinaryArray(size)
	// ensure that the first intersectionSize number of validators have the same bit in the binary array
	for i := 0; i < int(intersectionSize.Uint64()); i++ {
		binarray[i] = 1
	}

	fmt.Println("Binary Array: ", binarray)
	_, aggregatedSig := validatorSignatures(&secrets, &HM, &binarray) // _ is the individual signatures, not needed here

	apk := aggregatePubKeys(pubKeys, binarray)

	// check pairing
	_, _, g1, _ := bls12381.Generators()
	g1neg := g1.Neg(&g1)

	verify, err := bls12381.PairingCheck([]bls12381.G1Affine{*g1neg, apk}, []bls12381.G2Affine{*aggregatedSig, HM})
	if err != nil {
		panic(err)
	}
	fmt.Println("Off-circuit Pairing Verified: ", verify)

	// generate the

	// convert binary array to frontend.Variable array
	bitlist := uint8ToVariableArray(binarray)

	var temp [10]frontend.Variable // to fix the size of the array [size]
	copy(temp[:], bitlist)
	bitlist_parsed := temp

	var PKS_bls12 = toG1AffineArray(pubKeys)

	var temp2 [10]bls12.G1Affine // to fix the size of the array [size]
	copy(temp2[:], *PKS_bls12)
	PKS_bls12_parsed := &temp2

	// generate size - intersectionSize number of random weights and validators for the old set and combine them with the old set
	missingSize := size - int(intersectionSize.Uint64())
	_, missingPubKeys := genValidators(missingSize)
	oldFullPubKeys := append(*oldPubKeys, *missingPubKeys...)

	missingWeights := genWeights(missingSize)
	oldFullWeights := append(oldWeights, missingWeights...)

	oldWeightsArray := bigIntToVariableArray(oldFullWeights)
	oldPubKeysArray := toG1AffineArray(oldFullPubKeys)

	newWeights := genWeights(size)
	for i := 0; i < int(intersectionSize.Uint64()); i++ {
		newWeights[i] = oldWeights[i]
	}

	newWeights_ := bigIntToVariableArray(newWeights)

	oldBitlist := make([]uint8, size)
	// ensure that the first intersectionSize number of validators have the same bit in the binary array, and rest are zeros
	for i := 0; i < int(intersectionSize.Uint64()); i++ {
		oldBitlist[i] = 1

	}

	oldBinarray := uint8ToVariableArray(oldBitlist)

	intersectionBitlist := make([]uint8, size)
	for i := 0; i < int(intersectionSize.Uint64()); i++ {
		intersectionBitlist[i] = 1
	}
	intersectionBitlist_parsed := uint8ToVariableArray(intersectionBitlist)

	// compute the old and new commitee (apk) commitments by hashing (Poseidon) the old and new pubkeys with their respective weights

	oldApkCommitment := calculateCommitment(oldFullPubKeys, oldFullWeights)
	newApkCommitment := calculateCommitment(pubKeys, newWeights)

	// convert the old and new commitee commitments to frontend.Variable
	oldApkCommitment_ := frontend.Variable(oldApkCommitment)
	newApkCommitment_ := frontend.Variable(newApkCommitment)
	var temp3 [10]frontend.Variable // to fix the size of the array [size]
	copy(temp3[:], oldWeightsArray)
	oldWeights_parsed := temp3

	fmt.Println("Old weights: ", oldWeights_parsed)
	fmt.Println("trustedWeight: ", trustedWeight)

	var temp4 [10]bls12.G1Affine // to fix the size of the array [size]
	copy(temp4[:], *oldPubKeysArray)
	oldPubKeysArraySlice := temp4[:]

	var temp5 [10]frontend.Variable // to fix the size of the array [size]
	copy(temp5[:], oldBinarray)
	oldBitlist_parsed := temp5

	var temp6 [10]frontend.Variable // to fix the size of the array [size]
	copy(temp6[:], intersectionBitlist_parsed)
	intersectionBinlist := temp6

	var temp7 [10]frontend.Variable // to fix the size of the array [size]
	copy(temp7[:], newWeights_)
	newWeightsArray := temp7

	var APK_bls12 = bls12.NewG1Affine(apk)

	assignment := &AWMUltra{
		PK:                  *PKS_bls12_parsed,
		BL:                  bitlist_parsed,
		APK:                 APK_bls12,
		OldPubKeys:          *(*[10]bls12.G1Affine)(oldPubKeysArraySlice),
		OldWeights:          oldWeights_parsed,
		TrustedWeight:       frontend.Variable(trustedWeight),
		OldBitlist:          oldBitlist_parsed,
		IntersectionBitlist: intersectionBinlist,
		NewWeights:          newWeightsArray,
		OldApkCommitment:    oldApkCommitment_,
		NewApkCommitment:    newApkCommitment_,
	}

	// --------------------------------------------------------------------------------------------
	err = test.IsSolved(&AWMUltra{}, assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("Error:", err)
	}
	fmt.Println("Rotate Circuit Proving Tests started")
	assert.ProverSucceeded(&AWMUltra{}, assignment, test.WithCurves(ecc.BN254))
	fmt.Println("Starting R1CS generation...")
	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &AWMUltra{})
	if err != nil {
		panic(err)
	}
	fmt.Println("R1CS generated. Took: ", time.Since(start))
	var bufCS bytes.Buffer
	cs.WriteTo(&bufCS)

	// Open the output file for writing
	file, err := os.Create("rotate2.r1cs")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	// Write the buffer contents to the file
	_, err = file.Write(bufCS.Bytes())
	if err != nil {
		fmt.Println("Error:", err)
	}
	fmt.Println("R1CS saved to rotate2.r1cs file.")

	fmt.Println("Starting setup phase...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}
	// save the proving and verifying keys to disk
	var bufPK bytes.Buffer
	pk.WriteTo(&bufPK)

	// Open the output file for writing
	file, err = os.Create("rotate2.pk")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	// Write the buffer contents to the file
	_, err = io.Copy(file, &bufPK)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Proving key saved to rotate2.pk file.")

	// save the proving and verifying keys to disk
	var bufVK bytes.Buffer
	vk.WriteTo(&bufVK)

	// Open the output file for writing
	file, err = os.Create("rotate2.vk")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	// Write the buffer contents to the file
	_, err = io.Copy(file, &bufVK)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Verifying key saved to rotate2.vk file.")

	// --------------------------------------------------------------------------------------------
	// to read pk vk and r1cs from disk, uncomment after this line

	// fmt.Println("Reading R1CS (rotate2.r1cs) file from the disk.")
	// cs := groth16.NewCS(ecc.BN254)
	// // Read the R1CS
	// r1csFile, err := ioutil.ReadFile("rotate2.r1cs")
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }

	// r1csBuff := bytes.NewBuffer(r1csFile)
	// cs.ReadFrom(r1csBuff)
	// pk := groth16.NewProvingKey(ecc.BN254)

	// // Read the verifying key
	// fmt.Println("Reading the proving key (rotate2.pk) file from the disk.")
	// pkFile, err := os.ReadFile("rotate2.pk")
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }

	// pkBuff := bytes.NewBuffer(pkFile)
	// pk.ReadFrom(pkBuff)

	// vk := groth16.NewVerifyingKey(ecc.BN254)

	// // Read the verifying key
	// fmt.Println("Reading the verifying key (rotate.vk) file from the disk.")
	// vkFile, err := os.ReadFile("rotate2.vk")
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }

	// vkBuff := bytes.NewBuffer(vkFile)
	// vk.ReadFrom(vkBuff)

	// --------------------------------------------------------------------------------------------

	fmt.Println("Starting witness generation...")
	start = time.Now()
	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	fmt.Println("Witness generated. Took: ", time.Since(start))
	fmt.Println()
	fmt.Println("Starting proving phase...")

	start = time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		// dont panic continue to next test
		fmt.Println("Error:", err)
	}
	fmt.Println("Proof generated. Took: ", time.Since(start))

	publicWitness, _ := witness.Public()

	fmt.Println("Starting verifying phase...")
	start = time.Now()
	result := groth16.Verify(proof, vk, publicWitness)
	fmt.Println("Verification completed. Result: ", result, " Took: ", time.Since(start))
	fmt.Println("Rotate Circuit test passed")
	assert.NoError(err)
}

// bench
func BenchmarkAWMUltraRotate(b *testing.B) {
	var c AWMUltra
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("⏱️  BLS signature verifier on BLS12-381 in a BN254 R1CS circuit (v1): ", p.NbConstraints())
}
