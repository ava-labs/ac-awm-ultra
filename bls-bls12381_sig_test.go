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
	"github.com/consensys/gnark/test"
	bls12 "github.com/etrapay/awm-ultra/pairing_bls12381"
)

const DOMAIN_SEPERATOR = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

// ----
type AWMUltraWithPairing struct {
	PK  [3]bls12.G1Affine
	Sig bls12.G2Affine
	HM  bls12.G2Affine
	BL  [3]frontend.Variable
	APK bls12.G1Affine
}

func (c *AWMUltraWithPairing) Define(api frontend.API) error {
	bls, err := NewBLS_bls12(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)

	}

	bls.AWMUltraWithPairing(&c.PK, &c.Sig, &c.HM, &c.BL, &c.APK)
	return nil

}

type AWMUltra struct {
	PK  [3]bls12.G1Affine
	BL  [3]frontend.Variable
	APK bls12.G1Affine
}

func (c *AWMUltra) Define(api frontend.API) error {
	bls, err := NewBLS_bls12(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)

	}

	bls.AWMUltra(&c.PK, &c.BL, &c.APK)
	return nil

}

func genPriv() *big.Int {
	// for {
	secret, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(250), nil))
	if err != nil {
		panic(err)
	}
	return secret

	// blsorder := new(big.Int)
	// blsorder.SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	// var inv big.Int
	// if inv.ModInverse(secret, blsorder) != nil {
	// 	fmt.Println("inv.ModInverse(secret, blsorder): ", inv.ModInverse(secret, blsorder))
	// 	return secret
	// }
	// If no modular inverse, continue the loop to generate a new secret
	// }

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
			fmt.Println("Random bit: ", bit)
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

func TestRotateWithPairing(t *testing.T) {
	assert := test.NewAssert(t)

	size := 3 // number of validators

	secrets, pubKeys := genValidators(size)
	HM, err := bls12381.HashToG2([]byte("Hello, World!"), []byte("test"))
	if err != nil {
		panic(err)
	}

	binarray := genRandomBinaryArray(size)
	_, aggregatedSig := validatorSignatures(secrets, &HM, &binarray) // _ is the individual signatures, not needed here

	apk := aggregatePubKeys(*pubKeys, binarray)

	// check pairing
	_, _, g1, _ := bls12381.Generators()
	g1neg := g1.Neg(&g1)

	verify, err := bls12381.PairingCheck([]bls12381.G1Affine{*g1neg, apk}, []bls12381.G2Affine{*aggregatedSig, HM})
	if err != nil {
		panic(err)
	}
	fmt.Println("Off-circuit Pairing Verified: ", verify)

	// circuit test

	// convert binary array to frontend.Variable array
	bitlist := uint8ToVariableArray(binarray)

	var temp [3]frontend.Variable // to fix the size of the array [size]
	copy(temp[:], bitlist)
	bitlist_parsed := temp

	var PKS_bls12 = toG1AffineArray(*pubKeys)

	var temp2 [3]bls12.G1Affine // to fix the size of the array [size]
	copy(temp2[:], *PKS_bls12)
	PKS_bls12_parsed := &temp2

	var Sig_bls12 = bls12.NewG2Affine(*aggregatedSig)

	var APK_bls12 = bls12.NewG1Affine(apk)

	assignment := &AWMUltraWithPairing{
		PK:  *PKS_bls12_parsed,
		Sig: Sig_bls12,
		HM:  bls12.NewG2Affine(HM),
		BL:  bitlist_parsed,
		APK: APK_bls12,
	}

	err = test.IsSolved(&AWMUltraWithPairing{}, assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("Error:", err)
	}
	fmt.Println("Rotate Circuit Proving Tests started")
	// assert.ProverSucceeded(&AWMUltraWithPairing{}, assignment, test.WithCurves(ecc.BN254))
	fmt.Println("Starting R1CS generation...")
	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &AWMUltraWithPairing{})
	if err != nil {
		panic(err)
	}
	fmt.Println("R1CS generated. Took: ", time.Since(start))
	var bufCS bytes.Buffer
	cs.WriteTo(&bufCS)

	// Open the output file for writing
	file, err := os.Create("rotate.r1cs")
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
	fmt.Println("R1CS saved to rotate.r1cs file.")

	// fmt.Println("Reading R1CS (rotate.r1cs) file from the disk.")
	// cs := groth16.NewCS(ecc.BN254)
	// // Read the R1CS
	// r1csFile, err := ioutil.ReadFile("rotate.r1cs")
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }

	// r1csBuff := bytes.NewBuffer(r1csFile)
	// cs.ReadFrom(r1csBuff)

	fmt.Println("Starting setup phase...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}
	// save the proving and verifying keys to disk
	var bufPK bytes.Buffer
	pk.WriteTo(&bufPK)

	// Open the output file for writing
	file, err = os.Create("rotate.pk")
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
	fmt.Println("Proving key saved to rotate.pk file.")

	// save the proving and verifying keys to disk
	var bufVK bytes.Buffer
	vk.WriteTo(&bufVK)

	// Open the output file for writing
	file, err = os.Create("rotate.vk")
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
	fmt.Println("Verifying key saved to rotate.vk file.")

	// to read, uncomment after this line
	// pk := groth16.NewProvingKey(ecc.BN254)

	// // Read the verifying key
	// fmt.Println("Reading the proving key (rotate.pk) file from the disk.")
	// pkFile, err := os.ReadFile("rotate.pk")
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }

	// pkBuff := bytes.NewBuffer(pkFile)
	// pk.ReadFrom(pkBuff)

	// vk := groth16.NewVerifyingKey(ecc.BN254)

	// // Read the verifying key
	// fmt.Println("Reading the verifying key (rotate.vk) file from the disk.")
	// vkFile, err := os.ReadFile("rotate.vk")
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }

	// vkBuff := bytes.NewBuffer(vkFile)
	// vk.ReadFrom(vkBuff)

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

func TestRotate(t *testing.T) {
	assert := test.NewAssert(t)

	size := 3 // number of validators

	secrets, pubKeys := genValidators(size)
	HM, err := bls12381.HashToG2([]byte("Let there be zk!"), []byte(DOMAIN_SEPERATOR))
	if err != nil {
		panic(err)
	}

	binarray := genRandomBinaryArray(size)
	fmt.Println("Binary Array: ", binarray)
	_, aggregatedSig := validatorSignatures(secrets, &HM, &binarray) // _ is the individual signatures, not needed here

	apk := aggregatePubKeys(*pubKeys, binarray)

	// check pairing
	_, _, g1, _ := bls12381.Generators()
	g1neg := g1.Neg(&g1)

	verify, err := bls12381.PairingCheck([]bls12381.G1Affine{*g1neg, apk}, []bls12381.G2Affine{*aggregatedSig, HM})
	if err != nil {
		panic(err)
	}
	fmt.Println("Off-circuit Pairing Verified: ", verify)

	// circuit test

	// convert binary array to frontend.Variable array
	bitlist := uint8ToVariableArray(binarray)

	var temp [3]frontend.Variable // to fix the size of the array [size]
	copy(temp[:], bitlist)
	bitlist_parsed := temp

	var PKS_bls12 = toG1AffineArray(*pubKeys)

	var temp2 [3]bls12.G1Affine // to fix the size of the array [size]
	copy(temp2[:], *PKS_bls12)
	PKS_bls12_parsed := &temp2

	var APK_bls12 = bls12.NewG1Affine(apk)

	assignment := &AWMUltra{
		PK:  *PKS_bls12_parsed,
		BL:  bitlist_parsed,
		APK: APK_bls12,
	}
	err = test.IsSolved(&AWMUltra{}, assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("Error:", err)
	}
	fmt.Println("Rotate Circuit Proving Tests started")
	// assert.ProverSucceeded(&AWMUltraWithPairing{}, assignment, test.WithCurves(ecc.BN254))
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

	// fmt.Println("Reading R1CS (rotate2.r1cs) file from the disk.")
	// cs := groth16.NewCS(ecc.BN254)
	// // Read the R1CS
	// r1csFile, err := ioutil.ReadFile("rotate2.r1cs")
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }

	// r1csBuff := bytes.NewBuffer(r1csFile)
	// cs.ReadFrom(r1csBuff)

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

	// to read, uncomment after this line
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
func BenchmarkBLS2Verify_v1(b *testing.B) {
	var c AWMUltraWithPairing
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("⏱️  BLS signature verifier on BLS12-381 in a BN254 R1CS circuit (v1): ", p.NbConstraints())
}
