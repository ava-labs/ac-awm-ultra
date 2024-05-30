echo "Running AWM Ultra circuit test"
echo "--------------------------------------"
echo "Curve: BN254 | Proving scheme: Groth16 | Hash: Poseidon | AWM Default Curve: BLS12-381 pks over G1, signatures over G2"
echo "--------------------------------------"
go test -v -run ^TestRotate$ github.com/etrapay/awm-ultra 

