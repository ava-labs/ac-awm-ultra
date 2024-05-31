
# AWM Ultra (ZAWM)

ZAWM is a custom-built extension to Avalanche Warp Messaging (AWM) that leverages zk-SNARK proofs to enhance its capabilities. 

### Note:
ZAWM is initially designed to enable subnet<>any other blockchain communication via native AWM messages. This repository only includes the rotation circuit and a reproducible test for the ACP discussion. As a result, in-circuit BLS pairing verification (the most computationally intensive part) is removed from the rotation circuit, as Avalanche validators are already equipped with the BLS verifier due to the AWM. All other functions of the circuit remain unchanged.


## High-level Overview
ZAWM is initially designed to enable communication between subnets and any other blockchain via native AWM messages. The concept involves a relayer (or one of the validators from the source subnet) generating a succinct zk-proof of an AWM transaction and sending it to the destination chain outside the Avalanche network. A smart contract acting as a light client on the destination chain would then verify this proof (using BN254 for Ethereum) instead of performing the costly BLS12-381 pairing. This approach provides greater flexibility to subnets without requiring modifications to the existing AWM implementation, as only the relayers need to offer this service with custom incentives.

In short, ZAWM is designed to bring deterministic 'proof of sub-consensus' for subnets. The main bottleneck for this setup was how light client contracts on external chains could track the unpredictably updating validator sets of the subnets, which is crucial for trustless interoperability. For instance, in Ethereum, Sync Committee members are chosen randomly every ≈27 hours, with a group of 512 validators each time, and the current validators are responsible for confirming the new set, ensuring a reliable and predictable transition. In contrast, subnet validators can join and exit at completely random intervals, making it challenging to track and verify changes accurately. This scenario necessitated a different approach compared to existing consensus proofs.

To overcome this, ZAWM introduces a rotation proof circuit designed to efficiently handle dynamic changes in the validator set. Unlike the Sync Committee approach, where the previous validator set signs the commitment of the new validators, the rotation proof method has the current validators sign their own commitment (new set commitment) themselves. This process is initiated by a relayer who, upon receiving a cross-chain AWM message, detects a discrepancy in the validator commitment known by the destination chain. Consequently, the rotation proof generation is not a scheduled event; it is triggered by the cross-chain transaction itself and the detection of a change in the validator set on the source chain.

When the scenario described above occurs, the relayer generates the rotation proof. This proof (for detailed information, refer to the circuit) demonstrates that, despite changes in the validators, some validators from the old commitment (trusted by the destination) have signed off on the new set and that the total stake of these validators meets a specified threshold (which should be configured in the light client contract). Upon receiving the rotation proof, the light client contract performs a series of checks, including verifying that the old set commitment in the proof matches the one it already knows, confirming that the combined stake of these validators (those from the old set who are still present in the new set and are signers) is above the pre-set threshold, and validating the proof itself. If all these conditions are met, the destination subnet updates its commitment to the new commitment.

## Flow (Deprecated)

ZAWM includes two ZK circuits, transaction and rotate. Transaction circuit is used for proving the signatures for regular signed transactions against the existing validator set commitment. The rotate circuit is used for proving the change in the validator set. While the relayer (or validators) stores the proving key, the destination stores the verifying key of each circuit. Transaction proof generation is triggered by a cross-chain transaction from a user. Before generating the proof for the transaction, the relayer checks whether the validator set is still the same or not, and if it's changed, the relayer first generates the proof for rotation and then generates the transaction proof using the new set commitment.  

## Run Tests

### Prerequisites

You need the following dependencies for setup:

- [Go](https://golang.org/doc/install) >= 1.22.x 

Run from the root project directory:

```sh
./scripts/test.sh
```
It should automatically install other necessary dependencies and output the timings.

## Benchmarks

Below are the benchmark results for the rotation circuit with 10 validators, tested on a MacBook Pro with an M3 Pro CPU.

|         Operation         |        Time      | 
| :------------------------:| :--------------: | 
|    Compile                |      273.272ms   |     
|    Gen witness            |      214.958µs   | 
|    Prove                  |      180.603ms   |    
|    Verify                 |      1.577ms     |    
|    No. of constraints     |      43906       |   



## Disclaimer
Please refrain from using this project in a production environment, as it is currently considered in the alpha stage and has not undergone a formal audit. Use it at your own risk.

