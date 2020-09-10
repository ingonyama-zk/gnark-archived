/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rollup

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gurvy"
)

type circuitSignature struct {
	Circuit `gnark:",embed"`
}

// Circuit implements part of the rollup circuit only by delcaring a subset of the constraints
func (t *circuitSignature) Define(curveID gurvy.ID, cs *frontend.CS) error {
	if err := t.postInit(curveID, cs); err != nil {
		return err
	}
	hFunc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	return verifyTransferSignature(cs, t.Transfers[0], hFunc)
}

func TestCircuitSignature(t *testing.T) {
	const nbAccounts = 10

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(10)
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// verifies the signature of the transfer
	assert := groth16.NewAssert(t)

	var signatureCircuit circuitSignature
	r1cs, err := frontend.Compile(gurvy.BN256, &signatureCircuit)
	assert.NoError(err)

	assert.Solved(r1cs, &operator.witnesses, nil)

}

type circuitInclusionProof struct {
	Circuit `gnark:",embed"`
}

// Circuit implements part of the rollup circuit only by delcaring a subset of the constraints
func (t *circuitInclusionProof) Define(curveID gurvy.ID, cs *frontend.CS) error {
	if err := t.postInit(curveID, cs); err != nil {
		return err
	}
	hFunc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	merkle.VerifyProof(cs, hFunc, t.RootHashesBefore[0], t.MerkleProofsSenderBefore[0][:], t.MerkleProofHelperSenderBefore[0][:])
	merkle.VerifyProof(cs, hFunc, t.RootHashesBefore[0], t.MerkleProofsReceiverBefore[0][:], t.MerkleProofHelperReceiverBefore[0][:])

	merkle.VerifyProof(cs, hFunc, t.RootHashesAfter[0], t.MerkleProofsReceiverAfter[0][:], t.MerkleProofHelperReceiverAfter[0][:])
	merkle.VerifyProof(cs, hFunc, t.RootHashesAfter[0], t.MerkleProofsReceiverAfter[0][:], t.MerkleProofHelperReceiverAfter[0][:])

	return nil
}

func TestCircuitInclusionProof(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(16)
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// verifies the proofs of inclusion of the transfer
	assert := groth16.NewAssert(t)

	var inclusionProofCircuit circuitInclusionProof
	r1cs, err := frontend.Compile(gurvy.BN256, &inclusionProofCircuit)
	assert.NoError(err)

	assert.Solved(r1cs, &operator.witnesses, nil)

}

type circuitUpdateAccount struct {
	Circuit `gnark:",embed"`
}

// Circuit implements part of the rollup circuit only by delcaring a subset of the constraints
func (t *circuitUpdateAccount) Define(curveID gurvy.ID, cs *frontend.CS) error {
	if err := t.postInit(curveID, cs); err != nil {
		return err
	}
	verifyAccountUpdated(cs, t.SenderAccountsBefore[0], t.ReceiverAccountsBefore[0],
		t.SenderAccountsAfter[0], t.ReceiverAccountsAfter[0], t.Transfers[0].Amount)
	return nil
}

func TestCircuitUpdateAccount(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(10)
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert := groth16.NewAssert(t)

	var updateAccountCircuit circuitUpdateAccount
	r1cs, err := frontend.Compile(gurvy.BN256, &updateAccountCircuit)
	assert.NoError(err)

	assert.Solved(r1cs, &operator.witnesses, nil)

}

func TestCircuitFull(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(10)
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert := groth16.NewAssert(t)
	// verifies the proofs of inclusion of the transfer

	var rollupCircuit Circuit
	r1cs, err := frontend.Compile(gurvy.BN256, &rollupCircuit)
	assert.NoError(err)

	assert.Solved(r1cs, &operator.witnesses, nil)

}