package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	bn254plonk "github.com/consensys/gnark/backend/plonk/bn254"
	contract "github.com/consensys/gnark/backend/plonk/bn254/solidity/gopkg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
)

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func createSimulatedBackend(privateKey *ecdsa.PrivateKey) (*backends.SimulatedBackend, *bind.TransactOpts, error) {

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
	if err != nil {
		return nil, nil, err
	}

	balance := new(big.Int)
	balance.SetString("10000000000000000000", 10) // 10 eth in wei

	address := auth.From
	genesisAlloc := map[common.Address]core.GenesisAccount{
		address: {
			Balance: balance,
		},
	}

	// create simulated backend & deploy the contract
	blockGasLimit := uint64(14712388)
	client := backends.NewSimulatedBackend(genesisAlloc, blockGasLimit)

	return client, auth, nil

}

func getTransactionOpts(privateKey *ecdsa.PrivateKey, auth *bind.TransactOpts, client *backends.SimulatedBackend) (*bind.TransactOpts, error) {

	fromAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, err
	}

	gasprice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)
	auth.GasLimit = uint64(1000000) // -> + add the require for the pairing... +20k
	auth.GasPrice = gasprice

	return auth, nil

}

type commitmentCircuit struct {
	Public [3]frontend.Variable `gnark:",public"`
	X      [3]frontend.Variable
}

func (c *commitmentCircuit) Define(api frontend.API) error {

	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("type %T doesn't impl the Committer interface", api)
	}
	commitment, err := committer.Commit(c.X[:]...)
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		api.AssertIsDifferent(commitment, c.X[i])
		for _, p := range c.Public {
			api.AssertIsDifferent(p, 0)
		}
	}
	return err
}

func getVkProofCommitmentCircuit() (bn254plonk.Proof, bn254plonk.VerifyingKey) {

	var circuit commitmentCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	checkError(err)

	var witness commitmentCircuit
	witness.X = [3]frontend.Variable{3, 4, 5}
	witness.Public = [3]frontend.Variable{6, 7, 8}
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	checkError(err)
	witnessPublic, err := witnessFull.Public()
	checkError(err)

	srs, err := test.NewKZGSRS(ccs)
	checkError(err)

	pk, vk, err := plonk.Setup(ccs, srs)
	checkError(err)

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	checkError(err)

	err = plonk.Verify(proof, vk, witnessPublic)
	checkError(err)

	tvk := vk.(*bn254plonk.VerifyingKey)
	tproof := proof.(*bn254plonk.Proof)

	return *tproof, *tvk
}

func printvk(vk bn254plonk.VerifyingKey) {

	fmt.Println("uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;")
	fmt.Println("uint256 constant p_mod = 21888242871839275222246405745257275088696311157297823662689037894645226208583;")

	fmt.Printf("uint256 constant g2_srs_0_x_0 = %s;\n", vk.Kzg.G2[0].X.A1.String())
	fmt.Printf("uint256 constant g2_srs_0_x_1 = %s;\n", vk.Kzg.G2[0].X.A0.String())
	fmt.Printf("uint256 constant g2_srs_0_y_0 = %s;\n", vk.Kzg.G2[0].Y.A1.String())
	fmt.Printf("uint256 constant g2_srs_0_y_1 = %s;\n", vk.Kzg.G2[0].Y.A0.String())

	fmt.Printf("// ----------------------- vk ---------------------\n")

	fmt.Printf("uint256 constant vk_domain_size = %d;\n", vk.Size)
	fmt.Printf("uint256 constant vk_inv_domain_size = %s;\n", vk.SizeInv.String())
	fmt.Printf("uint256 constant vk_omega = %s;\n", vk.Generator.String())
	fmt.Printf("uint256 constant vk_ql_com_x = %s;\n", vk.Ql.X.String())
	fmt.Printf("uint256 constant vk_ql_com_y = %s;\n", vk.Ql.Y.String())
	fmt.Printf("uint256 constant vk_qr_com_x = %s;\n", vk.Qr.X.String())
	fmt.Printf("uint256 constant vk_qr_com_y = %s;\n", vk.Qr.Y.String())
	fmt.Printf("uint256 constant vk_qm_com_x = %s;\n", vk.Qm.X.String())
	fmt.Printf("uint256 constant vk_qm_com_y = %s;\n", vk.Qm.Y.String())
	fmt.Printf("uint256 constant vk_qo_com_x = %s;\n", vk.Qo.X.String())
	fmt.Printf("uint256 constant vk_qo_com_y = %s;\n", vk.Qo.Y.String())
	fmt.Printf("uint256 constant vk_qk_com_x = %s;\n", vk.Qk.X.String())
	fmt.Printf("uint256 constant vk_qk_com_y = %s;\n", vk.Qk.Y.String())
	fmt.Printf("uint256 constant vk_s1_com_x = %s;\n", vk.S[0].X.String())
	fmt.Printf("uint256 constant vk_s1_com_y = %s;\n", vk.S[0].Y.String())
	fmt.Printf("uint256 constant vk_s2_com_x = %s;\n", vk.S[1].X.String())
	fmt.Printf("uint256 constant vk_s2_com_y = %s;\n", vk.S[1].Y.String())
	fmt.Printf("uint256 constant vk_s3_com_x = %s;\n", vk.S[2].X.String())
	fmt.Printf("uint256 constant vk_s3_com_y = %s;\n", vk.S[2].Y.String())

	fmt.Printf("uint256 constant vk_coset_shift = 5;\n")

	fmt.Printf("uint256 constant vk_selector_commitments_commit_api_0_x = %s;\n", vk.Qcp.X.String())
	fmt.Printf("uint256 constant vk_selector_commitments_commit_api_0_y = %s;\n", vk.Qcp.Y.String())

	fmt.Printf("uint256 constant g2_srs_1_x_0 = %s;\n", vk.Kzg.G2[1].X.A1.String())
	fmt.Printf("uint256 constant g2_srs_1_x_1 = %s;\n", vk.Kzg.G2[1].X.A0.String())
	fmt.Printf("uint256 constant g2_srs_1_y_0 = %s;\n", vk.Kzg.G2[1].Y.A1.String())
	fmt.Printf("uint256 constant g2_srs_1_y_1 = %s;\n", vk.Kzg.G2[1].Y.A0.String())

	fmt.Println("function load_vk_commitments_indices_commit_api(uint256[] memory v)")
	fmt.Println("internal view {")
	fmt.Println("\tassembly {")
	fmt.Println("\tlet _v := add(v, 0x20)")
	for i := 0; i < len(vk.CommitmentConstraintIndexes); i++ {
		fmt.Printf("\tmstore(_v, %d)\n", vk.CommitmentConstraintIndexes[i])
		fmt.Println("\t_v := add(_v, 0x20)")
	}
	fmt.Println("\t}")
	fmt.Println("}")

	fmt.Printf("uint256 constant vk_nb_commitments_commit_api = %d;\n", len(vk.CommitmentConstraintIndexes))

}

func serialiseProof(proof bn254plonk.Proof) []byte {

	var res []byte

	// uint256 l_com_x;
	// uint256 l_com_y;
	// uint256 r_com_x;
	// uint256 r_com_y;
	// uint256 o_com_x;
	// uint256 o_com_y;
	var tmp64 [64]byte
	for i := 0; i < 3; i++ {
		tmp64 = proof.LRO[i].RawBytes()
		res = append(res, tmp64[:]...)
	}

	// uint256 h_0_x;
	// uint256 h_0_y;
	// uint256 h_1_x;
	// uint256 h_1_y;
	// uint256 h_2_x;
	// uint256 h_2_y;
	for i := 0; i < 3; i++ {
		tmp64 = proof.H[i].RawBytes()
		res = append(res, tmp64[:]...)
	}
	var tmp32 [32]byte

	// uint256 l_at_zeta;
	// uint256 r_at_zeta;
	// uint256 o_at_zeta;
	// uint256 s1_at_zeta;
	// uint256 s2_at_zeta;
	for i := 2; i < 7; i++ {
		tmp32 = proof.BatchedProof.ClaimedValues[i].Bytes()
		res = append(res, tmp32[:]...)
	}

	// uint256 grand_product_commitment_x;
	// uint256 grand_product_commitment_y;
	tmp64 = proof.Z.RawBytes()
	res = append(res, tmp64[:]...)

	// uint256 grand_product_at_zeta_omega;
	tmp32 = proof.ZShiftedOpening.ClaimedValue.Bytes()
	res = append(res, tmp32[:]...)

	// uint256 quotient_polynomial_at_zeta;
	// uint256 linearization_polynomial_at_zeta;
	tmp32 = proof.BatchedProof.ClaimedValues[0].Bytes()
	res = append(res, tmp32[:]...)
	tmp32 = proof.BatchedProof.ClaimedValues[1].Bytes()
	res = append(res, tmp32[:]...)

	// uint256 opening_at_zeta_proof_x;
	// uint256 opening_at_zeta_proof_y;
	tmp64 = proof.BatchedProof.H.RawBytes()
	res = append(res, tmp64[:]...)

	// uint256 opening_at_zeta_omega_proof_x;
	// uint256 opening_at_zeta_omega_proof_y;
	tmp64 = proof.ZShiftedOpening.H.RawBytes()
	res = append(res, tmp64[:]...)

	// uint256[] selector_commit_api_at_zeta;
	// uint256[] wire_committed_commitments;
	tmp32 = proof.BatchedProof.ClaimedValues[7].Bytes()
	res = append(res, tmp32[:]...)
	tmp64 = proof.PI2.RawBytes()
	res = append(res, tmp64[:]...)

	return res
}

func main() {

	// create account
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// create simulated backend
	client, auth, err := createSimulatedBackend(privateKey)
	checkError(err)

	// deploy the contract
	contractAddress, _, instance, err := contract.DeployContract(auth, client)
	checkError(err)
	client.Commit()

	var proof bn254plonk.Proof
	var vk bn254plonk.VerifyingKey

	// proof, vk = getVkProofCommitmentCircuit()
	// wproof, err := os.Create("proof.commit")
	// checkError(err)
	// _, err = proof.WriteRawTo(wproof)
	// checkError(err)
	// wvk, err := os.Create("vk.commit")
	// checkError(err)
	// _, err = vk.WriteRawTo(wvk)
	// checkError(err)
	// wproof.Close()
	// wvk.Close()

	rproof, err := os.Open("proof.commit")
	checkError(err)
	_, err = proof.ReadFrom(rproof)
	checkError(err)
	rvk, err := os.Open("vk.commit")
	checkError(err)
	_, err = vk.ReadFrom(rvk)
	checkError(err)
	rproof.Close()
	rvk.Close()

	// printvk(vk)

	var witness commitmentCircuit
	witness.X = [3]frontend.Variable{3, 4, 5}
	witness.Public = [3]frontend.Variable{6, 7, 8}
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	checkError(err)
	witnessPublic, err := witnessFull.Public()
	checkError(err)

	// err = plonk.Verify(&proof, &vk, witnessPublic)
	// checkError(err)
	plonk.Verify(&proof, &vk, witnessPublic)

	// Interact with the contract
	auth, err = getTransactionOpts(privateKey, auth, client)
	checkError(err)

	// fmt.Println(proof.PI2.String())
	pi := make([]*big.Int, 3)
	pi[0] = big.NewInt(6)
	pi[1] = big.NewInt(7)
	pi[2] = big.NewInt(8)
	sproof := serialiseProof(proof)
	_, err = instance.TestVerifier(auth, sproof, pi)
	checkError(err)
	client.Commit()

	// query event
	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(0),
		ToBlock:   big.NewInt(2),
		Addresses: []common.Address{
			contractAddress,
		},
	}

	logs, err := client.FilterLogs(context.Background(), query)
	checkError(err)

	contractABI, err := abi.JSON(strings.NewReader(string(contract.ContractABI)))
	checkError(err)

	for _, vLog := range logs {

		var event interface{}
		// err = contractABI.UnpackIntoInterface(&event, "PrintRes", vLog.Data)
		err = contractABI.UnpackIntoInterface(&event, "PrintUint256", vLog.Data)
		// err = contractABI.UnpackIntoInterface(&event, "PrintBytes32", vLog.Data)
		// err = contractABI.UnpackIntoInterface(&event, "PrintBytes", vLog.Data)
		checkError(err)
		fmt.Println(event)
	}
}
