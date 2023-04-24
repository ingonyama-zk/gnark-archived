 // It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity >=0.6.0;
pragma experimental ABIEncoderV2;

import {Bn254} from './Bn254.sol';
import {Fr} from './Fr.sol';
import {TranscriptLibrary} from './Transcript.sol';

// cf https://github.com/ConsenSys/gnark-crypto/blob/develop/ecc/bn254/fr/kzg/kzg.go
library Kzg {

    using Bn254 for Bn254.G1Point;
    using Bn254 for Bn254.G2Point;
    using Fr for uint256;
    using TranscriptLibrary for TranscriptLibrary.Transcript;

    uint256 constant g1_x = 1;
    uint256 constant g1_y = 2;

    // g2_x_0*u + g2_x_1 (evm order)
    uint256 constant g2_x_0 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2;
    uint256 constant g2_x_1 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6e;
    uint256 constant g2_y_0 = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975;
    uint256 constant g2_y_1 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7da;

    struct OpeningProof {
        // H = (h_x, h_y) quotient polynomial (f - f(z))/(x-z)
        //Bn254.G1Point H;
        uint256 h_x;
        uint256 h_y;

        // claimed_value purported value
        uint256 claimed_value;
    }

    struct BatchOpeningProof {
        
        // H quotient polynomial Sum_i gamma**i*(f - f(z))/(x-z)
        Bn254.G1Point H;

        // claimed_values purported values
        uint256[] claimed_values;
    }

    event PrintUint256(uint256 a);

    function copy_opening_proof(OpeningProof memory src, OpeningProof memory dst)
    internal pure {
        assembly {
            mstore(src, mload(dst))
            mstore(add(src, 0x20), mload(add(dst, 0x20)))
            mstore(add(src, 0x40), mload(add(dst, 0x40)))
        }
    }

    // fold the digests corresponding to a batch opening proof at a given point
    // return the proof associated to the folded digests, and the folded digest
    function fold_proof(Bn254.G1Point[] memory digests, BatchOpeningProof memory batch_opening_proof, uint256 point)
    internal view returns(OpeningProof memory opening_proof, Bn254.G1Point memory folded_digests)
    {
        require(digests.length==batch_opening_proof.claimed_values.length);

        TranscriptLibrary.Transcript memory t = TranscriptLibrary.new_transcript();
        t.set_challenge_name("gamma");
        t.update_with_fr(point);
        for (uint i = 0; i<digests.length; i++){
            t.update_with_g1(digests[i]);
        }
        uint256 gamma = t.get_challenge();

         // fold the claimed values
        uint256[] memory gammai = new uint256[](digests.length);
        uint256 r = Fr.r_mod;
        assembly {
            
            // opening_proof.H <- batch_opening_proof.H
            mstore(opening_proof, mload(add(batch_opening_proof, 0x40)))
            mstore(add(opening_proof,0x20), mload(add(batch_opening_proof, 0x60)))

            // opening_proof.claimed_value <- \sum_i batch_opening_proof.claimed_values[i]*gamma[i]
            // gammai <- [1,\gamma,..,\gamma^n]
            mstore(add(gammai,0x20), 1)
            let claimed_value_i := add(batch_opening_proof,0xa0)
            mstore(add(opening_proof,0x40), mload(claimed_value_i))
            let tmp := mload(0x40)
            let n := mload(digests)
            let prev_gamma := add(gammai,0x20)
            for {let i:=1} lt(i,n) {i:=add(i,1)}
            {
                claimed_value_i := add(claimed_value_i, 0x20)
                mstore(add(prev_gamma,0x20), mulmod(mload(prev_gamma),gamma,r))
                mstore(tmp, mulmod(mload(add(prev_gamma,0x20)), mload(claimed_value_i), r))
                mstore(add(opening_proof,0x40), addmod(mload(add(opening_proof,0x40)),  mload(tmp), r))
                prev_gamma := add(prev_gamma,0x20)
            }
        }

        // TODO hardcode the multi exp in the previous chunk ?
        folded_digests = Bn254.multi_exp(digests, gammai);

        return (opening_proof, folded_digests);
    }

    // returns \sum_i [lambda^{i}p_i]H_i \sum_i [lambda^{i)]H_i, \sum_i [lambda_i]Comm_i, \sum_i lambda^i*p_i
    function fold_digests_quotients_evals(uint256[] memory lambda, uint256[] memory points, Bn254.G1Point[] memory digests, OpeningProof[] memory proofs)
    internal view returns(
        Bn254.G1Point memory res_quotient, 
        Bn254.G1Point memory res_digest,
        Bn254.G1Point memory res_points_quotients,
        uint256 res_eval)
    {

        uint256 r = Fr.r_mod;

        assembly {

            // res_quotient <- proofs[0].H
            let proof_i := add(proofs, mul(add(mload(proofs),1),0x20))
            mstore(res_quotient, mload(proof_i))
            mstore(add(res_quotient, 0x20), mload(add(proof_i, 0x20)))

            // res_digest <- digests[0]
            let digest_i := add(digests, mul(add(mload(digests),1), 0x20))
            mstore(res_digest, mload(digest_i))
            mstore(add(res_digest, 0x20), mload(add(digest_i, 0x20)))

            // dst <- [s]src
            function point_mul_local(dst,src,s) {
                let buf := mload(0x40)
                mstore(buf,mload(src))
                mstore(add(buf,0x20),mload(add(src,0x20)))
                mstore(add(buf,0x40),mload(s))
                pop(staticcall(gas(),7,buf,0x60,dst,0x40)) // TODO should we check success here ?
            }

            // dst <- dst + [s]src
            function point_acc_mul_local(dst,src,s) {
                let buf := mload(0x40)
                mstore(buf,mload(src))
                mstore(add(buf,0x20),mload(add(src,0x20)))
                mstore(add(buf,0x40),mload(s))
                pop(staticcall(gas(),7,buf,0x60,buf,0x40)) // TODO should we check success here ?
                mstore(add(buf,0x40),mload(dst))
                mstore(add(buf,0x60),mload(add(dst,0x20)))
                pop(staticcall(gas(),6,buf,0x80,dst, 0x40))
            }

            // dst <- dst + [ a*b [r] ]src
            function point_acc_mul_mul_local(dst,src,a,b,rmod) {
                let buf := mload(0x40)
                mstore(buf,mload(src))
                mstore(add(buf,0x20),mload(add(src,0x20)))
                mstore(add(buf,0x40),mulmod(mload(a),mload(b),rmod))
                pop(staticcall(gas(),7,buf,0x60,buf,0x40)) // TODO should we check success here ?
                mstore(add(buf,0x40),mload(dst))
                mstore(add(buf,0x60),mload(add(dst,0x20)))
                pop(staticcall(gas(),6,buf,0x80,dst, 0x40))
            }

            // res_points_quotients <- [points[0]]*proofs[0].H
            let point_i := add(points,0x20)
            point_mul_local(res_points_quotients, proof_i, point_i)

            // res_eval <- proofs[0].claimed_value
            res_eval:= mload(add(proof_i, 0x40))

            let lambda_i := add(lambda,0x20)

            for {let i:=1} lt(i,mload(proofs)) {i:=add(i,1)}
            {

                digest_i := add(digest_i,0x40)
                proof_i := add(proof_i,0x60)
                lambda_i := add(lambda_i,0x20)
                point_i := add(point_i,0x20)

                // res_quotient <- res_quotient + [\lambda_i]proof[i].H
                point_acc_mul_local(res_quotient, proof_i, lambda_i)
                   
                // res_digest <- res_digest + [\lambda_i]digest[i]
                point_acc_mul_local(res_digest, digest_i, lambda_i)

                // res_point_quotient <- [\lambda_i point[i]]proof[i].H
                point_acc_mul_mul_local(res_points_quotients, proof_i, lambda_i, point_i, r)
                
                res_eval := addmod(res_eval,mulmod(mload(lambda_i),mload(add(proof_i,0x40)),r),r)
            }
        }

        return (res_points_quotients, res_digest, res_quotient, res_eval);

    }

    function batch_verify_multi_points(Bn254.G1Point[] memory digests, OpeningProof[] memory proofs, uint256[] memory points, Bn254.G2Point memory g2)
    internal view returns(bool)
    {

        require(digests.length == proofs.length);
        require(digests.length == points.length);

        // sample a random number (it's up to the verifier only so no need to take extra care)
        // here we take lambda[i] = keccak256(digest[i].h_x)
        uint256[] memory lambda = new uint256[](digests.length);
        uint256 r = Fr.r_mod;
        uint256 p = Bn254.p_mod;
        assembly {
            let lambda_i := add(lambda,0x20)
            mstore(lambda_i,1)
            let digest_i := add(digests, mul(add(mload(digests),1),0x20))
            for {let i:=1} lt(i,mload(digests)) {i:=add(i,1)}
            {
                digest_i := add(digest_i,0x40)
                lambda_i := add(lambda_i,0x20)
                mstore(lambda_i, mod(keccak256(digest_i,0x20),r))
            }
        }

        Bn254.G1Point memory folded_digests;
        Bn254.G1Point memory folded_quotients;
        Bn254.G1Point memory folded_points_quotients;
        uint256 folded_evals;
        (folded_points_quotients, folded_digests, folded_quotients, folded_evals) = fold_digests_quotients_evals(lambda, points, digests, proofs);

        uint256 res_pairing;
        assembly {

            // folded_evals_commit <- [folded_evals]G_1, G_1=(1,2)
            let folded_evals_commit_x
            let folded_evals_commit_y
            let buf := mload(0x40)
            mstore(buf, g1_x)
            mstore(add(buf,0x20), g1_y)
            mstore(add(buf,0x40), folded_evals)
            pop(staticcall(gas(),7,buf,0x60,buf,0x40))
            folded_evals_commit_x := mload(buf)
            folded_evals_commit_y := mload(add(buf,0x20))

            // foldedDigests <- ∑ᵢλᵢ[fᵢ(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁
            mstore(buf, mload(folded_digests))
            mstore(add(buf,0x20), mload(add(folded_digests,0x20)))
            mstore(add(buf,0x40), folded_evals_commit_x)
            mstore(add(buf,0x60), sub(p,folded_evals_commit_y))
            pop(staticcall(gas(),6,buf,0x80,folded_digests,0x40))

            // folded_digests <- [∑ᵢλᵢf_i(α) - ∑ᵢλᵢfᵢ(aᵢ) + ∑ᵢλᵢpᵢHᵢ(α)]G₁
            mstore(buf, mload(folded_digests))
            mstore(add(buf,0x20), mload(add(folded_digests, 0x20)))
            mstore(add(buf,0x40), mload(folded_points_quotients))
            mstore(add(buf,0x60), mload(add(folded_points_quotients, 0x20)))
            pop(staticcall(gas(),6,buf,0x80,folded_digests,0x40))

            // folded_quotients <- -[folded_quotients]
            mstore(add(folded_quotients,0x20), sub(p,mload(add(folded_quotients,0x20))))

            // e([∑ᵢλᵢ(fᵢ(α) - fᵢ(pᵢ) + pᵢHᵢ(α))]G₁, G₂).e([-∑ᵢλᵢ[Hᵢ(α)]G₁), [α]G₂)
            mstore(buf, mload(folded_digests))
            mstore(add(buf, 0x20), mload(add(folded_digests, 0x20)))
            mstore(add(buf, 0x40), g2_x_0) // the 4 lines are the canonical G2 point on BN254
            mstore(add(buf, 0x60), g2_x_1)
            mstore(add(buf, 0x80), g2_y_0)
            mstore(add(buf, 0xa0), g2_y_1)
            mstore(add(buf, 0xc0), mload(folded_quotients))
            mstore(add(buf, 0xe0), mload(add(folded_quotients, 0x20)))
            mstore(add(buf, 0x100), mload(g2))
            mstore(add(buf, 0x120), mload(add(g2, 0x20)))
            mstore(add(buf, 0x140), mload(add(g2, 0x40)))
            mstore(add(buf, 0x160), mload(add(g2, 0x60)))
            pop(staticcall(gas(),8,buf,0x180,0x00,0x20))
            res_pairing := mload(0x00)
        }
        return (res_pairing != 0);

    }

}