// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity >=0.6.0;

import {Bn254} from './crypto/Bn254.sol';
import {Fr} from './crypto/Fr.sol';
import {TranscriptLibrary} from './crypto/Transcript.sol';
import {Polynomials} from './crypto/Polynomials.sol';
import {Types} from './crypto/Types.sol';
import {Kzg} from './crypto/Kzg.sol';
import {UtilsFr} from './crypto/HashFr.sol';

// contract PlonkVerifier {
library PlonkVerifier{

    using Bn254 for Bn254.G1Point;
    using Bn254 for Bn254.G2Point;
    using Fr for uint256;
    using TranscriptLibrary for TranscriptLibrary.Transcript;
    using Polynomials for *;
    using Types for *;

    uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // offset for the proof data (in bytes)
    uint256 constant proof_l_commitment = 0x00;
    uint256 constant proof_r_commitment = 0x40;
    uint256 constant proof_o_commitment = 0x80;

    uint256 constant proof_quotient_poly_commitments_0 = 0xc0;
    uint256 constant proof_quotient_poly_commitments_1 = 0x100;
    uint256 constant proof_quotient_poly_commitments_2 = 0x140;

    uint256 constant proof_l_at_zeta = 0x180;
    uint256 constant proof_r_at_zeta = 0x1a0;
    uint256 constant proof_o_at_zeta = 0x1c0;

    uint256 constant proof_s1_at_zeta = 0x1e0;
    uint256 constant proof_s2_at_zeta = 0x200;

    uint256 constant proof_grand_product_commitment = 0x220;

    uint256 constant proof_grand_product_at_zeta_omega = 0x260;
    uint256 constant proof_quotient_polynomial_at_zeta = 0x280;
    uint256 constant proof_linearization_polynomial_at_zeta = 0x2a0;

    uint256 constant proof_opening_at_zeta_x = 0x2c0;
    uint256 constant proof_opening_at_zeta_y = 0x2e0;

    uint256 constant proof_selector_commit_api_at_zeta = 0x420;

    // offset for the state (in bytes)
    uint256 constant state_alpha = 0x00;
    uint256 constant state_beta = 0x20;
    uint256 constant state_gamma = 0x40;
    uint256 constant state_zeta = 0x60;

    uint256 constant state_v = 0x80;
    uint256 constant state_u = 0xa0;

    uint256 constant state_alpha_square_lagrange = 0xc0;

    uint256 constant state_folded_h_x = 0xe0;
    uint256 constant state_folded_h_y = 0x100;

    uint256 constant state_linearised_polynomial_x = 0x120;
    uint256 constant state_linearised_polynomial_y = 0x140;

    // verification key
    uint256 constant vk_domain_size = 0x00;
    uint256 constant vk_omega = 0x20;

    uint256 constant vk_ql_com_x = 0x40;
    uint256 constant vk_ql_com_y = 0x60;
    uint256 constant vk_qr_com_x = 0x80;
    uint256 constant vk_qr_com_y = 0xa0;
    uint256 constant vk_qm_com_x = 0xc0;
    uint256 constant vk_qm_com_y = 0xe0;
    uint256 constant vk_qo_com_x = 0x100;
    uint256 constant vk_qo_com_y = 0x120;
    uint256 constant vk_qk_com_x = 0x140;
    uint256 constant vk_qk_com_y = 0x160;

    uint256 constant vk_s1_com_x = 0x180;
    uint256 constant vk_s1_com_y = 0x1a0;
    uint256 constant vk_s2_com_x = 0x1c0;
    uint256 constant vk_s2_com_y = 0x1e0;
    uint256 constant vk_s3_com_x = 0x200;
    uint256 constant vk_s3_com_y = 0x220;

    // the first at vk+vk_selector_commitments_commit_api is the size of the
    // commitments_commit_api slice. It's the usual layout after that so
    // vk_selector_commitments_commit_api + size*0x20 to query the first point
    uint256 constant vk_selector_commitments_commit_api = 0x2e0;

    function derive_gamma_beta_alpha_zeta(

        Types.State memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk,
        uint256[] memory public_inputs) internal pure {

        TranscriptLibrary.Transcript memory t = TranscriptLibrary.new_transcript();
        t.set_challenge_name("gamma");

        t.update_with_u256(vk.s1_com_x);
        t.update_with_u256(vk.s1_com_y);
        t.update_with_u256(vk.s2_com_x);
        t.update_with_u256(vk.s2_com_y);
        t.update_with_u256(vk.s3_com_x);
        t.update_with_u256(vk.s3_com_y);

        t.update_with_u256(vk.ql_com_x); // ql
        t.update_with_u256(vk.ql_com_y); // ql
        t.update_with_u256(vk.qr_com_x); // qr
        t.update_with_u256(vk.qr_com_y); // qr
        t.update_with_u256(vk.qm_com_x); // qm
        t.update_with_u256(vk.qm_com_y); // qm
        t.update_with_u256(vk.qo_com_x); // qo
        t.update_with_u256(vk.qo_com_y); // qo
        t.update_with_u256(vk.qk_com_x); // qk
        t.update_with_u256(vk.qk_com_y); // qk

        for (uint256 i = 0; i < public_inputs.length; i++) {
            t.update_with_u256(public_inputs[i]);
        }

        for (uint i=0; i<proof.wire_committed_commitments.length; i++){
            t.update_with_g1(proof.wire_committed_commitments[i]); // PI2_i
        }

        t.update_with_u256(proof.l_com_x);
        t.update_with_u256(proof.l_com_y);
        t.update_with_u256(proof.r_com_x);
        t.update_with_u256(proof.r_com_y);
        t.update_with_u256(proof.o_com_x);
        t.update_with_u256(proof.o_com_y);

        state.gamma = t.get_challenge();

        t.set_challenge_name("beta");
        state.beta = t.get_challenge();

        t.set_challenge_name("alpha");
        //t.update_with_g1(proof.grand_product_commitment);
        t.update_with_u256(proof.grand_product_commitment_x);
        t.update_with_u256(proof.grand_product_commitment_y);
        state.alpha = t.get_challenge();

        t.set_challenge_name("zeta");
       
        t.update_with_u256(proof.h_0_x);
        t.update_with_u256(proof.h_0_y);
        t.update_with_u256(proof.h_1_x);
        t.update_with_u256(proof.h_1_y);
        t.update_with_u256(proof.h_2_x);
        t.update_with_u256(proof.h_2_y);

        state.zeta = t.get_challenge();
    }

     // plonk paper verify process step8: Compute quotient polynomial evaluation
    function verify_quotient_poly_eval_at_zeta(
        Types.State memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk,
        uint256[] memory public_inputs
    ) internal view returns (bool) {

        // evaluation of Z=Xⁿ⁻¹ at ζ
        uint256 zeta_power_n_minus_one = Fr.pow(state.zeta, vk.domain_size);
        zeta_power_n_minus_one = Fr.sub(zeta_power_n_minus_one, 1);

        // compute PI = ∑_{i<n} Lᵢ*wᵢ
        uint256 pi = Polynomials.compute_sum_li_zi(public_inputs, state.zeta, vk.omega, vk.domain_size);
        
        if (vk.commitment_indices.length > 0) {

            string memory dst = "BSB22-Plonk";

            for (uint256 i=0; i<vk.commitment_indices.length; i++){
                uint256 hash_res = UtilsFr.hash_fr(proof.wire_committed_commitments[i].X, proof.wire_committed_commitments[i].Y, dst);
                uint256 a = Polynomials.compute_ith_lagrange_at_z(vk.commitment_indices[i]+public_inputs.length, state.zeta, vk.omega, vk.domain_size);
                a = Fr.mul(hash_res, a);
                pi = Fr.add(pi, a);
            }
        }

        state.alpha_square_lagrange = Polynomials.compute_ith_lagrange_at_z(0, state.zeta, vk.omega, vk.domain_size);
        bool success;
    
        assembly {

            // (l(ζ)+β*s1(ζ)+γ)
            let s1 := mload(0x40)
            mstore(s1, mulmod(mload(add(proof,proof_s1_at_zeta)),mload(add(state, state_beta)), r_mod))
            mstore(s1, addmod(mload(s1), mload(add(state, state_gamma)), r_mod))
            mstore(s1, addmod(mload(s1), mload(add(proof, proof_l_at_zeta)), r_mod))

            // (r(ζ)+β*s2(ζ)+γ)
            let s2 := add(s1,0x20)
            mstore(s2, mulmod(mload(add(proof,proof_s2_at_zeta)),mload(add(state, state_beta)), r_mod))
            mstore(s2, addmod(mload(s2), mload(add(state, state_gamma)), r_mod))
            mstore(s2, addmod(mload(s2), mload(add(proof, proof_r_at_zeta)), r_mod))
            // _s2 := mload(s2)

            // (o(ζ)+γ)
            let o := add(s1,0x40)
            mstore(o, addmod(mload(add(proof,proof_o_at_zeta)), mload(add(state, state_gamma)), r_mod))

            //  α*(Z(μζ))*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(o(ζ)+γ)
            mstore(s1, mulmod(mload(s1), mload(s2), r_mod))
            mstore(s1, mulmod(mload(s1), mload(o), r_mod))
            mstore(s1, mulmod(mload(s1), mload(add(state, state_alpha)), r_mod))
            mstore(s1, mulmod(mload(s1), mload(add(proof, proof_grand_product_at_zeta_omega)), r_mod))

            // α²*L₁(ζ)
            mstore(add(state,state_alpha_square_lagrange), mulmod(mload(add(state,state_alpha_square_lagrange)), mload(add(state, state_alpha)), r_mod))
            mstore(add(state,state_alpha_square_lagrange), mulmod(mload(add(state,state_alpha_square_lagrange)), mload(add(state, state_alpha)), r_mod))

            let computed_quotient := add(s1,0x60)

            // linearizedpolynomial + pi(zeta)
            mstore(computed_quotient, addmod(mload(add(proof, proof_linearization_polynomial_at_zeta)), pi, r_mod))

            // linearizedpolynomial+pi(zeta)+α*(Z(μζ))*(l(ζ)+s1(ζ)+γ)*(r(ζ)+s2(ζ)+γ)*(o(ζ)+γ)
            mstore(computed_quotient, addmod(mload(computed_quotient), mload(s1), r_mod))

            // linearizedpolynomial+pi(zeta)+α*(Z(μζ))*(l(ζ)+s1(ζ)+γ)*(r(ζ)+s2(ζ)+γ)*(o(ζ)+γ)-α²*L₁(ζ)
            mstore(computed_quotient, addmod(mload(computed_quotient), sub(r_mod,mload(add(state, state_alpha_square_lagrange))), r_mod))

            // test_quotient := mload(computed_quotient)
            mstore(s2, mulmod(mload(add(proof,proof_quotient_polynomial_at_zeta)), zeta_power_n_minus_one, r_mod))

            success := eq(mload(computed_quotient), mload(s2))
        }
        return success;
    }

    function fold_h(
        Types.State memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk
    ) internal view {

        uint256 r = Fr.r_mod;
        assembly {

            let n_plus_two := addmod(mload(vk), 2, r)

            // dst <- [s]dst + src
            function point_acc_mul_local(dst,src,s) {
                let buf := mload(0x40)
                mstore(buf,mload(dst))
                mstore(add(buf,0x20),mload(add(dst,0x20)))
                mstore(add(buf,0x40),s)
                pop(staticcall(gas(),7,buf,0x60,buf,0x40)) // TODO should we check success here ?
                mstore(add(buf,0x40),mload(src))
                mstore(add(buf,0x60),mload(add(src,0x20)))
                pop(staticcall(gas(),6,buf,0x80,dst, 0x40))
            }

            // TODO careful depends on the proof layout
            // zeta_power_n_plus_two <- zeta**{n+2}
            // let zeta_power_n_plus_two
            let buf := mload(0x40)
            mstore(buf, 0x20)
            mstore(add(buf, 0x20), 0x20)
            mstore(add(buf, 0x40), 0x20)
            mstore(add(buf, 0x60), mload(add(state,0x60)))
            mstore(add(buf, 0x80), n_plus_two)
            mstore(add(buf, 0xa0), r)
            pop(staticcall(gas(),0x05,buf,0xc0,0x00,0x20))
            let zeta_power_n_plus_two := mload(0x00)

            // state.folded_h <- [zeta^{n+2}]proof.quotient_poly_commitments[2]
            let folded_h := add(state, state_folded_h_x)
            let proof_quotient_poly_commitments := add(proof, proof_quotient_poly_commitments_2)
            mstore(folded_h, mload(proof_quotient_poly_commitments))
            mstore(add(folded_h,0x20), mload(add(proof_quotient_poly_commitments,0x20)))
            proof_quotient_poly_commitments := add(proof, proof_quotient_poly_commitments_1)
            point_acc_mul_local(folded_h, proof_quotient_poly_commitments, zeta_power_n_plus_two)
            proof_quotient_poly_commitments := add(proof,proof_quotient_poly_commitments_0)
            point_acc_mul_local(folded_h, proof_quotient_poly_commitments, zeta_power_n_plus_two)
        }
    }

    function compute_commitment_linearised_polynomial(
        Types.State memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk
    ) internal view {

        // linearizedPolynomialDigest =
        // 		l(ζ)*ql+r(ζ)*qr+r(ζ)l(ζ)*qm+o(ζ)*qo+qk+\sum_i qc_i*PI2_i +
        // 		α*( Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*s₃(X)-Z(X)(l(ζ)+β*id_1(ζ)+γ)*(r(ζ)+β*id_2(ζ)+γ)*(o(ζ)+β*id_3(ζ)+γ) ) +
        // 		α²*L₁(ζ)*Zs

        // α*( Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*β*s₃(X)-Z(X)(l(ζ)+β*id_1(ζ)+γ)*(r(ζ)+β*id_2(ζ)+γ)*(o(ζ)+β*id_3(ζ)+γ) ) )
        uint256 u;
        uint256 v;
        uint256 w;
        u = Fr.mul(proof.grand_product_at_zeta_omega, state.beta);
        v = Fr.mul(state.beta, proof.s1_at_zeta);
        v = Fr.add(v, proof.l_at_zeta);
        v = Fr.add(v, state.gamma);

        w = Fr.mul(state.beta, proof.s2_at_zeta);
        w = Fr.add(w, proof.r_at_zeta);
        w = Fr.add(w, state.gamma);

        uint256 _s1;
        _s1 = Fr.mul(u, v);
        _s1 = Fr.mul(_s1, w);
        _s1 = Fr.mul(_s1, state.alpha); // α*Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*β

        uint256 coset_square = Fr.mul(vk.coset_shift, vk.coset_shift);
        uint256 betazeta = Fr.mul(state.beta, state.zeta);
        u = Fr.add(betazeta, proof.l_at_zeta);
        u = Fr.add(u, state.gamma); // (l(ζ)+β*ζ+γ)

        v = Fr.mul(betazeta, vk.coset_shift);
        v = Fr.add(v, proof.r_at_zeta);
        v = Fr.add(v, state.gamma); // (r(ζ)+β*μ*ζ+γ)

        w = Fr.mul(betazeta, coset_square);
        w = Fr.add(w, proof.o_at_zeta);
        w = Fr.add(w, state.gamma); // (o(ζ)+β*μ²*ζ+γ)

        uint256 _s2 = Fr.mul(u, v);
        _s2 = Fr.mul(_s2, w);
        _s2 = Fr.sub(0, _s2);  // -(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
        _s2 = Fr.mul(_s2, state.alpha);
        _s2 = Fr.add(_s2, state.alpha_square_lagrange); // -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ) + α²*L₁(ζ)

        uint256 rl =  Fr.mul(proof.l_at_zeta, proof.r_at_zeta);

        // multi exp part
        Bn254.G1Point memory linearised_polynomial;
        Bn254.G1Point memory sel_tmp;
        sel_tmp.X = vk.ql_com_x;
        sel_tmp.Y = vk.ql_com_y;
        linearised_polynomial = Bn254.point_mul(sel_tmp, proof.l_at_zeta);
        sel_tmp.X = vk.qr_com_x;
        sel_tmp.Y = vk.qr_com_y;
        Bn254.G1Point memory ptmp = Bn254.point_mul(sel_tmp, proof.r_at_zeta);
        linearised_polynomial = Bn254.point_add(linearised_polynomial, ptmp);

        sel_tmp.X = vk.qm_com_x;
        sel_tmp.Y = vk.qm_com_y;
        ptmp = Bn254.point_mul(sel_tmp, rl);
        linearised_polynomial = Bn254.point_add(linearised_polynomial, ptmp);

        sel_tmp.X = vk.qo_com_x;
        sel_tmp.Y = vk.qo_com_y;
        ptmp = Bn254.point_mul(sel_tmp, proof.o_at_zeta);
        linearised_polynomial = Bn254.point_add(linearised_polynomial, ptmp);

        sel_tmp.X = vk.qk_com_x;
        sel_tmp.Y = vk.qk_com_y;
        linearised_polynomial = Bn254.point_add(linearised_polynomial, sel_tmp);

        for (uint i=0; i<proof.selector_commit_api_at_zeta.length; i++){
            ptmp = Bn254.point_mul(proof.wire_committed_commitments[i], proof.selector_commit_api_at_zeta[i]);
            linearised_polynomial = Bn254.point_add(linearised_polynomial, ptmp);
        }

        sel_tmp.X = vk.s3_com_x;
        sel_tmp.Y = vk.s3_com_y;
        ptmp = Bn254.point_mul(sel_tmp, _s1);
        linearised_polynomial = Bn254.point_add(linearised_polynomial, ptmp);

        sel_tmp.X = proof.grand_product_commitment_x;
        sel_tmp.Y = proof.grand_product_commitment_y;
        ptmp = Bn254.point_mul(sel_tmp, _s2);
        linearised_polynomial = Bn254.point_add(linearised_polynomial, ptmp);

        state.linearised_polynomial_x = linearised_polynomial.X;
        state.linearised_polynomial_y= linearised_polynomial.Y;

    }

    event PrintUint256(uint256 a);

    // function fold_state_inline(Bn254.G1Point[] memory digests, BatchOpeningProof memory batch_opening_proof, uint256 point)
    // internal view returns(OpeningProof memory opening_proof, Bn254.G1Point memory folded_digests)
    // {
    //     require(digests.length==batch_opening_proof.claimed_values.length);

    //     TranscriptLibrary.Transcript memory t = TranscriptLibrary.new_transcript();
    //     t.set_challenge_name("gamma");
    //     t.update_with_fr(point);
    //     for (uint i = 0; i<digests.length; i++){
    //         t.update_with_g1(digests[i]);
    //     }
    //     uint256 gamma = t.get_challenge();

    //      // fold the claimed values
    //     uint256[] memory gammai = new uint256[](digests.length);
    //     uint256 r = Fr.r_mod;
    //     assembly {
            
    //         // opening_proof.H <- batch_opening_proof.H
    //         mstore(opening_proof, mload(add(batch_opening_proof, 0x40)))
    //         mstore(add(opening_proof,0x20), mload(add(batch_opening_proof, 0x60)))

    //         // opening_proof.claimed_value <- \sum_i batch_opening_proof.claimed_values[i]*gamma[i]
    //         // gammai <- [1,\gamma,..,\gamma^n]
    //         mstore(add(gammai,0x20), 1)
    //         let claimed_value_i := add(batch_opening_proof,0xa0)
    //         mstore(add(opening_proof,0x40), mload(claimed_value_i))
    //         let tmp := mload(0x40)
    //         let n := mload(digests)
    //         let prev_gamma := add(gammai,0x20)
    //         for {let i:=1} lt(i,n) {i:=add(i,1)}
    //         {
    //             claimed_value_i := add(claimed_value_i, 0x20)
    //             mstore(add(prev_gamma,0x20), mulmod(mload(prev_gamma),gamma,r))
    //             mstore(tmp, mulmod(mload(add(prev_gamma,0x20)), mload(claimed_value_i), r))
    //             mstore(add(opening_proof,0x40), addmod(mload(add(opening_proof,0x40)),  mload(tmp), r))
    //             prev_gamma := add(prev_gamma,0x20)
    //         }
    //     }

    //     // TODO hardcode the multi exp in the previous chunk ?
    //     folded_digests = Bn254.multi_exp(digests, gammai);

    //     return (opening_proof, folded_digests);
    // }

    function fold_state(
        Types.State memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk
    ) internal {

        // TranscriptLibrary.Transcript memory t = TranscriptLibrary.new_transcript();
        // t.set_challenge_name("gamma");
        // t.update_with_fr(state.zeta);
        
        // t.update_with_u256(state.folded_h_x);
        // t.update_with_u256(state.folded_h_y);

        // t.update_with_u256(state.linearised_polynomial_x);
        // t.update_with_u256(state.linearised_polynomial_y);

        // t.update_with_u256(proof.l_com_x);
        // t.update_with_u256(proof.l_com_y);
        // t.update_with_u256(proof.r_com_x);
        // t.update_with_u256(proof.r_com_y);
        // t.update_with_u256(proof.o_com_x);
        // t.update_with_u256(proof.o_com_y);

        // t.update_with_u256(vk.s1_com_x);
        // t.update_with_u256(vk.s1_com_y);
        // t.update_with_u256(vk.s2_com_x);
        // t.update_with_u256(vk.s2_com_y);

        // for (uint256 i=0; i < vk.selector_commitments_commit_api.length; i++) {
        //     t.update_with_u256(vk.selector_commitments_commit_api[i].X);
        //     t.update_with_u256(vk.selector_commitments_commit_api[i].Y);
        // }
        // uint256 gamma = t.get_challenge();

        // TODO if we don't copy manually the coordinates, can't manage to access memory lcoations with yul...
        Bn254.G1Point[] memory digests = new Bn254.G1Point[](7+vk.selector_commitments_commit_api.length);
        // digests[0].X = state.folded_h_x;
        // digests[0].Y = state.folded_h_y;
        
        // digests[1].X = state.linearised_polynomial_x;
        // digests[1].Y = state.linearised_polynomial_y;
        
        // digests[2].X = proof.l_com_x;
        // digests[2].Y = proof.l_com_y;

        // digests[3].X = proof.r_com_x;
        // digests[3].Y = proof.r_com_y;

        // digests[4].X = proof.o_com_x;
        // digests[4].Y = proof.o_com_y;
        
        // digests[5].X = vk.s1_com_x;
        // digests[5].Y = vk.s1_com_y;
        // digests[6].X = vk.s2_com_x;
        // digests[6].Y = vk.s2_com_y;
        // for (uint i=0; i<vk.selector_commitments_commit_api.length; i++){
        //     Bn254.copy_g1(digests[i+7], vk.selector_commitments_commit_api[i]);
        // }

        assembly {

            // let bop := add(batch_opening_proof,0x40)
            // mstore(bop, mload(add(proof, proof_quotient_polynomial_at_zeta)))
            // mstore(add(bop,0x20), mload(add(proof, add(proof_quotient_polynomial_at_zeta,0x20))))

            // bop := add(bop, 0xa0)
            // mstore(bop, mload(add(proof, proof_quotient_polynomial_at_zeta)))
            // bop := add(bop,0x20)
            // mstore(bop, mload(add(proof, proof_l_at_zeta)))
            // bop := add(bop,0x20)
            // mstore(bop, mload(add(proof, proof_r_at_zeta)))
            // bop := add(bop,0x20)
            // mstore(bop, mload(add(proof, proof_o_at_zeta)))
            // bop := add(bop,0x20)
            // mstore(bop, mload(add(proof, proof_s1_at_zeta)))
            // bop := add(bop,0x20)
            // mstore(bop, mload(add(proof, proof_s2_at_zeta)))
            
            // let _proof := add(proof, proof_selector_commit_api_at_zeta)
            // for {let i:=0} lt(i,bop) {i:=add(i,1)}
            // {
            //     bop := add(bop, 0x20)
            //     _proof := add(_proof, 0x20)
            //     mstore(bop, mload(_proof))
            // }


            // dst <- dst + [s]src
        //     function point_acc_mul_local(dst,src,s) {
        //         let buf := mload(0x40)
        //         mstore(buf,mload(src))
        //         mstore(add(buf,0x20),mload(add(src,0x20)))
        //         mstore(add(buf,0x40),mload(s))
        //         pop(staticcall(gas(),7,buf,0x60,buf,0x40)) // TODO should we check success here ?
        //         mstore(add(buf,0x40),mload(dst))
        //         mstore(add(buf,0x60),mload(add(dst,0x20)))
        //         pop(staticcall(gas(),6,buf,0x80,dst, 0x40))
        //     }

            let _digests := add(digests, mul(add(mload(digests),1),0x20)) // TODO modify here mload(0x40)
            mstore(_digests, mload(add(state, state_folded_h_x)))
            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(state, state_folded_h_y)))

            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(state, state_linearised_polynomial_x)))
            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(state, state_linearised_polynomial_y)))

            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(proof, proof_l_commitment)))
            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(proof, add(proof_l_commitment,0x20))))

            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(proof, proof_r_commitment)))
            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(proof, add(proof_r_commitment,0x20))))

            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(proof, proof_o_commitment)))
            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(proof, add(proof_o_commitment,0x20))))

            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(vk, vk_s1_com_x)))
            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(vk, vk_s1_com_y)))

            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(vk, vk_s2_com_x)))
            _digests := add(_digests, 0x20)
            mstore(_digests, mload(add(vk, vk_s2_com_y)))
            _digests := add(_digests, 0x20)

            let api_commit := add(vk, vk_selector_commitments_commit_api)
            api_commit := mload(api_commit)
            let nb_commitments := mload(api_commit)
            api_commit := add(api_commit, mul(add(nb_commitments,1),0x20)) 
            for {let i:=0} lt(i, nb_commitments) {i:=add(i,1)}
            {
                mstore(_digests, mload(api_commit))
                _digests := add(_digests, 0x20)
                api_commit := add(api_commit,0x20)
                mstore(_digests, mload(api_commit))
                api_commit := add(api_commit,0x20)
                _digests := add(_digests, 0x20)
            }

            // let _ss := add(ss, 0x20)
            // let _vk := add(vk, vk_selector_commitments_commit_api)
            // _vk := mload(_vk)
            // let n := mload(_vk)
            // _vk := add(_vk, mul(add(n,1),0x20))
            // for {let i := 0} lt(i,2) {i:=add(i,1)}
            // {
            //     mstore(_ss, mload(_vk))
            //     _vk := add(_vk, 0x20)
            //     _ss := add(_ss, 0x20)
            // }
        }

        // TODO perhaps we should we inline all this
        Kzg.BatchOpeningProof memory batch_opening_proof;
        //Bn254.copy_g1(batch_opening_proof.H, proof.opening_at_zeta_proof);
        batch_opening_proof.H.X = proof.opening_at_zeta_proof_x;
        batch_opening_proof.H.Y = proof.opening_at_zeta_proof_y;
        batch_opening_proof.claimed_values = new uint256[](7+proof.selector_commit_api_at_zeta.length);
        batch_opening_proof.claimed_values[0] = proof.quotient_polynomial_at_zeta;
        batch_opening_proof.claimed_values[1] = proof.linearization_polynomial_at_zeta;
        batch_opening_proof.claimed_values[2] = proof.l_at_zeta;
        batch_opening_proof.claimed_values[3] = proof.r_at_zeta;
        batch_opening_proof.claimed_values[4] = proof.o_at_zeta;
        batch_opening_proof.claimed_values[5] = proof.s1_at_zeta;
        batch_opening_proof.claimed_values[6] = proof.s2_at_zeta;
        for (uint i=0; i<proof.selector_commit_api_at_zeta.length; i++){
            batch_opening_proof.claimed_values[7+i] = proof.selector_commit_api_at_zeta[i];
        }


        (state.folded_proof, state.folded_digests) = Kzg.fold_proof(
            digests, 
            batch_opening_proof,
            state.zeta);  
        
    } 

    function verify(Types.Proof memory proof, Types.VerificationKey memory vk, uint256[] memory public_inputs)
    internal     returns (bool) {

        Types.State memory state;
        
        // // step 1: derive gamma, beta, alpha, delta
        derive_gamma_beta_alpha_zeta(state, proof, vk, public_inputs);

        // step 2: verifiy the claimed quotient
        bool valid = verify_quotient_poly_eval_at_zeta(state, proof, vk, public_inputs);
        
        // step 3: fold H ( = Comm(h₁) + ζᵐ⁺²*Comm(h₂) + ζ²⁽ᵐ⁺²⁾*Comm(h₃))
        fold_h(state, proof, vk);
        // state.folded_h.X = 1;
        // state.folded_h.Y = 2;

        // linearizedPolynomialDigest =
        // 		l(ζ)*ql+r(ζ)*qr+r(ζ)l(ζ)*qm+o(ζ)*qo+qk+\sum_i qc_i*PI2_i +
        // 		α*( Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*s₃(X)-Z(X)(l(ζ)+β*id_1(ζ)+γ)*(r(ζ)+β*id_2(ζ)+γ)*(o(ζ)+β*id_3(ζ)+γ) ) +
        // 		α²*L₁(ζ)*Z
        compute_commitment_linearised_polynomial(state, proof, vk);

        // // step 4: fold proof + digests 
        fold_state(state, proof, vk);

        // step 5: batch verify the folded proof and the opening proof at omega*zeta
        Bn254.G1Point[] memory digests = new Bn254.G1Point[](2);
        Bn254.copy_g1(digests[0], state.folded_digests);
        // Bn254.copy_g1(digests[1], proof.grand_product_commitment);
        digests[1].X = proof.grand_product_commitment_x;
        digests[1].Y = proof.grand_product_commitment_y;
        
        Kzg.OpeningProof[] memory proofs = new Kzg.OpeningProof[](2);
        
        Kzg.copy_opening_proof(proofs[0], state.folded_proof);

        //Bn254.copy_g1(proofs[1].H, proof.opening_at_zeta_omega_proof);
        proofs[1].h_x = proof.opening_at_zeta_omega_proof.X;
        proofs[1].h_y = proof.opening_at_zeta_omega_proof.Y;
        proofs[1].claimed_value = proof.grand_product_at_zeta_omega;

        uint256[] memory points = new uint256[](2);
        points[0] = state.zeta;
        points[1] = Fr.mul(state.zeta, vk.omega);

        Bn254.G2Point memory g2_x;

        g2_x.X0 = vk.g2_x_0;
        g2_x.X1 = vk.g2_x_1;
        g2_x.Y0 = vk.g2_y_0;
        g2_x.Y1 = vk.g2_y_1;

        valid = valid && Kzg.batch_verify_multi_points(digests, proofs, points, g2_x);
        
        return valid;
    }
}

