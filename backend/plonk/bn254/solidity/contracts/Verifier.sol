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

    uint256 constant STATE_WIDTH = 3;

    // offset for the proof data (in bytes)
    uint256 constant proof_quotient_poly_commitments_0 = 0x280;
    uint256 constant proof_quotient_poly_commitments_1 = 0x2c0;
    uint256 constant proof_quotient_poly_commitments_2 = 0x300;

    // offset for the state (in bytes)
    uint256 constant state_folded_h = 0xe0;

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
        t.update_with_g1(proof.grand_product_commitment);
        state.alpha = t.get_challenge();

        t.set_challenge_name("zeta");
        for (uint256 i = 0; i < proof.quotient_poly_commitments.length; i++) {
            t.update_with_g1(proof.quotient_poly_commitments[i]);
        }
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

        uint256 _s1;
        _s1 = Fr.mul(proof.permutation_polynomials_at_zeta[0], state.beta);
        _s1 = Fr.add(_s1, state.gamma);
        _s1 = Fr.add(_s1, proof.wire_values_at_zeta[0]);  // (l(ζ)+β*s1(ζ)+γ)

        uint256 _s2;
        _s2 = Fr.mul(proof.permutation_polynomials_at_zeta[1], state.beta);
        _s2 = Fr.add(_s2, state.gamma);
        _s2 = Fr.add(_s2, proof.wire_values_at_zeta[1]); // (r(ζ)+β*s2(ζ)+γ)

        uint256 _o;
        _o = Fr.add(proof.wire_values_at_zeta[2], state.gamma);  // (o(ζ)+γ)

        _s1 = Fr.mul(_s1, _s2);
        _s1 = Fr.mul(_s1, _o);
        _s1 = Fr.mul(_s1, state.alpha);
        _s1 = Fr.mul(_s1, proof.grand_product_at_zeta_omega); //  α*(Z(μζ))*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(o(ζ)+γ)

        state.alpha_square_lagrange = Polynomials.compute_ith_lagrange_at_z(0, state.zeta, vk.omega, vk.domain_size);
        state.alpha_square_lagrange = Fr.mul(state.alpha_square_lagrange, state.alpha);
        state.alpha_square_lagrange = Fr.mul(state.alpha_square_lagrange, state.alpha);  // α²*L₁(ζ)
        
        uint256 computed_quotient;
        computed_quotient = Fr.add(proof.linearization_polynomial_at_zeta, pi); // linearizedpolynomial + pi(zeta)
        computed_quotient = Fr.add(computed_quotient, _s1); // linearizedpolynomial+pi(zeta)+α*(Z(μζ))*(l(ζ)+s1(ζ)+γ)*(r(ζ)+s2(ζ)+γ)*(o(ζ)+γ)
        computed_quotient = Fr.sub(computed_quotient, state.alpha_square_lagrange); // linearizedpolynomial+pi(zeta)+α*(Z(μζ))*(l(ζ)+s1(ζ)+γ)*(r(ζ)+s2(ζ)+γ)*(o(ζ)+γ)-α²*L₁(ζ)

        _s2 = Fr.mul(proof.quotient_polynomial_at_zeta, zeta_power_n_minus_one);
        
        // H(ζ)*(\zeta^{n}-1) ==?  lin_pol(\zeta)
        return computed_quotient == _s2;
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
            let folded_h := add(state, state_folded_h)
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
        v = Fr.mul(state.beta, proof.permutation_polynomials_at_zeta[0]);
        v = Fr.add(v, proof.wire_values_at_zeta[0]);
        v = Fr.add(v, state.gamma);

        w = Fr.mul(state.beta, proof.permutation_polynomials_at_zeta[1]);
        w = Fr.add(w, proof.wire_values_at_zeta[1]);
        w = Fr.add(w, state.gamma);

        uint256 _s1;
        _s1 = Fr.mul(u, v);
        _s1 = Fr.mul(_s1, w);
        _s1 = Fr.mul(_s1, state.alpha); // α*Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*β

        uint256 coset_square = Fr.mul(vk.coset_shift, vk.coset_shift);
        uint256 betazeta = Fr.mul(state.beta, state.zeta);
        u = Fr.add(betazeta, proof.wire_values_at_zeta[0]);
        u = Fr.add(u, state.gamma); // (l(ζ)+β*ζ+γ)

        v = Fr.mul(betazeta, vk.coset_shift);
        v = Fr.add(v, proof.wire_values_at_zeta[1]);
        v = Fr.add(v, state.gamma); // (r(ζ)+β*μ*ζ+γ)

        w = Fr.mul(betazeta, coset_square);
        w = Fr.add(w, proof.wire_values_at_zeta[2]);
        w = Fr.add(w, state.gamma); // (o(ζ)+β*μ²*ζ+γ)

        uint256 _s2 = Fr.mul(u, v);
        _s2 = Fr.mul(_s2, w);
        _s2 = Fr.sub(0, _s2);  // -(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
        _s2 = Fr.mul(_s2, state.alpha);
        _s2 = Fr.add(_s2, state.alpha_square_lagrange); // -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ) + α²*L₁(ζ)

        uint256 rl =  Fr.mul(proof.wire_values_at_zeta[0], proof.wire_values_at_zeta[1]);

        // multi exp part
        Bn254.G1Point memory linearised_polynomial;
        Bn254.G1Point memory sel_tmp;
        sel_tmp.X = vk.ql_com_x;
        sel_tmp.Y = vk.ql_com_y;
        linearised_polynomial = Bn254.point_mul(sel_tmp, proof.wire_values_at_zeta[0]);
        sel_tmp.X = vk.qr_com_x;
        sel_tmp.Y = vk.qr_com_y;
        Bn254.G1Point memory ptmp = Bn254.point_mul(sel_tmp, proof.wire_values_at_zeta[1]);
        linearised_polynomial = Bn254.point_add(linearised_polynomial, ptmp);

        sel_tmp.X = vk.qm_com_x;
        sel_tmp.Y = vk.qm_com_y;
        ptmp = Bn254.point_mul(sel_tmp, rl);
        linearised_polynomial = Bn254.point_add(linearised_polynomial, ptmp);

        sel_tmp.X = vk.qo_com_x;
        sel_tmp.Y = vk.qo_com_y;
        ptmp = Bn254.point_mul(sel_tmp, proof.wire_values_at_zeta[2]);
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

        ptmp = Bn254.point_mul(proof.grand_product_commitment, _s2);
        linearised_polynomial = Bn254.point_add(linearised_polynomial, ptmp);

        state.linearised_polynomial_x = linearised_polynomial.X;
        state.linearised_polynomial_y= linearised_polynomial.Y;

    }

    event PrintUint256(uint256 a);

    function fold_state(
        Types.State memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk
    ) internal view {

        // TODO if we don't copy manually the coordinates, can't manage to access memory lcoations with yul...
        Bn254.G1Point[] memory digests = new Bn254.G1Point[](7+vk.selector_commitments_commit_api.length);
        digests[0].X = state.folded_h_x;
        digests[0].Y = state.folded_h_y;
        digests[1].X = state.linearised_polynomial_x;
        digests[1].Y = state.linearised_polynomial_y;
        // Bn254.copy_g1(digests[2], proof.wire_commitments[0]);
        // Bn254.copy_g1(digests[3], proof.wire_commitments[1]);
        // Bn254.copy_g1(digests[4], proof.wire_commitments[2]);
        digests[2].X = proof.l_com_x;
        digests[2].Y = proof.l_com_y;

        digests[3].X = proof.r_com_x;
        digests[3].Y = proof.r_com_y;
        
        digests[4].X = proof.o_com_x;
        digests[4].Y = proof.o_com_y;
        
        digests[5].X = vk.s1_com_x;
        digests[5].Y = vk.s1_com_y;
        digests[6].X = vk.s2_com_x;
        digests[6].Y = vk.s2_com_y;
        for (uint i=0; i<vk.selector_commitments_commit_api.length; i++){
            Bn254.copy_g1(digests[i+7], vk.selector_commitments_commit_api[i]);
        }

        // TODO perhaps we should we inline all this
        Kzg.BatchOpeningProof memory batch_opening_proof;
        Bn254.copy_g1(batch_opening_proof.H, proof.opening_at_zeta_proof);
        batch_opening_proof.claimed_values = new uint256[](7+proof.selector_commit_api_at_zeta.length);
        batch_opening_proof.claimed_values[0] = proof.quotient_polynomial_at_zeta;
        batch_opening_proof.claimed_values[1] = proof.linearization_polynomial_at_zeta;
        batch_opening_proof.claimed_values[2] = proof.wire_values_at_zeta[0];
        batch_opening_proof.claimed_values[3] = proof.wire_values_at_zeta[1];
        batch_opening_proof.claimed_values[4] = proof.wire_values_at_zeta[2];
        batch_opening_proof.claimed_values[5] = proof.permutation_polynomials_at_zeta[0];
        batch_opening_proof.claimed_values[6] = proof.permutation_polynomials_at_zeta[1];
        //batch_opening_proof.claimed_values[7] = proof.qcprime_at_zeta;
        for (uint i=0; i<proof.selector_commit_api_at_zeta.length; i++){
            batch_opening_proof.claimed_values[7+i] = proof.selector_commit_api_at_zeta[i];
        }

        (state.folded_proof, state.folded_digests) = Kzg.fold_proof(
            digests, 
            batch_opening_proof,
            state.zeta);  
        
    } 

    function verify(Types.Proof memory proof, Types.VerificationKey memory vk, uint256[] memory public_inputs)
    internal view returns (bool) {

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
        Bn254.copy_g1(digests[1], proof.grand_product_commitment);
        
        Kzg.OpeningProof[] memory proofs = new Kzg.OpeningProof[](2);
        
        Kzg.copy_opening_proof(proofs[0], state.folded_proof);

        //Bn254.copy_g1(proofs[1].H, proof.opening_at_zeta_omega_proof);
        proofs[1].h_x = proof.opening_at_zeta_omega_proof.X;
        proofs[1].h_y = proof.opening_at_zeta_omega_proof.Y;
        proofs[1].claimed_value = proof.grand_product_at_zeta_omega;

        uint256[] memory points = new uint256[](2);
        points[0] = state.zeta;
        points[1] = Fr.mul(state.zeta, vk.omega);

        // emit PrintUint256(state.folded_digests.X);
        // emit PrintUint256(state.folded_digests.Y);
        // emit PrintUint256(state.folded_proof.h_x);
        // emit PrintUint256(state.folded_proof.h_y);
        // emit PrintUint256(state.folded_proof.claimed_value);

        valid = valid && Kzg.batch_verify_multi_points(digests, proofs, points, vk.g2_x);
        
        return valid;
    }
}

