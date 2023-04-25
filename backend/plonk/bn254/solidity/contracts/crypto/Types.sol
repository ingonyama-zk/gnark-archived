// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity >=0.6.0;

import {Bn254} from './Bn254.sol';
import {Kzg} from './Kzg.sol';

library Types {

    using Bn254 for *;
    using Kzg for *;

    int256 constant STATE_WIDTH = 3;

    struct VerificationKey {

        uint256 domain_size;
        uint256 omega;    // w
        uint256 ql_com_x;
        uint256 ql_com_y;
        uint256 qr_com_x;
        uint256 qr_com_y;
        uint256 qm_com_x;
        uint256 qm_com_y;
        uint256 qo_com_x;
        uint256 qo_com_y;
        uint256 qk_com_x;
        uint256 qk_com_y;

        uint256 s1_com_x; // [Sσ1(x)]
        uint256 s1_com_y;
        uint256 s2_com_x; // [Sσ2(x)]
        uint256 s2_com_y;
        uint256 s3_com_x; // [Sσ3(x)]
        uint256 s3_com_y;

        uint256 coset_shift;                                    // generator of Fr*
        Bn254.G2Point g2_x;                                     // SRS.G2[1]
        Bn254.G1Point[] selector_commitments_commit_api;        // [qcp_i]
        uint256[] commitment_indices;                           // indices of the public wires resulting from the hash.

    }

    struct Proof {
        
        uint256 l_com_x;
        uint256 l_com_y;
        uint256 r_com_x;
        uint256 r_com_y;
        uint256 o_com_x;
        uint256 o_com_y;

        Bn254.G1Point[STATE_WIDTH] quotient_poly_commitments;   // [t_lo]/[t_mid]/[t_hi]
        uint256[STATE_WIDTH] wire_values_at_zeta;               // a(zeta)/b(zeta)/c(zeta)
        uint256[STATE_WIDTH-1] permutation_polynomials_at_zeta; // Sσ1(zeta),Sσ2(zeta)
        Bn254.G1Point grand_product_commitment;                 // [z(x)]
        uint256 grand_product_at_zeta_omega;                    // z(w*zeta)
        uint256 quotient_polynomial_at_zeta;                    // t(zeta)
        uint256 linearization_polynomial_at_zeta;               // r(zeta)

        Bn254.G1Point opening_at_zeta_proof;            // [Wzeta]
        Bn254.G1Point opening_at_zeta_omega_proof;      // [Wzeta*omega]
        
        Bn254.G1Point[] wire_committed_commitments;             // commitment to the wires committed using Commit api
        uint256[] selector_commit_api_at_zeta;                  // qc_i(zeta)
    }

    struct State {
     
        // challenges to check the claimed quotient
        uint256 alpha;
        uint256 beta;
        uint256 gamma;
        uint256 zeta;

        // challenges related to KZG
        uint256 v;
        uint256 u;

        // reusable value
        uint256 alpha_square_lagrange;

        // commitment to H
        //Bn254.G1Point folded_h;
        uint256 folded_h_x;
        uint256 folded_h_y;

        // commitment to the linearised polynomial
        uint256 linearised_polynomial_x;
        uint256 linearised_polynomial_y;

        // Folded proof for the opening of H, linearised poly, l, r, o, s_1, s_2, qcp
        Kzg.OpeningProof folded_proof;

        // folded digests of H, linearised poly, l, r, o, s_1, s_2, qcp
        Bn254.G1Point folded_digests;

    }

}