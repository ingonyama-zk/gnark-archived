pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

// import {PlonkVerifier} from '../Verifier.sol';
// import {Types} from '../crypto/Types.sol';
// import {TranscriptLibrary} from '../crypto/Transcript.sol';
// import {Bn254} from '../crypto/Bn254.sol';
import {UtilsFr} from '../crypto/HashFr.sol';
import {Polynomials} from '../crypto/Polynomials.sol';
// import {Fr} from '../crypto/Fr.sol';
import {TestProof} from './TestProof.sol';

contract TestContract {

  using Polynomials for *;
  // using PlonkVerifier for *;
  // using Types for *;
  // using TranscriptLibrary for *;
  // using Fr for *;
  // using Bn254 for *;
  using UtilsFr for *;
  using TestProof for *;

  uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  uint256 constant p_mod = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

  uint256 constant g2_srs_0_x_0 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
  uint256 constant g2_srs_0_x_1 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
  uint256 constant g2_srs_0_y_0 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
  uint256 constant g2_srs_0_y_1 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

  // ----------------------- vk ---------------------

  uint256 constant vk_domain_size = 32;
  uint256 constant vk_inv_domain_size = 21204235282094297871551205565717985242031228012903033270457635305745314480129;
  uint256 constant vk_omega = 4419234939496763621076330863786513495701855246241724391626358375488475697872;
  uint256 constant vk_ql_com_x = 3249492299937356830250489011041180308067992016591401527068121784106989719648;
  uint256 constant vk_ql_com_y = 10459965615643388455781136436726437288800547058370943251873623010731177440661;
  uint256 constant vk_qr_com_x = 12510476613922141136476828275709042037770171239066681610748147345655672163851;
  uint256 constant vk_qr_com_y = 21702499139579688323831199788191067119894864133780232136805753631080002427269;
  uint256 constant vk_qm_com_x = 14953002130617700035755035451150408651119074291254331128989112575148233333491;
  uint256 constant vk_qm_com_y = 17892566681051922084336151301309366102531970850688837636319063607093137053627;
  uint256 constant vk_qo_com_x = 12510476613922141136476828275709042037770171239066681610748147345655672163851;
  uint256 constant vk_qo_com_y = 185743732259586898415205957066207968801447023517591525883284263565223781314;
  uint256 constant vk_qk_com_x = 14953002130617700035755035451150408651119074291254331128989112575148233333491;
  uint256 constant vk_qk_com_y = 3995676190787353137910254443947908986164340306608986026369974287552089154956;
  uint256 constant vk_s1_com_x = 21855018542748430565529761638971558125245342907512256948393636927196567938581;
  uint256 constant vk_s1_com_y = 11712367707713868753009749003773415568950091810241040629437353992390346924664;
  uint256 constant vk_s2_com_x = 17771334109737095158037840313408192145908096951666120454569319380122548644876;
  uint256 constant vk_s2_com_y = 1557548382852739357942435662406820815086929855797636868167313245414326520716;
  uint256 constant vk_s3_com_x = 3042622247313413937841956962385471739016337091363862127586520834001367730368;
  uint256 constant vk_s3_com_y = 11237012146990418046605498478831176936003562652049794077037238123223985118834;

  uint256 constant vk_coset_shift = 5;

  uint256 constant vk_selector_commitments_commit_api_0_x = 6072894980673347906024769411958097208049504128219463716820120075337948200814;
  uint256 constant vk_selector_commitments_commit_api_0_y = 19560123544018144421880384701499189813392268921297788713816469086064585937291;

  function load_vk_commitments_indices_commit_api(uint256[] memory v)
  internal view {
    assembly {
      let _v := add(v, 0x20)
      mstore(_v, 3)
    }
  }

  uint256 constant g2_srs_1_x_0 = 4777846902900565418590449384753263717909657903692016614099552076160357595620;
  uint256 constant g2_srs_1_y_0 = 3861286923073220011793349409046889289349533020715526625969101603056608090795;
  uint256 constant g2_srs_1_x_1 = 16406754891999554747479650379038048271643900448173543122927661446988296543616;
  uint256 constant g2_srs_1_y_1 = 21022748302362729781528857183979865986597752242747307653138221198529458362155;

  uint256 constant vk_nb_commitments_commit_api = 1;

  // ------------------------------------------------

  // offset proof
  uint256 constant proof_l_com_x = 0x20;
  uint256 constant proof_l_com_y = 0x40;
  uint256 constant proof_r_com_x = 0x60;
  uint256 constant proof_r_com_y = 0x80;
  uint256 constant proof_o_com_x = 0xa0;
  uint256 constant proof_o_com_y = 0xc0;

  // h = h_0 + x^{n+2}h_1 + x^{2(n+2)}h_2
  uint256 constant proof_h_0_x = 0xe0; 
  uint256 constant proof_h_0_y = 0x100;
  uint256 constant proof_h_1_x = 0x120;
  uint256 constant proof_h_1_y = 0x140;
  uint256 constant proof_h_2_x = 0x160;
  uint256 constant proof_h_2_y = 0x180;

  // wire values at zeta
  uint256 constant proof_l_at_zeta = 0x1a0;
  uint256 constant proof_r_at_zeta = 0x1c0;
  uint256 constant proof_o_at_zeta = 0x1e0;

  //uint256[STATE_WIDTH-1] permutation_polynomials_at_zeta; // Sσ1(zeta),Sσ2(zeta)
  uint256 constant proof_s1_at_zeta = 0x200; // Sσ1(zeta)
  uint256 constant proof_s2_at_zeta = 0x220; // Sσ2(zeta)

  //Bn254.G1Point grand_product_commitment;                 // [z(x)]
  uint256 constant proof_grand_product_commitment_x = 0x240;
  uint256 constant proof_grand_product_commitment_y = 0x260;

  uint256 constant proof_grand_product_at_zeta_omega = 0x280;                    // z(w*zeta)
  uint256 constant proof_quotient_polynomial_at_zeta = 0x2a0;                    // t(zeta)
  uint256 constant proof_linearization_polynomial_at_zeta = 0x2c0;               // r(zeta)

  // Folded proof for the opening of H, linearised poly, l, r, o, s_1, s_2, qcp
  uint256 constant proof_batch_opening_at_zeta_x = 0x2e0;            // [Wzeta]
  uint256 constant proof_batch_opening_at_zeta_y = 0x300;

  //Bn254.G1Point opening_at_zeta_omega_proof;      // [Wzeta*omega]
  uint256 constant proof_opening_at_zeta_omega_x = 0x320;
  uint256 constant proof_opening_at_zeta_omega_y = 0x340;
  
  uint256 constant proof_openings_selector_commit_api_at_zeta = 0x360;
  // -> next part of proof is 
  // [ openings_selector_commits || commitments_wires_commit_api]

  // -------- offset state

  // challenges to check the claimed quotient
  uint256 constant state_alpha = 0x00;
  uint256 constant state_beta = 0x20;
  uint256 constant state_gamma = 0x40;
  uint256 constant state_zeta = 0x60;

  // challenges related to KZG
  uint256 constant state_sv = 0x80;
  uint256 constant state_su = 0xa0;

  // reusable value
  uint256 constant state_alpha_square_lagrange = 0xc0;

  // commitment to H
  // Bn254.G1Point folded_h;
  uint256 constant state_folded_h_x = 0xe0;
  uint256 constant state_folded_h_y = 0x100;

  // commitment to the linearised polynomial
  uint256 constant state_linearised_polynomial_x = 0x120;
  uint256 constant state_linearised_polynomial_y = 0x140;

  // Folded proof for the opening of H, linearised poly, l, r, o, s_1, s_2, qcp
  // Kzg.OpeningProof folded_proof;
  uint256 constant state_folded_claimed_values = 0x160;

  // folded digests of H, linearised poly, l, r, o, s_1, s_2, qcp
  // Bn254.G1Point folded_digests;
  uint256 constant state_folded_digests_x = 0x180;
  uint256 constant state_folded_digests_y = 0x1a0;

  uint256 constant state_pi = 0x1c0;

  uint256 constant state_zeta_power_n_minus_one = 0x1e0;
  uint256 constant state_alpha_square_lagrange_one = 0x200;

  uint256 constant state_gamma_kzg = 0x220;

  uint256 constant state_success = 0x240;
  uint256 constant state_check_pairing = 0x260;


  uint256 constant state_last_mem = 0x280;

  event PrintBool(bool a);
  event PrintUint256(uint256 a);
  event PrintBytes(bytes a);
  event PrintBytes32(bytes32 a);

  function derive_gamma_beta_alpha_zeta(bytes memory proof, uint256[] memory public_inputs)
  internal returns(uint256, uint256, uint256, uint256) {

    uint256 gamma;
    uint256 beta;
    uint256 alpha;
    uint256 zeta;

    assembly {

      let mem := mload(0x40)

      derive_gamma(proof, public_inputs)
      gamma := mload(mem)

      derive_beta(proof, gamma)
      beta := mload(mem)

      derive_alpha(proof, beta)
      alpha := mload(mem)

      derive_zeta(proof, alpha)
      zeta := mload(mem)

      gamma := mod(gamma, r_mod)
      beta := mod(beta, r_mod)
      alpha := mod(alpha, r_mod)
      zeta := mod(zeta, r_mod)

      function derive_gamma(aproof, pub_inputs) {
        
        let mPtr := mload(0x40)

        // gamma
        mstore(mPtr, 0x67616d6d61) // "gamma"

        mstore(add(mPtr, 0x20), vk_s1_com_x)
        mstore(add(mPtr, 0x40), vk_s1_com_y)
        mstore(add(mPtr, 0x60), vk_s2_com_x)
        mstore(add(mPtr, 0x80), vk_s2_com_y)
        mstore(add(mPtr, 0xa0), vk_s3_com_x)
        mstore(add(mPtr, 0xc0), vk_s3_com_y)
        mstore(add(mPtr, 0xe0), vk_ql_com_x)
        mstore(add(mPtr, 0x100), vk_ql_com_y)
        mstore(add(mPtr, 0x120), vk_qr_com_x)
        mstore(add(mPtr, 0x140), vk_qr_com_y)
        mstore(add(mPtr, 0x160), vk_qm_com_x)
        mstore(add(mPtr, 0x180), vk_qm_com_y)
        mstore(add(mPtr, 0x1a0), vk_qo_com_x)
        mstore(add(mPtr, 0x1c0), vk_qo_com_y)
        mstore(add(mPtr, 0x1e0), vk_qk_com_x)
        mstore(add(mPtr, 0x200), vk_qk_com_y)

        let pi := add(pub_inputs, 0x20)
        let _mPtr := add(mPtr, 0x220)
        for {let i:=0} lt(i, mload(pub_inputs)) {i:=add(i,1)}
        {
          mstore(_mPtr, mload(pi))
          pi := add(pi, 0x20)
          _mPtr := add(_mPtr, 0x20)
        }

        let _proof := add(aproof, proof_openings_selector_commit_api_at_zeta)
        _proof := add(_proof, mul(vk_nb_commitments_commit_api, 0x20))
        for {let i:=0} lt(i, vk_nb_commitments_commit_api) {i:=add(i,1)}
        {
          mstore(_mPtr, mload(_proof))
          mstore(add(_mPtr, 0x20), mload(add(_proof, 0x20)))
          _mPtr := add(_mPtr, 0x40)
          _proof := add(_proof, 0x40)
        }

        mstore(_mPtr, mload(add(aproof, proof_l_com_x)))
        mstore(add(_mPtr, 0x20), mload(add(aproof, proof_l_com_y)))
        mstore(add(_mPtr, 0x40), mload(add(aproof, proof_r_com_x)))
        mstore(add(_mPtr, 0x60), mload(add(aproof, proof_r_com_y)))
        mstore(add(_mPtr, 0x80), mload(add(aproof, proof_o_com_x)))
        mstore(add(_mPtr, 0xa0), mload(add(aproof, proof_o_com_y)))

        let size := add(0x2c5, mul(mload(pub_inputs), 0x20)) // 0x2c5 = 22*32+5
        size := add(size, mul(vk_nb_commitments_commit_api, 0x40))
        pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr, 0x1b), size, mPtr, 0x20)) //0x1b -> 000.."gamma"
      }

      function derive_beta(aproof, prev_challenge){
        let mPtr := mload(0x40)
        // beta
        mstore(mPtr, 0x62657461) // "beta"
        mstore(add(mPtr, 0x20), prev_challenge)
        pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr, 0x1c), 0x24, mPtr, 0x20)) //0x1b -> 000.."gamma"
      }

      function derive_alpha(aproof, prev_challenge){
        let mPtr := mload(0x40)
        // alpha
        mstore(mPtr, 0x616C706861) // "alpha"
        mstore(add(mPtr, 0x20), prev_challenge)
        mstore(add(mPtr, 0x40), mload(add(aproof, proof_grand_product_commitment_x)))
        mstore(add(mPtr, 0x60), mload(add(aproof, proof_grand_product_commitment_y)))
        pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr, 0x1b), 0x65, mPtr, 0x20)) //0x1b -> 000.."gamma"
      }

      function derive_zeta(aproof, prev_challenge) {
        let mPtr := mload(0x40)
        // zeta
        mstore(mPtr, 0x7a657461) // "zeta"
        mstore(add(mPtr, 0x20), prev_challenge)
        mstore(add(mPtr, 0x40), mload(add(aproof, proof_h_0_x)))
        mstore(add(mPtr, 0x60), mload(add(aproof, proof_h_0_y)))
        mstore(add(mPtr, 0x80), mload(add(aproof, proof_h_1_x)))
        mstore(add(mPtr, 0xa0), mload(add(aproof, proof_h_1_y)))
        mstore(add(mPtr, 0xc0), mload(add(aproof, proof_h_2_x)))
        mstore(add(mPtr, 0xe0), mload(add(aproof, proof_h_2_y)))
        pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr, 0x1c), 0xe4, mPtr, 0x20))
      }
    }

    return (gamma, beta, alpha, zeta);
  }

  function load_wire_commitments_commit_api(uint256[] memory wire_commitments, bytes memory proof)
  internal {
    assembly {
      let w := add(wire_commitments, 0x20)
      let p := add(proof, proof_openings_selector_commit_api_at_zeta)
      p := add(p, mul(vk_nb_commitments_commit_api, 0x20))
      for {let i:=0} lt(i, mul(vk_nb_commitments_commit_api,2)) {i:=add(i,1)}
      {
        mstore(w, mload(p))
        w := add(w,0x20)
        p := add(p,0x20)
        mstore(w, mload(p))
        w := add(w,0x20)
        p := add(p,0x20)
      }
    }
  }

  function compute_ith_lagrange_at_z(uint256 zeta, uint256 i) 
  internal returns (uint256) {

    uint256 res;
    assembly {

      // _n^_i [r]
      function pow_local(x, e)->result {
          let mPtr := mload(0x40)
          mstore(mPtr, 0x20)
          mstore(add(mPtr, 0x20), 0x20)
          mstore(add(mPtr, 0x40), 0x20)
          mstore(add(mPtr, 0x60), x)
          mstore(add(mPtr, 0x80), e)
          mstore(add(mPtr, 0xa0), r_mod)
          pop(staticcall(sub(gas(), 2000),0x05,mPtr,0xc0,0x00,0x20))
          result := mload(0x00)
      }

      let w := pow_local(vk_omega,i) // w**i
      i := addmod(zeta, sub(r_mod, w), r_mod) // z-w**i
      zeta := pow_local(zeta, vk_domain_size) // z**n
      zeta := addmod(zeta, sub(r_mod, 1), r_mod) // z**n-1
      w := mulmod(w, vk_inv_domain_size, r_mod) // w**i/n
      i := pow_local(i, sub(r_mod,2)) // (z-w**i)**-1
      w := mulmod(w, i, r_mod) // w**i/n*(z-w)**-1
      res := mulmod(w, zeta, r_mod)
    }
    
    return res;
  }

  function compute_pi(
        bytes memory proof,
        uint256[] memory public_inputs,
        uint256 zeta
    ) internal returns (uint256) {

        // evaluation of Z=Xⁿ⁻¹ at ζ
        // uint256 zeta_power_n_minus_one = Fr.pow(zeta, vk_domain_size);
        // zeta_power_n_minus_one = Fr.sub(zeta_power_n_minus_one, 1);
        uint256 zeta_power_n_minus_one;

        assembly {
          // _n^_i [r]
          function pow_local(x, e)->result {
            let mPtr := mload(0x40)
            mstore(mPtr, 0x20)
            mstore(add(mPtr, 0x20), 0x20)
            mstore(add(mPtr, 0x40), 0x20)
            mstore(add(mPtr, 0x60), x)
            mstore(add(mPtr, 0x80), e)
            mstore(add(mPtr, 0xa0), r_mod)
            pop(staticcall(sub(gas(), 2000),0x05,mPtr,0xc0,0x00,0x20))
            result := mload(0x00)
          }
          zeta_power_n_minus_one := pow_local(zeta, vk_domain_size)
          zeta_power_n_minus_one := addmod(zeta_power_n_minus_one, sub(r_mod, 1), r_mod)
        }

        // compute PI = ∑_{i<n} Lᵢ*wᵢ
        uint256 pi = Polynomials.compute_sum_li_zi(public_inputs, zeta, vk_omega, vk_domain_size);
        
        uint256[] memory commitment_indices = new uint256[](vk_nb_commitments_commit_api);
        load_vk_commitments_indices_commit_api(commitment_indices);
    
        if (vk_nb_commitments_commit_api > 0) {

          uint256[] memory wire_committed_commitments;
          wire_committed_commitments = new uint256[](2*vk_nb_commitments_commit_api);
          load_wire_commitments_commit_api(wire_committed_commitments, proof);

          string memory dst = "BSB22-Plonk";

          for (uint256 i=0; i<vk_nb_commitments_commit_api; i++){
              
              uint256 hash_res = UtilsFr.hash_fr(wire_committed_commitments[2*i], wire_committed_commitments[2*i+1], dst);
              uint256 a = compute_ith_lagrange_at_z(zeta, commitment_indices[i]+public_inputs.length);
              assembly {
                a := mulmod(hash_res, a, r_mod)
                pi := addmod(pi, a, r_mod)
              }
          }
        }
        
        return pi;
    }

  function test_assembly() 
  public {

    uint256[] memory public_inputs = new uint256[](3);
    public_inputs[0] = 6;
    public_inputs[1] = 7;
    public_inputs[2] = 8;
    
    bytes memory proof = TestProof.get_proof();

    verify_bis(proof, public_inputs);

  }

  function verify_bis(bytes memory proof, uint256[] memory public_inputs) 
  internal returns(bool) {

    uint256 gamma;
    uint256 beta;
    uint256 alpha;
    uint256 zeta;

    (gamma, beta, alpha, zeta) = derive_gamma_beta_alpha_zeta(proof, public_inputs);

    uint256 pi = compute_pi(proof, public_inputs, zeta);

    uint256 check;

    bool success = false;
    // uint256 success;

    assembly {

      let mem := mload(0x40)
      mstore(add(mem, state_alpha), alpha)
      mstore(add(mem, state_gamma), gamma)
      mstore(add(mem, state_zeta), zeta)
      mstore(add(mem, state_beta), beta)
      mstore(add(mem, state_pi), pi)

      compute_alpha_square_lagrange()
      verify_quotient_poly_eval_at_zeta(proof)
      fold_h(proof)
      compute_commitment_linearised_polynomial(proof)
      compute_gamma_kzg(proof)
      fold_state(proof)
      batch_verify_multi_points(proof)

      success := mload(add(mem, state_success))
      
      check := mload(add(mem,state_check_pairing))

      function compute_alpha_square_lagrange() {   
        let state := mload(0x40)
        let mPtr := add(mload(0x40), state_last_mem)

        // zeta**n - 1
        let res := pow(mload(add(state, state_zeta)), vk_domain_size, mPtr)
        res := addmod(res, sub(r_mod,1), r_mod)
        mstore(add(state, state_zeta_power_n_minus_one), res)

        // let res := mload(add(state, state_zeta_power_n_minus_one))
        let den := addmod(mload(add(state, state_zeta)), sub(r_mod, 1), r_mod)
        den := pow(den, sub(r_mod, 2), mPtr)
        den := mulmod(den, vk_inv_domain_size, r_mod)
        res := mulmod(den, res, r_mod)

        let l_alpha := mload(add(state, state_alpha))
        res := mulmod(res, l_alpha, r_mod)
        res := mulmod(res, l_alpha, r_mod)
        mstore(add(state, state_alpha_square_lagrange), res)
      }

      function batch_verify_multi_points(aproof) {

        let state := mload(0x40)
        let mPtr := add(state, state_last_mem)

        let random := 3

        let folded_quotients := mPtr
        mPtr := add(folded_quotients, 0x40)
        mstore(folded_quotients, mload(add(aproof, proof_batch_opening_at_zeta_x)))
        mstore(add(folded_quotients, 0x20), mload(add(aproof, proof_batch_opening_at_zeta_y)))
        point_acc_mul(folded_quotients, add(aproof, proof_opening_at_zeta_omega_x), random, mPtr)

        let folded_digests := add(state, state_folded_digests_x)
        point_acc_mul(folded_digests, add(aproof, proof_grand_product_commitment_x), random, mPtr)

        let folded_evals := add(state, state_folded_claimed_values)
        fr_acc_mul(folded_evals, add(aproof, proof_grand_product_at_zeta_omega), random)

        let folded_evals_commit := mPtr
        mPtr := add(folded_evals_commit, 0x40)
        mstore(folded_evals_commit, 0x1)
        mstore(add(folded_evals_commit, 0x20), 0x2)
        mstore(add(folded_evals_commit, 0x40), mload(folded_evals))
        pop(staticcall(sub(gas(), 2000),7,folded_evals_commit,0x60,folded_evals_commit,0x40))

        let folded_evals_commit_y := add(folded_evals_commit, 0x20)
        mstore(folded_evals_commit_y, sub(p_mod, mload(folded_evals_commit_y)))
        point_add(folded_digests, folded_digests, folded_evals_commit, mPtr)

        let folded_points_quotients := mPtr
        mPtr := add(mPtr, 0x40)
        point_mul(folded_points_quotients, add(aproof, proof_batch_opening_at_zeta_x), mload(add(state, state_zeta)), mPtr)
        let zeta_omega := mulmod(mload(add(state, state_zeta)), vk_omega, r_mod)
        random := mulmod(random, zeta_omega, r_mod)
        point_acc_mul(folded_points_quotients, add(aproof, proof_opening_at_zeta_omega_x), random, mPtr)

        point_add(folded_digests, folded_digests, folded_points_quotients, mPtr)

        let folded_quotients_y := add(folded_quotients, 0x20)
        mstore(folded_quotients_y, sub(p_mod, mload(folded_quotients_y)))
        mstore(add(state, state_check_pairing), mload(add(folded_digests, 0x20)))

        mstore(mPtr, mload(folded_digests))
        mstore(add(mPtr, 0x20), mload(add(folded_digests, 0x20)))
        mstore(add(mPtr, 0x40), g2_srs_0_x_0) // the 4 lines are the canonical G2 point on BN254
        mstore(add(mPtr, 0x60), g2_srs_0_x_1)
        mstore(add(mPtr, 0x80), g2_srs_0_y_0)
        mstore(add(mPtr, 0xa0), g2_srs_0_y_1)
        mstore(add(mPtr, 0xc0), mload(folded_quotients))
        mstore(add(mPtr, 0xe0), mload(add(folded_quotients, 0x20)))
        mstore(add(mPtr, 0x100), g2_srs_1_x_0)
        mstore(add(mPtr, 0x120), g2_srs_1_x_1)
        mstore(add(mPtr, 0x140), g2_srs_1_y_0)
        mstore(add(mPtr, 0x160), g2_srs_1_y_1)
        let l_success := staticcall(sub(gas(), 2000),8,mPtr,0x180,0x00,0x20)
        // l_success := true
        // mstore(add(state, state_success), and(l_success,mload(add(state, state_success))))
        // mstore(add(state, state_success), l_success)
        // mstore(add(state, state_check_pairing), mload(mPtr))
      }

      // at this stage the state of mPtr is the same as in compute_gamma
      function fold_state(aproof) {
        
        let state := mload(0x40)
        let mPtr := add(mload(0x40), state_last_mem)

        let l_gamma_kzg := mload(add(state, state_gamma_kzg))
        let acc_gamma := l_gamma_kzg

        let offset := add(0x200, mul(vk_nb_commitments_commit_api, 0x40)) // 0x40 = 2*0x20
        let mPtrOffset := add(mPtr, offset)

        mstore(add(state, state_folded_digests_x), mload(add(mPtr,0x40)))
        mstore(add(state, state_folded_digests_y), mload(add(mPtr,0x60)))
        mstore(add(state, state_folded_claimed_values), mload(add(aproof, proof_quotient_polynomial_at_zeta)))

        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0x80), acc_gamma, mPtrOffset)
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_linearization_polynomial_at_zeta), acc_gamma)
        mstore(add(state, state_check_pairing), acc_gamma)
        
        acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0xc0), acc_gamma, mPtrOffset)
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_l_at_zeta), acc_gamma)
        
        acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0x100), acc_gamma, add(mPtr, offset))
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_r_at_zeta), acc_gamma)

        acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0x140), acc_gamma, add(mPtr, offset))
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_o_at_zeta), acc_gamma)
        
        acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0x180), acc_gamma, add(mPtr, offset))
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_s1_at_zeta), acc_gamma)
        
        acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0x1c0), acc_gamma, add(mPtr, offset))
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_s2_at_zeta), acc_gamma)
        
        let poscaz := add(aproof, proof_openings_selector_commit_api_at_zeta)
        let opca := add(mPtr, 0x200) // offset_proof_commits_api
        for {let i := 0} lt(i, vk_nb_commitments_commit_api) {i:=add(i,1)}
        {
          acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
          point_acc_mul(add(state, state_folded_digests_x), opca, acc_gamma, add(mPtr, offset))
          fr_acc_mul(add(state, state_folded_claimed_values), poscaz, acc_gamma)
          poscaz := add(poscaz, 0x20)
          opca := add(opca, 0x40)
        }

      }

      function compute_gamma_kzg(aproof) {

        let state := mload(0x40)
        let mPtr := add(mload(0x40), state_last_mem)
        mstore(mPtr, 0x67616d6d61) // "gamma"
        mstore(add(mPtr, 0x20), mload(add(state, state_zeta)))
        mstore(add(mPtr,0x40), mload(add(state, state_folded_h_x)))
        mstore(add(mPtr,0x60), mload(add(state, state_folded_h_y)))
        mstore(add(mPtr,0x80), mload(add(state, state_linearised_polynomial_x)))
        mstore(add(mPtr,0xa0), mload(add(state, state_linearised_polynomial_y)))
        mstore(add(mPtr,0xc0), mload(add(aproof, proof_l_com_x)))
        mstore(add(mPtr,0xe0), mload(add(aproof, proof_l_com_y)))
        mstore(add(mPtr,0x100), mload(add(aproof, proof_r_com_x)))
        mstore(add(mPtr,0x120), mload(add(aproof, proof_r_com_y)))
        mstore(add(mPtr,0x140), mload(add(aproof, proof_o_com_x)))
        mstore(add(mPtr,0x160), mload(add(aproof, proof_o_com_y)))
        mstore(add(mPtr,0x180), vk_s1_com_x)
        mstore(add(mPtr,0x1a0), vk_s1_com_y)
        mstore(add(mPtr,0x1c0), vk_s2_com_x)
        mstore(add(mPtr,0x1e0), vk_s2_com_y)
        
        // TODO this part needs to be auto generated
        let offset := 0x200
        mstore(add(mPtr,offset), vk_selector_commitments_commit_api_0_x)
        mstore(add(mPtr,add(offset, 0x20)), vk_selector_commitments_commit_api_0_y)

        let start_input := 0x1b // 00.."gamma"
        let size_input := add(0xf, mul(vk_nb_commitments_commit_api,2)) // number of 32bytes elmts = 15 (zeta+2*7 for the digests) + 2*vk_nb_commitments_commit_api
        size_input := add(0x5, mul(size_input, 0x20)) // size in bytes: 15*32 bytes + 5 bytes for gamma
        pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr,start_input), size_input, add(state, state_gamma_kzg), 0x20))
        mstore(add(state, state_gamma_kzg), mod(mload(add(state, state_gamma_kzg)), r_mod))

      }

      function compute_commitment_linearised_polynomial_ec(aproof, s1, s2) {

        let state := mload(0x40)
        let mPtr := add(mload(0x40), state_last_mem)

        mstore(mPtr, vk_ql_com_x)
        mstore(add(mPtr,0x20), vk_ql_com_y)
        point_mul(add(state, state_linearised_polynomial_x), mPtr, mload(add(aproof, proof_l_at_zeta)), add(mPtr,0x40))

        mstore(mPtr, vk_qr_com_x)
        mstore(add(mPtr,0x20), vk_qr_com_y)
        point_acc_mul(add(state, state_linearised_polynomial_x),mPtr,mload(add(aproof, proof_r_at_zeta)),add(mPtr,0x40))
        
        let rl := mulmod(mload(add(aproof, proof_l_at_zeta)), mload(add(aproof, proof_r_at_zeta)), r_mod)
        mstore(mPtr, vk_qm_com_x)
        mstore(add(mPtr,0x20), vk_qm_com_y)
        point_acc_mul(add(state, state_linearised_polynomial_x),mPtr,rl,add(mPtr,0x40))
        
        mstore(mPtr, vk_qo_com_x)
        mstore(add(mPtr,0x20), vk_qo_com_y)
        point_acc_mul(add(state, state_linearised_polynomial_x),mPtr,mload(add(aproof, proof_o_at_zeta)),add(mPtr,0x40))
        
        mstore(mPtr, vk_qk_com_x)
        mstore(add(mPtr, 0x20), vk_qk_com_y)
        point_add(add(state, state_linearised_polynomial_x),add(state, state_linearised_polynomial_x),mPtr,add(mPtr, 0x40))

        let commits_api_at_zeta := add(aproof, proof_openings_selector_commit_api_at_zeta)
        let commits_api := add(aproof, add(proof_openings_selector_commit_api_at_zeta, mul(vk_nb_commitments_commit_api, 0x20)))
        for {let i:=0} lt(i, vk_nb_commitments_commit_api) {i:=add(i,1)}
        {
          mstore(mPtr, mload(commits_api))
          mstore(add(mPtr, 0x20), mload(add(commits_api, 0x20)))
          point_acc_mul(add(state, state_linearised_polynomial_x),mPtr,mload(commits_api_at_zeta),add(mPtr,0x40))
          commits_api_at_zeta := add(commits_api_at_zeta, 0x20)
          commits_api := add(commits_api, 0x40)
        }

        mstore(mPtr, vk_s3_com_x)
        mstore(add(mPtr, 0x20), vk_s3_com_y)
        point_acc_mul(add(state, state_linearised_polynomial_x), mPtr, s1, add(mPtr, 0x40))

        mstore(mPtr, mload(add(aproof, proof_grand_product_commitment_x)))
        mstore(add(mPtr, 0x20), mload(add(aproof, proof_grand_product_commitment_y)))
        point_acc_mul(add(state, state_linearised_polynomial_x), mPtr, s2, add(mPtr, 0x40))

      }

      function compute_commitment_linearised_polynomial(aproof) {
        
        let state := mload(0x40)
        let l_beta := mload(add(state, state_beta))
        let l_gamma := mload(add(state, state_gamma))
        let l_zeta := mload(add(state, state_zeta))
        let l_alpha := mload(add(state, state_alpha))

        let u := mulmod(mload(add(aproof,proof_grand_product_at_zeta_omega)), l_beta, r_mod)
        let v := mulmod(l_beta, mload(add(aproof, proof_s1_at_zeta)), r_mod)
        v := addmod(v, mload(add(aproof, proof_l_at_zeta)), r_mod)
        v := addmod(v, l_gamma, r_mod)

        let w := mulmod(l_beta, mload(add(aproof, proof_s2_at_zeta)), r_mod)
        w := addmod(w, mload(add(aproof, proof_r_at_zeta)), r_mod)
        w := addmod(w, l_gamma, r_mod)

        let s1 := mulmod(u, v, r_mod)
        s1 := mulmod(s1, w, r_mod)
        s1 := mulmod(s1, l_alpha, r_mod)

        let coset_square := mulmod(vk_coset_shift, vk_coset_shift, r_mod)
        let betazeta := mulmod(l_beta, l_zeta, r_mod)
        u := addmod(betazeta, mload(add(aproof, proof_l_at_zeta)), r_mod)
        u := addmod(u, l_gamma, r_mod)

        v := mulmod(betazeta, vk_coset_shift, r_mod)
        v := addmod(v, mload(add(aproof, proof_r_at_zeta)), r_mod)
        v := addmod(v, l_gamma, r_mod)

        w := mulmod(betazeta, coset_square, r_mod)
        w := addmod(w, mload(add(aproof, proof_o_at_zeta)), r_mod)
        w := addmod(w, l_gamma, r_mod)

        let s2 := mulmod(u, v, r_mod)
        s2 := mulmod(s2, w, r_mod)
        s2 := sub(r_mod, s2)
        s2 := mulmod(s2, l_alpha, r_mod)
        s2 := addmod(s2, mload(add(state, state_alpha_square_lagrange)), r_mod)

        compute_commitment_linearised_polynomial_ec(aproof, s1, s2)
      }

      function fold_h(aproof) {
        let state := mload(0x40)
        let n_plus_two := add(vk_domain_size, 2)
        let mPtr := add(mload(0x40), state_last_mem)
        let zeta_power_n_plus_two := pow(mload(add(state, state_zeta)), n_plus_two, mPtr)
        point_mul(add(state, state_folded_h_x), add(aproof, proof_h_2_x), zeta_power_n_plus_two, mPtr)
        point_add(add(state, state_folded_h_x), add(state, state_folded_h_x), add(aproof, proof_h_1_x), mPtr)
        point_mul(add(state, state_folded_h_x), add(state, state_folded_h_x), zeta_power_n_plus_two, mPtr)
        point_add(add(state, state_folded_h_x), add(state, state_folded_h_x), add(aproof, proof_h_0_x), mPtr)
      }

      function verify_quotient_poly_eval_at_zeta(aproof) {

        let state := mload(0x40)

        // (l(ζ)+β*s1(ζ)+γ)
        let s1 := add(mload(0x40), state_last_mem)
        mstore(s1, mulmod(mload(add(aproof,proof_s1_at_zeta)),mload(add(state, state_beta)), r_mod))
        mstore(s1, addmod(mload(s1), mload(add(state, state_gamma)), r_mod))
        mstore(s1, addmod(mload(s1), mload(add(aproof, proof_l_at_zeta)), r_mod))

        // (r(ζ)+β*s2(ζ)+γ)
        let s2 := add(s1,0x20)
        mstore(s2, mulmod(mload(add(aproof,proof_s2_at_zeta)),mload(add(state, state_beta)), r_mod))
        mstore(s2, addmod(mload(s2), mload(add(state, state_gamma)), r_mod))
        mstore(s2, addmod(mload(s2), mload(add(aproof, proof_r_at_zeta)), r_mod))
        // _s2 := mload(s2)

        // (o(ζ)+γ)
        let o := add(s1,0x40)
        mstore(o, addmod(mload(add(aproof,proof_o_at_zeta)), mload(add(state, state_gamma)), r_mod))

        //  α*(Z(μζ))*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(o(ζ)+γ)
        mstore(s1, mulmod(mload(s1), mload(s2), r_mod))
        mstore(s1, mulmod(mload(s1), mload(o), r_mod))
        mstore(s1, mulmod(mload(s1), mload(add(state, state_alpha)), r_mod))
        mstore(s1, mulmod(mload(s1), mload(add(aproof, proof_grand_product_at_zeta_omega)), r_mod))

        let computed_quotient := add(s1,0x60)

        // linearizedpolynomial + pi(zeta)
        mstore(computed_quotient, addmod(mload(add(aproof, proof_linearization_polynomial_at_zeta)), mload(add(state, state_pi)), r_mod))
        mstore(computed_quotient, addmod(mload(computed_quotient), mload(s1), r_mod))
        mstore(computed_quotient, addmod(mload(computed_quotient), sub(r_mod,mload(add(state, state_alpha_square_lagrange))), r_mod))
        mstore(s2, mulmod(mload(add(aproof,proof_quotient_polynomial_at_zeta)), mload(add(state, state_zeta_power_n_minus_one)), r_mod))
        mstore(add(state, state_success), mload(computed_quotient))

        mstore(add(state, state_success),eq(mload(computed_quotient), mload(s2)))
      }

      function point_add(dst, p, q, mPtr) {
        // let mPtr := add(mload(0x40), state_last_mem)
        let state := mload(0x40)
        mstore(mPtr, mload(p))
        mstore(add(mPtr, 0x20), mload(add(p, 0x20)))
        mstore(add(mPtr, 0x40), mload(q))
        mstore(add(mPtr, 0x60), mload(add(q, 0x20)))
        let l_success := staticcall(sub(gas(), 2000),6,mPtr,0x80,dst,0x40)
        mstore(add(state, state_success), and(l_success,mload(add(state, state_success))))
      }

      // dst <- [s]src
      function point_mul(dst,src,s, mPtr) {
        // let mPtr := add(mload(0x40), state_last_mem)
        let state := mload(0x40)
        mstore(mPtr,mload(src))
        mstore(add(mPtr,0x20),mload(add(src,0x20)))
        mstore(add(mPtr,0x40),s)
        let l_success := staticcall(sub(gas(), 2000),7,mPtr,0x60,dst,0x40)
        mstore(add(state, state_success), and(l_success,mload(add(state, state_success))))
      }

      // dst <- dst + [s]src (Elliptic curve)
      function point_acc_mul(dst,src,s, mPtr) {
        let state := mload(0x40)
        mstore(mPtr,mload(src))
        mstore(add(mPtr,0x20),mload(add(src,0x20)))
        mstore(add(mPtr,0x40),s)
        let l_success := staticcall(sub(gas(), 2000),7,mPtr,0x60,mPtr,0x40)
        mstore(add(mPtr,0x40),mload(dst))
        mstore(add(mPtr,0x60),mload(add(dst,0x20)))
        l_success := and(l_success, staticcall(sub(gas(), 2000),6,mPtr,0x80,dst, 0x40))
        mstore(add(state, state_success), and(l_success,mload(add(state, state_success))))
      }

      // dst <- dst + src (Fr) dst,src are addresses, s is a value
      function fr_acc_mul(dst, src, s) {
        let tmp :=  mulmod(mload(src), s, r_mod)
        mstore(dst, addmod(mload(dst), tmp, r_mod))
      }

      // dst <- x ** e mod r (x, e are values, not pointers)
      function pow(x, e, mPtr)->res {
        mstore(mPtr, 0x20)
        mstore(add(mPtr, 0x20), 0x20)
        mstore(add(mPtr, 0x40), 0x20)
        mstore(add(mPtr, 0x60), x)
        mstore(add(mPtr, 0x80), e)
        mstore(add(mPtr, 0xa0), r_mod)
        pop(staticcall(sub(gas(), 2000),0x05,mPtr,0xc0,mPtr,0x20))
        res := mload(mPtr)
      }
    }

    emit PrintUint256(check);
    // emit PrintBool(success);
    // return true;

  }

  // function test_plonk_vanilla() public returns(bool) {

  //   Types.Proof memory proof;
  //   Types.VerificationKey memory vk;
    
  //   // uint256[] memory public_inputs = new uint256[](1);

  //   // public_inputs[0] = 35;
    
  //   // proof.wire_commitments[0].X = 7402952568124454645845736777641866552675031262050682573556534534858027996784;
  //   // proof.wire_commitments[0].Y = 7721623742789196166730813243887735477743597239585390242724094247354637565544;
  //   // proof.wire_commitments[1].X = 11271319237270981124663589355586188807156928810499812473685494720888794872581;
  //   // proof.wire_commitments[1].Y = 20488811762796854925372757945147232320672748486976170402778457422570786638669;
  //   // proof.wire_commitments[2].X = 3669172208412190819843581801519336747022181412463804565137782762858611893985;
  //   // proof.wire_commitments[2].Y = 12448601402265162446888472249857519465227846767809916563399273420395263941915;
  //   // proof.wire_commitments[3].X = 0;
  //   // proof.wire_commitments[3].Y = 0;
  //   // proof.grand_product_commitment.X = 10092250402245204252603902206337034381601405644605884905846783842996521520338;
  //   // proof.grand_product_commitment.Y = 16731131268265064815566220696608448043796483271291871887273464663755856610927;
  //   // proof.quotient_poly_commitments[0].X = 21624049071107194757409003813993956585155916097105560254252927000685722430025;
  //   // proof.quotient_poly_commitments[0].Y = 21322056886658342106307841170159195796496336229423950378264534552603828690248;
  //   // proof.quotient_poly_commitments[1].X = 1208531179388220327920535913035865384608283306009540378841158842283433451078;
  //   // proof.quotient_poly_commitments[1].Y = 8337872203508192174552956761531420012950393008003249907492668844815888262281;
  //   // proof.quotient_poly_commitments[2].X = 21314605163049482422917438086914657743577333949189455562012535945980342078642;
  //   // proof.quotient_poly_commitments[2].Y = 9753312925837168187675089732387929414977192564019269170890472844836508904954;
  //   // proof.wire_values_at_zeta[0] = 12420035679103689381146924546067053421694751509495013905243274009204064636882;
  //   // proof.wire_values_at_zeta[1] = 14433353910868022028400533619512372250663285451644383160429974253654837987957;
  //   // proof.wire_values_at_zeta[2] = 7045091301142048913570423041906665771589372546780363419502056230232909157408;
  //   // proof.grand_product_at_zeta_omega = 3541181423555613302668737085131204462813646128736337739223439001793094463637;
  //   // proof.quotient_polynomial_at_zeta = 4335188781339503573682158301704411587457304474953632704907173941714674708508;
  //   // proof.linearization_polynomial_at_zeta = 12873239272909347293147728869734547946130640225154416133598374928927260907146;
  //   // proof.qcprime_at_zeta = 0;
  //   // proof.permutation_polynomials_at_zeta[0] = 2768527762105052023875300543219346509474203912803109071052099382848818148643;
  //   // proof.permutation_polynomials_at_zeta[1] = 11999849468532410321943668282153704776854567977933773371563737676235303570120;
  //   // proof.opening_at_zeta_proof.X = 13546448907362513257769833130391030885597927638789662456112236347751864392466;
  //   // proof.opening_at_zeta_proof.Y = 17324005865144217255228312393378444114800639813215319488231606200402652504685;
  //   // proof.opening_at_zeta_omega_proof.X = 7311127190197599671097904572559409683938391656917282863665049102691445214771;
  //   // proof.opening_at_zeta_omega_proof.Y = 3775341651408032132890886088980972458765236819963905710844910644472534329197;

  //   // vk.domain_size = 8;
  //   // vk.omega = 19540430494807482326159819597004422086093766032135589407132600596362845576832;
  //   // vk.selector_commitments[0].X = 8189666426043331144155669872300600774171192646548141390348956113753612826659;
  //   // vk.selector_commitments[0].Y = 10313117252544255973189350009555804999945079563194643552452902111721448442971;
  //   // vk.selector_commitments[1].X = 2884297688615897926157558081052017092039007805580174275059512429510521353270;
  //   // vk.selector_commitments[1].Y = 18811799544315619829036734559482969749919233915425590430946441872725361598151;
  //   // vk.selector_commitments[2].X = 11626619589014720822672641922098051869770015499639519338181546071029924308662;
  //   // vk.selector_commitments[2].Y = 6083678428235555399679843987710050532979061766999254968451629002987536413913;
  //   // vk.selector_commitments[3].X = 10686584549975741631212192436688876235893754089269055574885255861471560945658;
  //   // vk.selector_commitments[3].Y = 2633808041567920234861550499108507191305965241418972615251743324312142488233;
  //   // vk.selector_commitments[4].X = 7758877141323307678959418497588606535400022377604587810029991983861809232258;
  //   // vk.selector_commitments[4].Y = 14909344509206972948079751360668078630652329581726778118559443254943032200179;
  //   // vk.selector_commitments[5].X = 0;
  //   // vk.selector_commitments[5].Y = 0;
  //   // vk.permutation_commitments[0].X = 11259971107737398289358431927631024480842492775743490333163789640913767061403;
  //   // vk.permutation_commitments[0].Y = 2311338094084049130958226103528626747959868092981732991251380716666844066408;
  //   // vk.permutation_commitments[1].X = 10192295337750345373342738789931108868102263759411795958006016848582599001259;
  //   // vk.permutation_commitments[1].Y = 5862535421258031008351007678455106726734513536108098615905368693160490744826;
  //   // vk.permutation_commitments[2].X = 18629873756620873235671635932713462746784965955369570126916283160403064656283;
  //   // vk.permutation_commitments[2].Y = 11408802041040746443363674818850983028977499452386819044888810122061678223118;
  //   // vk.coset_shift = 5;
  //   // vk.permutation_non_residues[0] = 5;
  //   // vk.permutation_non_residues[1] = 25;
  //   // vk.g2_x.X[0] = 10502847900728352820104995430384591572235862434148733107155956109347693984589;
  //   // vk.g2_x.X[1] = 14227438095234809947593477115205615798437098135983661833593245518598873470133;
  //   // vk.g2_x.Y[0] = 21715068306295773599916956786074008492685752252069347482027975832766446299128;
  //   // vk.g2_x.Y[1] = 7327864992410983220565967131396496522982024563883331581506589780450237498081;
  //   // vk.commitmentIndex = 0;

  //   uint256[] memory public_inputs = new uint256[](3);
  //   public_inputs[0] = 6;
  //   public_inputs[1] = 7;
  //   public_inputs[2] = 8;

  //   proof.l_com_x = 15136993133195984427146198656723976006016155651448836712029011094324350716138;
  //   proof.l_com_y = 14459340593279620571863508149384177746249983937035550477949458936596373965107;
  //   proof.r_com_x = 21003232367709372501451837430898797278780185517655218895087485127513957219222;
  //   proof.r_com_y = 3824868253843571833375362829100465281829818047450051728199066835761275859289;
  //   proof.o_com_x = 20052680778575398443396546624549987202887743634883688392825045060439187808295;
  //   proof.o_com_y = 14015482909472906087860468458774003114410351817454316564117646652364197944144;
    
  //   proof.wire_committed_commitments = new Bn254.G1Point[](1);
  //   proof.wire_committed_commitments[0].X =  15552480929910802332205434009033658529300932452690724290794850059288694568607;
  //   proof.wire_committed_commitments[0].Y =  4106131824108708883155969901844611304524714469488967324682353598451772881497;
  //   proof.grand_product_commitment_x = 8129382300249911509490994003768166931158456454519181570771543561021078604275;
  //   proof.grand_product_commitment_y = 16152052816489514765957359820447985214657491258890001545796749692715439650299;
  //   proof.h_0_x = 20322267595253153758698719677231418675569873881549989484761886683610366417437;
  //   proof.h_0_y = 9878571745392382940810963608086360874234150563732267813042586933182767510138;
  //   proof.h_1_x = 10187780944047721763399836028129649392015814094297062016647984900675121198477;
  //   proof.h_1_y = 17932641774430901128841566993464166907161121085974443041096056905093366102177;
  //   proof.h_2_x = 18457590569346495976812666189406939977730202462176974574513696424592726780082;
  //   proof.h_2_y = 6482702839552877652030428600624199861900963835448886114848087524836661646598;
  //   proof.l_at_zeta = 5147914084083247636555741113909432788023238731935224321705970839013049335098;
  //   proof.r_at_zeta = 11285072319599834721395808518851876001078585459194050444352925712060413368187;
  //   proof.o_at_zeta = 9743976338769318804724056599463012978117527881438551826928791374927337492860;
  //   proof.grand_product_at_zeta_omega = 4593806665053773110798740279726341994234187426202123910303846961813084696792;
  //   proof.quotient_polynomial_at_zeta = 316735932536137588220581511099302037891028579128547889996388785546506882698;
  //   proof.linearization_polynomial_at_zeta = 19350585134276416869177653874145854863819129994210395496841863513331019644994;
  //   proof.selector_commit_api_at_zeta = new uint256[](1);
  //   proof.selector_commit_api_at_zeta[0] = 3037506189426785371747045033080583929261182816576630524423545100817866974469;
  //   proof.s1_at_zeta = 6190498314569077887779183249877684324945647094815852142606141315731906685034;
  //   proof.s2_at_zeta = 5831053470298471998223188926028283472689709068111900324593204169285691081717;
  //   proof.opening_at_zeta_proof_x = 13224527132371105279913250536758217546265152888112369856898250310768235198131;
  //   proof.opening_at_zeta_proof_y = 19302896778185915684708615973130767719760274252616248185517862385997672256778;
  //   proof.opening_at_zeta_omega_proof_x = 5327606518865781512867344072729252925384850742898184104533960334549231249970;
  //   proof.opening_at_zeta_omega_proof_y = 4147756127288704823083405587555355700553844930947669522662884986348621037601;
    
  //   vk.domain_size = 32;
  //   vk.omega = 4419234939496763621076330863786513495701855246241724391626358375488475697872;
  //   vk.ql_com_x = 3249492299937356830250489011041180308067992016591401527068121784106989719648;
  //   vk.ql_com_y = 10459965615643388455781136436726437288800547058370943251873623010731177440661;
  //   vk.qr_com_x = 12510476613922141136476828275709042037770171239066681610748147345655672163851;
  //   vk.qr_com_y = 21702499139579688323831199788191067119894864133780232136805753631080002427269;
  //   vk.qm_com_x = 14953002130617700035755035451150408651119074291254331128989112575148233333491;
  //   vk.qm_com_y = 17892566681051922084336151301309366102531970850688837636319063607093137053627;
  //   vk.qo_com_x = 12510476613922141136476828275709042037770171239066681610748147345655672163851;
  //   vk.qo_com_y = 185743732259586898415205957066207968801447023517591525883284263565223781314;
  //   vk.qk_com_x = 14953002130617700035755035451150408651119074291254331128989112575148233333491;
  //   vk.qk_com_y = 3995676190787353137910254443947908986164340306608986026369974287552089154956;
  //   vk.s1_com_x = 21855018542748430565529761638971558125245342907512256948393636927196567938581;
  //   vk.s1_com_y = 11712367707713868753009749003773415568950091810241040629437353992390346924664;
  //   vk.s2_com_x = 17771334109737095158037840313408192145908096951666120454569319380122548644876;
  //   vk.s2_com_y = 1557548382852739357942435662406820815086929855797636868167313245414326520716;
  //   vk.s3_com_x = 3042622247313413937841956962385471739016337091363862127586520834001367730368;
  //   vk.s3_com_y = 11237012146990418046605498478831176936003562652049794077037238123223985118834;

  //   vk.coset_shift = 5;

  //   vk.selector_commitments_commit_api = new Bn254.G1Point[](1);
  //   vk.selector_commitments_commit_api[0].X = 6072894980673347906024769411958097208049504128219463716820120075337948200814;
  //   vk.selector_commitments_commit_api[0].Y = 19560123544018144421880384701499189813392268921297788713816469086064585937291;

  //   vk.g2_x_0 = 4777846902900565418590449384753263717909657903692016614099552076160357595620;
  //   vk.g2_x_1 = 3861286923073220011793349409046889289349533020715526625969101603056608090795;
  //   vk.g2_y_0 = 16406754891999554747479650379038048271643900448173543122927661446988296543616;
  //   vk.g2_y_1 = 21022748302362729781528857183979865986597752242747307653138221198529458362155;

  //   vk.commitment_indices = new uint256[](1);
  //   vk.commitment_indices[0] = 3;

  //   bool res = PlonkVerifier.verify(proof, vk, public_inputs);
  //   emit PrintBool(res);
  //   return res;
  // }

}