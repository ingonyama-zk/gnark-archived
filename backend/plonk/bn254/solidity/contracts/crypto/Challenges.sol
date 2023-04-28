pragma solidity >=0.6.0;
pragma experimental ABIEncoderV2;

import {TranscriptLibrary} from './Transcript.sol';

library Challenges {

    using TranscriptLibrary for *;

    uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

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

    //Bn254.G1Point opening_at_zeta_proof;            // [Wzeta]
    uint256 constant proof_opening_at_zeta_proof_x = 0x2e0;            // [Wzeta]
    uint256 constant proof_opening_at_zeta_proof_y = 0x300;

    //Bn254.G1Point opening_at_zeta_omega_proof;      // [Wzeta*omega]
    uint256 constant proof_opening_at_zeta_omega_proof_x = 0x320;
    uint256 constant proof_opening_at_zeta_omega_proof_y = 0x340;
    
    uint256 constant proof_nb_selector_commit_api_at_zeta = 0x360;

    function get_vk_selector_commitments_commit_api(uint256[] memory v) 
    internal view {
        v[0] = 6072894980673347906024769411958097208049504128219463716820120075337948200814;
        v[1] = 19560123544018144421880384701499189813392268921297788713816469086064585937291;
    }

    function get_vk_commitments_indices_commit_api(uint256[] memory v)
    internal view {
        v[0] = 3;
    }

    uint256 constant vk_g2_x_0 = 4777846902900565418590449384753263717909657903692016614099552076160357595620;
    uint256 constant vk_g2_x_1 = 3861286923073220011793349409046889289349533020715526625969101603056608090795;
    uint256 constant vk_g2_y_0 = 16406754891999554747479650379038048271643900448173543122927661446988296543616;
    uint256 constant vk_g2_y_1 = 21022748302362729781528857183979865986597752242747307653138221198529458362155;

    uint256 constant vk_nb_commitments_commit_api = 1;

    function derive_gamma(bytes memory proof, uint256[] memory public_inputs, TranscriptLibrary.Transcript memory t)
    internal returns(uint256) {

    uint256 gamma;
    t.set_challenge_name("gamma");
    
    t.update_with_u256(vk_s1_com_x);
    t.update_with_u256(vk_s1_com_y);
    t.update_with_u256(vk_s2_com_x);
    t.update_with_u256(vk_s2_com_y);
    t.update_with_u256(vk_s3_com_x);
    t.update_with_u256(vk_s3_com_y);

    t.update_with_u256(vk_ql_com_x);
    t.update_with_u256(vk_ql_com_y);
    t.update_with_u256(vk_qr_com_x);
    t.update_with_u256(vk_qr_com_y);
    t.update_with_u256(vk_qm_com_x);
    t.update_with_u256(vk_qm_com_y);
    t.update_with_u256(vk_qo_com_x);
    t.update_with_u256(vk_qo_com_y);
    t.update_with_u256(vk_qk_com_x);
    t.update_with_u256(vk_qk_com_y);

    for (uint256 i = 0; i < public_inputs.length; i++) {
        t.update_with_u256(public_inputs[i]);
    }

    uint256[] memory wire_committed_commitments;
    wire_committed_commitments = new uint256[](2*vk_nb_commitments_commit_api);
    load_wire_commitments_commit_api(wire_committed_commitments, proof);
    for (uint i=0; i<2*vk_nb_commitments_commit_api; i++){
      t.update_with_u256(wire_committed_commitments[i]); // PI2_i
    }
    uint256 p_l_com_x;
    uint256 p_l_com_y;
    uint256 p_r_com_x;
    uint256 p_r_com_y;
    uint256 p_o_com_x;
    uint256 p_o_com_y;
    assembly {
      p_l_com_x := mload(add(proof, proof_l_com_x))
      p_l_com_y := mload(add(proof, proof_l_com_y))
      p_r_com_x := mload(add(proof, proof_r_com_x))
      p_r_com_y := mload(add(proof, proof_r_com_y))
      p_o_com_x := mload(add(proof, proof_o_com_x))
      p_o_com_y := mload(add(proof, proof_o_com_y))
    }
    t.update_with_u256(p_l_com_x);
    t.update_with_u256(p_l_com_y);
    t.update_with_u256(p_r_com_x);
    t.update_with_u256(p_r_com_y);
    t.update_with_u256(p_o_com_x);
    t.update_with_u256(p_o_com_y);

    gamma = t.get_challenge();
    
    return gamma;
  }

  function derive_alpha(bytes memory proof, TranscriptLibrary.Transcript memory t)
  internal returns(uint256){

    t.set_challenge_name("alpha");
    uint256 p_grand_product_commitment_x;
    uint256 p_grand_product_commitment_y;

    assembly{
      p_grand_product_commitment_x := mload(add(proof, proof_grand_product_commitment_x))
      p_grand_product_commitment_y := mload(add(proof, proof_grand_product_commitment_y))
    }
    t.update_with_u256(p_grand_product_commitment_x);
    t.update_with_u256(p_grand_product_commitment_y);
    uint256 alpha = t.get_challenge();

    return alpha;
  }

  function derive_zeta(bytes memory proof, TranscriptLibrary.Transcript memory t)
  internal returns(uint256){

    t.set_challenge_name("zeta");
    uint256 p_h_0_x;
    uint256 p_h_0_y;
    uint256 p_h_1_x;
    uint256 p_h_1_y;
    uint256 p_h_2_x;
    uint256 p_h_2_y;

    assembly {
      p_h_0_x := mload(add(proof, proof_h_0_x))
      p_h_0_y := mload(add(proof, proof_h_0_y))
      p_h_1_x := mload(add(proof, proof_h_1_x))
      p_h_1_y := mload(add(proof, proof_h_1_y))
      p_h_2_x := mload(add(proof, proof_h_2_x))
      p_h_2_y := mload(add(proof, proof_h_2_y))
    }
    
    t.update_with_u256(p_h_0_x);
    t.update_with_u256(p_h_0_y);
    t.update_with_u256(p_h_1_x);
    t.update_with_u256(p_h_1_y);
    t.update_with_u256(p_h_2_x);
    t.update_with_u256(p_h_2_y);

    uint256 zeta = t.get_challenge();

    return zeta;

  }

  function derive_gamma_beta_alpha_zeta(bytes memory proof, uint256[] memory public_inputs)
  internal returns(uint256, uint256, uint256, uint256) {

      TranscriptLibrary.Transcript memory t = TranscriptLibrary.new_transcript();
      uint256 gamma = derive_gamma(proof, public_inputs, t);
      
      t.set_challenge_name("beta");
      uint256 beta  = t.get_challenge();

      uint256 alpha = derive_alpha(proof, t);

      uint256 zeta = derive_zeta(proof, t);

      return (gamma, beta, alpha, zeta);
  }

  function load_wire_commitments_commit_api(uint256[] memory wire_commitments, bytes memory proof)
  internal {
    assembly {
      let w := add(wire_commitments, 0x20)
      let p := add(proof, proof_nb_selector_commit_api_at_zeta)
      p := add(p, mul(add(vk_nb_commitments_commit_api,1), 0x20))
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

}