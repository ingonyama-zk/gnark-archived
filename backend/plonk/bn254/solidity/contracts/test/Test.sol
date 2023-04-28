pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import {PlonkVerifier} from '../Verifier.sol';
import {Types} from '../crypto/Types.sol';
import {TranscriptLibrary} from '../crypto/Transcript.sol';
import {Bn254} from '../crypto/Bn254.sol';
import {UtilsFr} from '../crypto/HashFr.sol';
import {Polynomials} from '../crypto/Polynomials.sol';
import {Fr} from '../crypto/Fr.sol';

contract TestContract {

  using Polynomials for *;
  using PlonkVerifier for *;
  using Types for *;
  using TranscriptLibrary for *;
  using Fr for *;
  using Bn254 for *;
  using UtilsFr for *;

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

  //Bn254.G1Point opening_at_zeta_proof;            // [Wzeta]
  uint256 constant proof_opening_at_zeta_proof_x = 0x2e0;            // [Wzeta]
  uint256 constant proof_opening_at_zeta_proof_y = 0x300;

  //Bn254.G1Point opening_at_zeta_omega_proof;      // [Wzeta*omega]
  uint256 constant proof_opening_at_zeta_omega_proof_x = 0x320;
  uint256 constant proof_opening_at_zeta_omega_proof_y = 0x340;
  
  uint256 constant proof_nb_selector_commit_api_at_zeta = 0x360;
  // -> next part of proof is 
  // [nb_selector_commit_api_at_zeta || openings || commitments]

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
  uint256 constant state_kzg_opening_proof_x = 0x160;
  uint256 constant state_kzg_opening_proof_y = 0x180;  
  uint256 constant state_claimed_value = 0x1a0;

  // folded digests of H, linearised poly, l, r, o, s_1, s_2, qcp
  // Bn254.G1Point folded_digests;
  uint256 constant state_folded_digests_x = 0x1c0;
  uint256 constant state_folded_digests_y = 0x1e0;

  uint256 constant state_last_mem = 0x200;

  event PrintBool(bool a);
  event PrintUint256(uint256 a);
  event PrintBytes(bytes a);
  event PrintBytes32(bytes32 a);

  function get_proof() 
  internal pure returns (bytes memory)
  {
    bytes memory res;

    Types.Proof memory proof;

    uint256 one = 1;

    proof.l_com_x = 15136993133195984427146198656723976006016155651448836712029011094324350716138;
    proof.l_com_y = 14459340593279620571863508149384177746249983937035550477949458936596373965107;
    proof.r_com_x = 21003232367709372501451837430898797278780185517655218895087485127513957219222;
    proof.r_com_y = 3824868253843571833375362829100465281829818047450051728199066835761275859289;
    proof.o_com_x = 20052680778575398443396546624549987202887743634883688392825045060439187808295;
    proof.o_com_y = 14015482909472906087860468458774003114410351817454316564117646652364197944144;
    
    proof.h_0_x = 20322267595253153758698719677231418675569873881549989484761886683610366417437;
    proof.h_0_y = 9878571745392382940810963608086360874234150563732267813042586933182767510138;
    proof.h_1_x = 10187780944047721763399836028129649392015814094297062016647984900675121198477;
    proof.h_1_y = 17932641774430901128841566993464166907161121085974443041096056905093366102177;
    proof.h_2_x = 18457590569346495976812666189406939977730202462176974574513696424592726780082;
    proof.h_2_y = 6482702839552877652030428600624199861900963835448886114848087524836661646598;
    
    proof.l_at_zeta = 5147914084083247636555741113909432788023238731935224321705970839013049335098;
    proof.r_at_zeta = 11285072319599834721395808518851876001078585459194050444352925712060413368187;
    proof.o_at_zeta = 9743976338769318804724056599463012978117527881438551826928791374927337492860;
    
    proof.s1_at_zeta = 6190498314569077887779183249877684324945647094815852142606141315731906685034;
    proof.s2_at_zeta = 5831053470298471998223188926028283472689709068111900324593204169285691081717;

    proof.grand_product_commitment_x = 8129382300249911509490994003768166931158456454519181570771543561021078604275;
    proof.grand_product_commitment_y = 16152052816489514765957359820447985214657491258890001545796749692715439650299;
    
    proof.grand_product_at_zeta_omega = 4593806665053773110798740279726341994234187426202123910303846961813084696792;
    proof.quotient_polynomial_at_zeta = 316735932536137588220581511099302037891028579128547889996388785546506882698;
    proof.linearization_polynomial_at_zeta = 19350585134276416869177653874145854863819129994210395496841863513331019644994;
   
    proof.opening_at_zeta_proof_x = 13224527132371105279913250536758217546265152888112369856898250310768235198131;
    proof.opening_at_zeta_proof_y = 19302896778185915684708615973130767719760274252616248185517862385997672256778;
   
    proof.opening_at_zeta_omega_proof_x = 5327606518865781512867344072729252925384850742898184104533960334549231249970;
    proof.opening_at_zeta_omega_proof_y = 4147756127288704823083405587555355700553844930947669522662884986348621037601;

    res = abi.encodePacked(
      proof.l_com_x, 
      proof.l_com_y, 
      proof.r_com_x,
      proof.r_com_y,
      proof.o_com_x,
      proof.o_com_y,
      proof.h_0_x,
      proof.h_0_y,
      proof.h_1_x
    );
    res = abi.encodePacked(
      res,
      proof.h_1_y,
      proof.h_2_x,
      proof.h_2_y,
      proof.l_at_zeta,
      proof.r_at_zeta,
      proof.o_at_zeta,
      proof.s1_at_zeta,
      proof.s2_at_zeta
    );
    res = abi.encodePacked(
      res,
      proof.grand_product_commitment_x,
      proof.grand_product_commitment_y,
      proof.grand_product_at_zeta_omega,
      proof.quotient_polynomial_at_zeta,
      proof.linearization_polynomial_at_zeta,
      proof.opening_at_zeta_proof_x,
      proof.opening_at_zeta_proof_y,
      proof.opening_at_zeta_omega_proof_x,
      proof.opening_at_zeta_omega_proof_y
    );

    proof.selector_commit_api_at_zeta = new uint256[](1);
    proof.selector_commit_api_at_zeta[0] = 3037506189426785371747045033080583929261182816576630524423545100817866974469;
    res = abi.encodePacked(res, one, proof.selector_commit_api_at_zeta[0]);
    proof.wire_committed_commitments = new Bn254.G1Point[](1);
    proof.wire_committed_commitments[0].X =  15552480929910802332205434009033658529300932452690724290794850059288694568607;
    proof.wire_committed_commitments[0].Y =  4106131824108708883155969901844611304524714469488967324682353598451772881497;
    
    res = abi.encodePacked(
      res,
      proof.wire_committed_commitments[0].X,
      proof.wire_committed_commitments[0].Y
    );

    return res;
  }

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

  function compute_ith_lagrange_at_z(uint256 zeta, uint256 i) 
  internal returns (uint256) {

    uint256 res;
    uint256 t;
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
          pop(staticcall(gas(),0x05,mPtr,0xc0,0x00,0x20))
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
        uint256 zeta_power_n_minus_one = Fr.pow(zeta, vk_domain_size);
        zeta_power_n_minus_one = Fr.sub(zeta_power_n_minus_one, 1);

        // compute PI = ∑_{i<n} Lᵢ*wᵢ
        uint256 pi = Polynomials.compute_sum_li_zi(public_inputs, zeta, vk_omega, vk_domain_size);
        
        uint256[] memory commitment_indices = new uint256[](vk_nb_commitments_commit_api);
        get_vk_commitments_indices_commit_api(commitment_indices);
    
        if (vk_nb_commitments_commit_api > 0) {

          uint256[] memory wire_committed_commitments;
          wire_committed_commitments = new uint256[](2*vk_nb_commitments_commit_api);
          load_wire_commitments_commit_api(wire_committed_commitments, proof);

          string memory dst = "BSB22-Plonk";

          for (uint256 i=0; i<vk_nb_commitments_commit_api; i++){
              
              uint256 hash_res = UtilsFr.hash_fr(wire_committed_commitments[2*i], wire_committed_commitments[2*i+1], dst);
              uint256 a = compute_ith_lagrange_at_z(zeta, commitment_indices[i]+public_inputs.length);
              
              // a = Fr.mul(hash_res, a);
              // pi = Fr.add(pi, a);
              assembly {
                a := mulmod(hash_res, a, r_mod)
                pi := addmod(pi, a, r_mod)
              }
          }
        }
        
        return pi;
    
        // assembly {

        //     // (l(ζ)+β*s1(ζ)+γ)
        //     let s1 := mload(0x40)
        //     mstore(s1, mulmod(mload(add(proof,proof_s1_at_zeta)),mload(add(state, state_beta)), r_mod))
        //     mstore(s1, addmod(mload(s1), mload(add(state, state_gamma)), r_mod))
        //     mstore(s1, addmod(mload(s1), mload(add(proof, proof_l_at_zeta)), r_mod))

        //     // (r(ζ)+β*s2(ζ)+γ)
        //     let s2 := add(s1,0x20)
        //     mstore(s2, mulmod(mload(add(proof,proof_s2_at_zeta)),mload(add(state, state_beta)), r_mod))
        //     mstore(s2, addmod(mload(s2), mload(add(state, state_gamma)), r_mod))
        //     mstore(s2, addmod(mload(s2), mload(add(proof, proof_r_at_zeta)), r_mod))
        //     // _s2 := mload(s2)

        //     // (o(ζ)+γ)
        //     let o := add(s1,0x40)
        //     mstore(o, addmod(mload(add(proof,proof_o_at_zeta)), mload(add(state, state_gamma)), r_mod))

        //     //  α*(Z(μζ))*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(o(ζ)+γ)
        //     mstore(s1, mulmod(mload(s1), mload(s2), r_mod))
        //     mstore(s1, mulmod(mload(s1), mload(o), r_mod))
        //     mstore(s1, mulmod(mload(s1), mload(add(state, state_alpha)), r_mod))
        //     mstore(s1, mulmod(mload(s1), mload(add(proof, proof_grand_product_at_zeta_omega)), r_mod))

        //     // α²*L₁(ζ)
        //     mstore(add(state,state_alpha_square_lagrange), mulmod(mload(add(state,state_alpha_square_lagrange)), mload(add(state, state_alpha)), r_mod))
        //     mstore(add(state,state_alpha_square_lagrange), mulmod(mload(add(state,state_alpha_square_lagrange)), mload(add(state, state_alpha)), r_mod))

        //     let computed_quotient := add(s1,0x60)

        //     // linearizedpolynomial + pi(zeta)
        //     mstore(computed_quotient, addmod(mload(add(proof, proof_linearization_polynomial_at_zeta)), pi, r_mod))

        //     // linearizedpolynomial+pi(zeta)+α*(Z(μζ))*(l(ζ)+s1(ζ)+γ)*(r(ζ)+s2(ζ)+γ)*(o(ζ)+γ)
        //     mstore(computed_quotient, addmod(mload(computed_quotient), mload(s1), r_mod))

        //     // linearizedpolynomial+pi(zeta)+α*(Z(μζ))*(l(ζ)+s1(ζ)+γ)*(r(ζ)+s2(ζ)+γ)*(o(ζ)+γ)-α²*L₁(ζ)
        //     mstore(computed_quotient, addmod(mload(computed_quotient), sub(r_mod,mload(add(state, state_alpha_square_lagrange))), r_mod))

        //     // test_quotient := mload(computed_quotient)
        //     mstore(s2, mulmod(mload(add(proof,proof_quotient_polynomial_at_zeta)), zeta_power_n_minus_one, r_mod))

        //     success := eq(mload(computed_quotient), mload(s2))
        // }
    }

  function test_assembly() 
  public {

    uint256[] memory public_inputs = new uint256[](3);
    public_inputs[0] = 6;
    public_inputs[1] = 7;
    public_inputs[2] = 8;
    
    bytes memory proof = get_proof();

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

    emit PrintUint256(pi);

    assembly {

      // dst <- [s]src
      function point_mul(dst,src,s) {
        let buf := mload(0x40)
        mstore(buf,mload(src))
        mstore(add(buf,0x20),mload(add(src,0x20)))
        mstore(add(buf,0x40),mload(s))
        pop(staticcall(gas(),7,buf,0x60,dst,0x40)) // TODO should we check success here ?
      }

      // dst <- dst + [s]src
      function point_acc_mul(dst,src,s) {
        let buf := mload(0x40)
        mstore(buf,mload(src))
        mstore(add(buf,0x20),mload(add(src,0x20)))
        mstore(add(buf,0x40),mload(s))
        pop(staticcall(gas(),7,buf,0x60,buf,0x40)) // TODO should we check success here ?
        mstore(add(buf,0x40),mload(dst))
        mstore(add(buf,0x60),mload(add(dst,0x20)))
        pop(staticcall(gas(),6,buf,0x80,dst, 0x40))
      }

      // dst <- x ** e mod r (x, e are values, not pointers)
      function pow(dst, x, e) {
        let buf := mload(0x40)
        mstore(buf, 0x20)
        mstore(add(buf, 0x20), 0x20)
        mstore(add(buf, 0x40), 0x20)
        mstore(add(buf, 0x60), x)
        mstore(add(buf, 0x80), e)
        mstore(add(buf, 0xa0), r_mod)
        pop(staticcall(gas(),0x05,buf,0xc0,dst,0x20))
      }

      

    }
    return true;

  }

  function test_plonk_vanilla() public returns(bool) {

    Types.Proof memory proof;
    Types.VerificationKey memory vk;
    
    // uint256[] memory public_inputs = new uint256[](1);

    // public_inputs[0] = 35;
    
    // proof.wire_commitments[0].X = 7402952568124454645845736777641866552675031262050682573556534534858027996784;
    // proof.wire_commitments[0].Y = 7721623742789196166730813243887735477743597239585390242724094247354637565544;
    // proof.wire_commitments[1].X = 11271319237270981124663589355586188807156928810499812473685494720888794872581;
    // proof.wire_commitments[1].Y = 20488811762796854925372757945147232320672748486976170402778457422570786638669;
    // proof.wire_commitments[2].X = 3669172208412190819843581801519336747022181412463804565137782762858611893985;
    // proof.wire_commitments[2].Y = 12448601402265162446888472249857519465227846767809916563399273420395263941915;
    // proof.wire_commitments[3].X = 0;
    // proof.wire_commitments[3].Y = 0;
    // proof.grand_product_commitment.X = 10092250402245204252603902206337034381601405644605884905846783842996521520338;
    // proof.grand_product_commitment.Y = 16731131268265064815566220696608448043796483271291871887273464663755856610927;
    // proof.quotient_poly_commitments[0].X = 21624049071107194757409003813993956585155916097105560254252927000685722430025;
    // proof.quotient_poly_commitments[0].Y = 21322056886658342106307841170159195796496336229423950378264534552603828690248;
    // proof.quotient_poly_commitments[1].X = 1208531179388220327920535913035865384608283306009540378841158842283433451078;
    // proof.quotient_poly_commitments[1].Y = 8337872203508192174552956761531420012950393008003249907492668844815888262281;
    // proof.quotient_poly_commitments[2].X = 21314605163049482422917438086914657743577333949189455562012535945980342078642;
    // proof.quotient_poly_commitments[2].Y = 9753312925837168187675089732387929414977192564019269170890472844836508904954;
    // proof.wire_values_at_zeta[0] = 12420035679103689381146924546067053421694751509495013905243274009204064636882;
    // proof.wire_values_at_zeta[1] = 14433353910868022028400533619512372250663285451644383160429974253654837987957;
    // proof.wire_values_at_zeta[2] = 7045091301142048913570423041906665771589372546780363419502056230232909157408;
    // proof.grand_product_at_zeta_omega = 3541181423555613302668737085131204462813646128736337739223439001793094463637;
    // proof.quotient_polynomial_at_zeta = 4335188781339503573682158301704411587457304474953632704907173941714674708508;
    // proof.linearization_polynomial_at_zeta = 12873239272909347293147728869734547946130640225154416133598374928927260907146;
    // proof.qcprime_at_zeta = 0;
    // proof.permutation_polynomials_at_zeta[0] = 2768527762105052023875300543219346509474203912803109071052099382848818148643;
    // proof.permutation_polynomials_at_zeta[1] = 11999849468532410321943668282153704776854567977933773371563737676235303570120;
    // proof.opening_at_zeta_proof.X = 13546448907362513257769833130391030885597927638789662456112236347751864392466;
    // proof.opening_at_zeta_proof.Y = 17324005865144217255228312393378444114800639813215319488231606200402652504685;
    // proof.opening_at_zeta_omega_proof.X = 7311127190197599671097904572559409683938391656917282863665049102691445214771;
    // proof.opening_at_zeta_omega_proof.Y = 3775341651408032132890886088980972458765236819963905710844910644472534329197;

    // vk.domain_size = 8;
    // vk.omega = 19540430494807482326159819597004422086093766032135589407132600596362845576832;
    // vk.selector_commitments[0].X = 8189666426043331144155669872300600774171192646548141390348956113753612826659;
    // vk.selector_commitments[0].Y = 10313117252544255973189350009555804999945079563194643552452902111721448442971;
    // vk.selector_commitments[1].X = 2884297688615897926157558081052017092039007805580174275059512429510521353270;
    // vk.selector_commitments[1].Y = 18811799544315619829036734559482969749919233915425590430946441872725361598151;
    // vk.selector_commitments[2].X = 11626619589014720822672641922098051869770015499639519338181546071029924308662;
    // vk.selector_commitments[2].Y = 6083678428235555399679843987710050532979061766999254968451629002987536413913;
    // vk.selector_commitments[3].X = 10686584549975741631212192436688876235893754089269055574885255861471560945658;
    // vk.selector_commitments[3].Y = 2633808041567920234861550499108507191305965241418972615251743324312142488233;
    // vk.selector_commitments[4].X = 7758877141323307678959418497588606535400022377604587810029991983861809232258;
    // vk.selector_commitments[4].Y = 14909344509206972948079751360668078630652329581726778118559443254943032200179;
    // vk.selector_commitments[5].X = 0;
    // vk.selector_commitments[5].Y = 0;
    // vk.permutation_commitments[0].X = 11259971107737398289358431927631024480842492775743490333163789640913767061403;
    // vk.permutation_commitments[0].Y = 2311338094084049130958226103528626747959868092981732991251380716666844066408;
    // vk.permutation_commitments[1].X = 10192295337750345373342738789931108868102263759411795958006016848582599001259;
    // vk.permutation_commitments[1].Y = 5862535421258031008351007678455106726734513536108098615905368693160490744826;
    // vk.permutation_commitments[2].X = 18629873756620873235671635932713462746784965955369570126916283160403064656283;
    // vk.permutation_commitments[2].Y = 11408802041040746443363674818850983028977499452386819044888810122061678223118;
    // vk.coset_shift = 5;
    // vk.permutation_non_residues[0] = 5;
    // vk.permutation_non_residues[1] = 25;
    // vk.g2_x.X[0] = 10502847900728352820104995430384591572235862434148733107155956109347693984589;
    // vk.g2_x.X[1] = 14227438095234809947593477115205615798437098135983661833593245518598873470133;
    // vk.g2_x.Y[0] = 21715068306295773599916956786074008492685752252069347482027975832766446299128;
    // vk.g2_x.Y[1] = 7327864992410983220565967131396496522982024563883331581506589780450237498081;
    // vk.commitmentIndex = 0;

    uint256[] memory public_inputs = new uint256[](3);
    public_inputs[0] = 6;
    public_inputs[1] = 7;
    public_inputs[2] = 8;

    proof.l_com_x = 15136993133195984427146198656723976006016155651448836712029011094324350716138;
    proof.l_com_y = 14459340593279620571863508149384177746249983937035550477949458936596373965107;
    proof.r_com_x = 21003232367709372501451837430898797278780185517655218895087485127513957219222;
    proof.r_com_y = 3824868253843571833375362829100465281829818047450051728199066835761275859289;
    proof.o_com_x = 20052680778575398443396546624549987202887743634883688392825045060439187808295;
    proof.o_com_y = 14015482909472906087860468458774003114410351817454316564117646652364197944144;
    
    proof.wire_committed_commitments = new Bn254.G1Point[](1);
    proof.wire_committed_commitments[0].X =  15552480929910802332205434009033658529300932452690724290794850059288694568607;
    proof.wire_committed_commitments[0].Y =  4106131824108708883155969901844611304524714469488967324682353598451772881497;
    proof.grand_product_commitment_x = 8129382300249911509490994003768166931158456454519181570771543561021078604275;
    proof.grand_product_commitment_y = 16152052816489514765957359820447985214657491258890001545796749692715439650299;
    proof.h_0_x = 20322267595253153758698719677231418675569873881549989484761886683610366417437;
    proof.h_0_y = 9878571745392382940810963608086360874234150563732267813042586933182767510138;
    proof.h_1_x = 10187780944047721763399836028129649392015814094297062016647984900675121198477;
    proof.h_1_y = 17932641774430901128841566993464166907161121085974443041096056905093366102177;
    proof.h_2_x = 18457590569346495976812666189406939977730202462176974574513696424592726780082;
    proof.h_2_y = 6482702839552877652030428600624199861900963835448886114848087524836661646598;
    proof.l_at_zeta = 5147914084083247636555741113909432788023238731935224321705970839013049335098;
    proof.r_at_zeta = 11285072319599834721395808518851876001078585459194050444352925712060413368187;
    proof.o_at_zeta = 9743976338769318804724056599463012978117527881438551826928791374927337492860;
    proof.grand_product_at_zeta_omega = 4593806665053773110798740279726341994234187426202123910303846961813084696792;
    proof.quotient_polynomial_at_zeta = 316735932536137588220581511099302037891028579128547889996388785546506882698;
    proof.linearization_polynomial_at_zeta = 19350585134276416869177653874145854863819129994210395496841863513331019644994;
    proof.selector_commit_api_at_zeta = new uint256[](1);
    proof.selector_commit_api_at_zeta[0] = 3037506189426785371747045033080583929261182816576630524423545100817866974469;
    proof.s1_at_zeta = 6190498314569077887779183249877684324945647094815852142606141315731906685034;
    proof.s2_at_zeta = 5831053470298471998223188926028283472689709068111900324593204169285691081717;
    proof.opening_at_zeta_proof_x = 13224527132371105279913250536758217546265152888112369856898250310768235198131;
    proof.opening_at_zeta_proof_y = 19302896778185915684708615973130767719760274252616248185517862385997672256778;
    proof.opening_at_zeta_omega_proof_x = 5327606518865781512867344072729252925384850742898184104533960334549231249970;
    proof.opening_at_zeta_omega_proof_y = 4147756127288704823083405587555355700553844930947669522662884986348621037601;
    
    vk.domain_size = 32;
    vk.omega = 4419234939496763621076330863786513495701855246241724391626358375488475697872;
    vk.ql_com_x = 3249492299937356830250489011041180308067992016591401527068121784106989719648;
    vk.ql_com_y = 10459965615643388455781136436726437288800547058370943251873623010731177440661;
    vk.qr_com_x = 12510476613922141136476828275709042037770171239066681610748147345655672163851;
    vk.qr_com_y = 21702499139579688323831199788191067119894864133780232136805753631080002427269;
    vk.qm_com_x = 14953002130617700035755035451150408651119074291254331128989112575148233333491;
    vk.qm_com_y = 17892566681051922084336151301309366102531970850688837636319063607093137053627;
    vk.qo_com_x = 12510476613922141136476828275709042037770171239066681610748147345655672163851;
    vk.qo_com_y = 185743732259586898415205957066207968801447023517591525883284263565223781314;
    vk.qk_com_x = 14953002130617700035755035451150408651119074291254331128989112575148233333491;
    vk.qk_com_y = 3995676190787353137910254443947908986164340306608986026369974287552089154956;
    vk.s1_com_x = 21855018542748430565529761638971558125245342907512256948393636927196567938581;
    vk.s1_com_y = 11712367707713868753009749003773415568950091810241040629437353992390346924664;
    vk.s2_com_x = 17771334109737095158037840313408192145908096951666120454569319380122548644876;
    vk.s2_com_y = 1557548382852739357942435662406820815086929855797636868167313245414326520716;
    vk.s3_com_x = 3042622247313413937841956962385471739016337091363862127586520834001367730368;
    vk.s3_com_y = 11237012146990418046605498478831176936003562652049794077037238123223985118834;

    vk.coset_shift = 5;

    vk.selector_commitments_commit_api = new Bn254.G1Point[](1);
    vk.selector_commitments_commit_api[0].X = 6072894980673347906024769411958097208049504128219463716820120075337948200814;
    vk.selector_commitments_commit_api[0].Y = 19560123544018144421880384701499189813392268921297788713816469086064585937291;

    vk.g2_x_0 = 4777846902900565418590449384753263717909657903692016614099552076160357595620;
    vk.g2_x_1 = 3861286923073220011793349409046889289349533020715526625969101603056608090795;
    vk.g2_y_0 = 16406754891999554747479650379038048271643900448173543122927661446988296543616;
    vk.g2_y_1 = 21022748302362729781528857183979865986597752242747307653138221198529458362155;

    vk.commitment_indices = new uint256[](1);
    vk.commitment_indices[0] = 3;

    bool res = PlonkVerifier.verify(proof, vk, public_inputs);
    emit PrintBool(res);
    return res;
  }

}