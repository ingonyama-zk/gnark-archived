pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import {Fr} from '../crypto/Fr.sol';
import {UtilsFr} from '../crypto/HashFr.sol';
import {Polynomials} from '../crypto/Polynomials.sol';
import {PlonkVerifier} from '../Verifier.sol';
import {Types} from '../crypto/Types.sol';
import {TranscriptLibrary} from '../crypto/Transcript.sol';
import {Marshal} from '../Marshal.sol';

contract TestContract {

  using UtilsFr for *;
  using Polynomials for *;
  using PlonkVerifier for *;
  using Types for *;
  using TranscriptLibrary for *;
  using Fr for *;

  event PrintUint256(uint256 a);
  event PrintBool(bool a);

  function test_hash(uint256 x, uint256 y, string memory dst) public returns(uint256 res){

    res = UtilsFr.hash_fr(x, y, dst);

    emit PrintUint256(res);

    return res;

  }

  function test_eval_ith_lagrange(uint256 i, uint256 z, uint256 w, uint256 n) public returns (uint256 res){

    res = Polynomials.compute_ith_lagrange_at_z(i, z, w, n);

    emit PrintUint256(res);

  }

  function test_compute_sum_li_zi(uint256[] memory inputs, uint256 z, uint256 w, uint256 n) public returns (uint256 res){

    res = Polynomials.compute_sum_li_zi(inputs, z, w, n);

    emit PrintUint256(res);

  }

  function test_batch_invert(uint256[] memory inputs) public {
    emit PrintUint256(12321);
    uint256[] memory res = Fr.batch_inverse(inputs);
    for (uint i = 0; i < res.length; i++) {
      res[i] = Fr.mul(inputs[i], res[i]);
      emit PrintUint256(res[i]);
    }
  }

  function test_batch_compute_lagrange(uint256 k, uint256 z, uint256 w, uint256 n) public {
    emit PrintUint256(1001001);

    uint256[] memory got = Polynomials.batch_compute_lagranges_at_z(k, z, w, n);
    emit PrintUint256(13579);
    /*for (uint i = 0; i < k; i++) {
      emit PrintUint256(got[i]);
    }*/
    for (uint i = 0; i < k; i++) {
      uint256 want = Polynomials.compute_ith_lagrange_at_z(i, z, w, n);
      emit PrintUint256(Fr.sub(got[i], want));
    }
  }
  function test_plonk_vanilla() public returns(bool) {

    Types.Proof memory proof;
    Types.VerificationKey memory vk;
    uint256[] memory public_inputs = new uint256[](1);

    public_inputs[0] = 35;
    
    proof.wire_commitments[0].X = 7402952568124454645845736777641866552675031262050682573556534534858027996784;
    proof.wire_commitments[0].Y = 7721623742789196166730813243887735477743597239585390242724094247354637565544;
    proof.wire_commitments[1].X = 11271319237270981124663589355586188807156928810499812473685494720888794872581;
    proof.wire_commitments[1].Y = 20488811762796854925372757945147232320672748486976170402778457422570786638669;
    proof.wire_commitments[2].X = 3669172208412190819843581801519336747022181412463804565137782762858611893985;
    proof.wire_commitments[2].Y = 12448601402265162446888472249857519465227846767809916563399273420395263941915;
    proof.wire_commitments[3].X = 0;
    proof.wire_commitments[3].Y = 0;
    proof.grand_product_commitment.X = 10092250402245204252603902206337034381601405644605884905846783842996521520338;
    proof.grand_product_commitment.Y = 16731131268265064815566220696608448043796483271291871887273464663755856610927;
    proof.quotient_poly_commitments[0].X = 21624049071107194757409003813993956585155916097105560254252927000685722430025;
    proof.quotient_poly_commitments[0].Y = 21322056886658342106307841170159195796496336229423950378264534552603828690248;
    proof.quotient_poly_commitments[1].X = 1208531179388220327920535913035865384608283306009540378841158842283433451078;
    proof.quotient_poly_commitments[1].Y = 8337872203508192174552956761531420012950393008003249907492668844815888262281;
    proof.quotient_poly_commitments[2].X = 21314605163049482422917438086914657743577333949189455562012535945980342078642;
    proof.quotient_poly_commitments[2].Y = 9753312925837168187675089732387929414977192564019269170890472844836508904954;
    proof.wire_values_at_zeta[0] = 12420035679103689381146924546067053421694751509495013905243274009204064636882;
    proof.wire_values_at_zeta[1] = 14433353910868022028400533619512372250663285451644383160429974253654837987957;
    proof.wire_values_at_zeta[2] = 7045091301142048913570423041906665771589372546780363419502056230232909157408;
    proof.grand_product_at_zeta_omega = 3541181423555613302668737085131204462813646128736337739223439001793094463637;
    proof.quotient_polynomial_at_zeta = 4335188781339503573682158301704411587457304474953632704907173941714674708508;
    proof.linearization_polynomial_at_zeta = 12873239272909347293147728869734547946130640225154416133598374928927260907146;
    proof.qcprime_at_zeta = 0;
    proof.permutation_polynomials_at_zeta[0] = 2768527762105052023875300543219346509474203912803109071052099382848818148643;
    proof.permutation_polynomials_at_zeta[1] = 11999849468532410321943668282153704776854567977933773371563737676235303570120;
    proof.opening_at_zeta_proof.X = 13546448907362513257769833130391030885597927638789662456112236347751864392466;
    proof.opening_at_zeta_proof.Y = 17324005865144217255228312393378444114800639813215319488231606200402652504685;
    proof.opening_at_zeta_omega_proof.X = 7311127190197599671097904572559409683938391656917282863665049102691445214771;
    proof.opening_at_zeta_omega_proof.Y = 3775341651408032132890886088980972458765236819963905710844910644472534329197;

    vk.domain_size = 8;
    vk.omega = 19540430494807482326159819597004422086093766032135589407132600596362845576832;
    vk.selector_commitments[0].X = 8189666426043331144155669872300600774171192646548141390348956113753612826659;
    vk.selector_commitments[0].Y = 10313117252544255973189350009555804999945079563194643552452902111721448442971;
    vk.selector_commitments[1].X = 2884297688615897926157558081052017092039007805580174275059512429510521353270;
    vk.selector_commitments[1].Y = 18811799544315619829036734559482969749919233915425590430946441872725361598151;
    vk.selector_commitments[2].X = 11626619589014720822672641922098051869770015499639519338181546071029924308662;
    vk.selector_commitments[2].Y = 6083678428235555399679843987710050532979061766999254968451629002987536413913;
    vk.selector_commitments[3].X = 10686584549975741631212192436688876235893754089269055574885255861471560945658;
    vk.selector_commitments[3].Y = 2633808041567920234861550499108507191305965241418972615251743324312142488233;
    vk.selector_commitments[4].X = 7758877141323307678959418497588606535400022377604587810029991983861809232258;
    vk.selector_commitments[4].Y = 14909344509206972948079751360668078630652329581726778118559443254943032200179;
    vk.selector_commitments[5].X = 0;
    vk.selector_commitments[5].Y = 0;
    vk.permutation_commitments[0].X = 11259971107737398289358431927631024480842492775743490333163789640913767061403;
    vk.permutation_commitments[0].Y = 2311338094084049130958226103528626747959868092981732991251380716666844066408;
    vk.permutation_commitments[1].X = 10192295337750345373342738789931108868102263759411795958006016848582599001259;
    vk.permutation_commitments[1].Y = 5862535421258031008351007678455106726734513536108098615905368693160490744826;
    vk.permutation_commitments[2].X = 18629873756620873235671635932713462746784965955369570126916283160403064656283;
    vk.permutation_commitments[2].Y = 11408802041040746443363674818850983028977499452386819044888810122061678223118;
    vk.coset_shift = 5;
    //vk.permutation_non_residues[0] = 5;
    //vk.permutation_non_residues[1] = 25;
    vk.coset_shift = 5;
    vk.g2_x.X[0] = 14227438095234809947593477115205615798437098135983661833593245518598873470133;
    vk.g2_x.X[1] = 10502847900728352820104995430384591572235862434148733107155956109347693984589;
    vk.g2_x.Y[0] = 7327864992410983220565967131396496522982024563883331581506589780450237498081;
    vk.g2_x.Y[1] = 21715068306295773599916956786074008492685752252069347482027975832766446299128;
    vk.commitmentIndex = 0;

    bool res = PlonkVerifier.verify(proof, vk, public_inputs);

    // expected gamma = 21625473336763634026948787553361369256520448719159937253746108462373062122442
    // emit PrintUint256(state.gamma);
    // emit PrintUint256(state.alpha);
    // emit PrintUint256(state.beta);
    // emit PrintUint256(state.zeta);

    return true;
  }

}

function test_plonk(uint256[] calldata kzg, bytes calldata preprocessed, uint256[] calldata proof, uint256[] calldata public_inputs) returns (bool) {
  Types.Proof memory proofD = Marshal.deserialize_proof(proof);
  Types.VerificationKey memory vk = Marshal.deserialize_vk(kzg, preprocessed);
  bool res = PlonkVerifier.verify(proofD, vk, public_inputs);
  return true;
}