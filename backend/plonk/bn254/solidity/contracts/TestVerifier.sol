

pragma solidity ^0.8.0;
    
import {PlonkVerifier} from './Verifier.sol';


contract TestVerifier {

    using PlonkVerifier for *;

    event PrintBool(bool a);

    struct Proof {
        uint256 proof_l_com_x;
        uint256 proof_l_com_y;
        uint256 proof_r_com_x;
        uint256 proof_r_com_y;
        uint256 proof_o_com_x;
        uint256 proof_o_com_y;

        // h = h_0 + x^{n+2}h_1 + x^{2(n+2)}h_2
        uint256 proof_h_0_x;
        uint256 proof_h_0_y;
        uint256 proof_h_1_x;
        uint256 proof_h_1_y;
        uint256 proof_h_2_x;
        uint256 proof_h_2_y;

        // wire values at zeta
        uint256 proof_l_at_zeta;
        uint256 proof_r_at_zeta;
        uint256 proof_o_at_zeta;

        //uint256[STATE_WIDTH-1] permutation_polynomials_at_zeta; // Sσ1(zeta),Sσ2(zeta)
        uint256 proof_s1_at_zeta; // Sσ1(zeta)
        uint256 proof_s2_at_zeta; // Sσ2(zeta)

        //Bn254.G1Point grand_product_commitment;                 // [z(x)]
        uint256 proof_grand_product_commitment_x;
        uint256 proof_grand_product_commitment_y;

        uint256 proof_grand_product_at_zeta_omega;                    // z(w*zeta)
        uint256 proof_quotient_polynomial_at_zeta;                    // t(zeta)
        uint256 proof_linearised_polynomial_at_zeta;               // r(zeta)

        // Folded proof for the opening of H, linearised poly, l, r, o, s_1, s_2, qcp
        uint256 proof_batch_opening_at_zeta_x;            // [Wzeta]
        uint256 proof_batch_opening_at_zeta_y;

        //Bn254.G1Point opening_at_zeta_omega_proof;      // [Wzeta*omega]
        uint256 proof_opening_at_zeta_omega_x;
        uint256 proof_opening_at_zeta_omega_y;
        
        uint256 proof_openings_selector_commit_api_at_zeta;
        uint256 proof_selector_commit_api_commitment_x;
        uint256 proof_selector_commit_api_commitment_y;
    }

    function get_proof() internal view
    returns (bytes memory)
    {

        Proof memory proof;

        proof.proof_l_com_x = 9961527895649042447746237286019755744616063958222988704110250136724157271563;
        proof.proof_l_com_y = 3763853458820893624836626172621935293091643204367462431299344778633409793851;
        proof.proof_r_com_x = 11639323135504771147463504874127032317355460801396045882521334514299314373530;
        proof.proof_r_com_y = 4546125450241775539513437257799882232053370272638111440459311011543217543654;
        proof.proof_o_com_x = 6951885478365451859633218033534177953531151179025720808412664456507849098318;
        proof.proof_o_com_y = 10078316954566323850919294801300171612334236346594013740379896447714658364603;
        proof.proof_h_0_x = 19343392751150103637175769804055262957929391960949586454313351476870597441267;
        proof.proof_h_0_y = 15040021422290546131503927397701891874391251462368874123165081810335115946049;
        proof.proof_h_1_x = 6072989367096230458908488395188736698175608514486238412835812913582675193758;
        proof.proof_h_1_y = 1198862419377885759585537527801117909049414401526055843368139216458547894568;
        proof.proof_h_2_x = 1801257928055081756685845788175802334634386062611058316056184007883883842895;
        proof.proof_h_2_y = 15182044514430459993950051213783441555565616294069564570875152439098945883109;
        proof.proof_l_at_zeta = 3834311582724048913125247236908815424117666083750820736046136261523421388600;
        proof.proof_r_at_zeta = 8058392488012205352731755808897826179529961008792643371319157933207453954152;
        proof.proof_o_at_zeta = 16098047569238095182887288016201967471235427466557824783045483920003553117095;
        proof.proof_s1_at_zeta = 8357163133014564328792229968897199513343420768827196655924103616295848055563;
        proof.proof_s2_at_zeta = 11662601929308876147251795155385177276775281386266970781388372264216673487256;
        proof.proof_grand_product_commitment_x = 2373492145219130964546926031479330683532199534199352165119470130540126770141;
        proof.proof_grand_product_commitment_y = 19647164456434786549067972933948789240695088178892620345756016286354683500024;
        proof.proof_grand_product_at_zeta_omega = 4447307470839761674123221436625847386073121481521339495027310118699332465756;
        proof.proof_quotient_polynomial_at_zeta = 15854527596584854931439982985827444460810034506516587154914105651319805188796;
        proof.proof_linearised_polynomial_at_zeta = 7809061422914766373647062757126101099950513928375208932199539582179780378144;
        proof.proof_batch_opening_at_zeta_x = 15543895048600230990087821789984347474569502028927455845259937790603044752031;
        proof.proof_batch_opening_at_zeta_y = 19159835962845394813006687165002283311180895679579777313909259356041500892243;
        proof.proof_opening_at_zeta_omega_x = 8843808738930381635526231444509951037743945772055891399170668205157713018674;
		proof.proof_opening_at_zeta_omega_y = 19946455830740339450544117348780746817776336373415577733942888673495414022398;
        proof.proof_openings_selector_commit_api_at_zeta = 2638827982992591344468894412825174792212521718536770229047896803748603401550   ;
        proof.proof_selector_commit_api_commitment_x = 6880245239814378219702152162766819134805106735294751388859945517685478108082;
        proof.proof_selector_commit_api_commitment_y = 20470852159689608083980220583992671579924463595673688210282102382870132575092;

        bytes memory res;
        res = abi.encodePacked(
            proof.proof_l_com_x,
            proof.proof_l_com_y,
            proof.proof_r_com_x,
            proof.proof_r_com_y,
            proof.proof_o_com_x,
            proof.proof_o_com_y,
            proof.proof_h_0_x,
            proof.proof_h_0_y,
            proof.proof_h_1_x,
            proof.proof_h_1_y,
            proof.proof_h_2_x,
            proof.proof_h_2_y
        );
        res = abi.encodePacked(
            res,
            proof.proof_l_at_zeta,
            proof.proof_r_at_zeta,
            proof.proof_o_at_zeta
        );
        res = abi.encodePacked(
            res,
            proof.proof_s1_at_zeta,
            proof.proof_s2_at_zeta,
            proof.proof_grand_product_commitment_x,
            proof.proof_grand_product_commitment_y,
            proof.proof_grand_product_at_zeta_omega,
            proof.proof_quotient_polynomial_at_zeta,
            proof.proof_linearised_polynomial_at_zeta
        );
        res = abi.encodePacked(
            res,
            proof.proof_batch_opening_at_zeta_x,
            proof.proof_batch_opening_at_zeta_y,
            proof.proof_opening_at_zeta_omega_x,
            proof.proof_opening_at_zeta_omega_y,
            proof.proof_openings_selector_commit_api_at_zeta,
            proof.proof_selector_commit_api_commitment_x,
            proof.proof_selector_commit_api_commitment_y
        );

        return res;
    }

    function test_verifier_go(bytes memory proof, uint256[] memory public_inputs) public {
        bool check_proof = PlonkVerifier.Verify(proof, public_inputs);
        require(check_proof, "verification failed!");
    }

    function test_verifier() public {

        uint256[] memory pi = new uint256[](3);
        
        pi[0] = 6;
        
        pi[1] = 7;
        
        pi[2] = 8;
        

        bytes memory proof = get_proof();

        bool check_proof = PlonkVerifier.Verify(proof, pi);
        emit PrintBool(check_proof);
        require(check_proof, "verification failed!");
    }

}
