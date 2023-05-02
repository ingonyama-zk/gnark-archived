pragma solidity >=0.6.0;
pragma experimental ABIEncoderV2;

library TestProof {

    // here to avoid stack too deep error...
    struct Proof {

        uint256 l_com_x;
        uint256 l_com_y;        
        uint256 r_com_x;
        uint256 r_com_y;
        uint256 o_com_x;
        uint256 o_com_y;
        uint256 h_0_x;
        uint256 h_0_y;
        uint256 h_1_x;
        uint256 h_1_y;
        uint256 h_2_x;
        uint256 h_2_y;
        uint256 l_at_zeta;
        uint256 r_at_zeta;
        uint256 o_at_zeta;
        uint256 s1_at_zeta;
        uint256 s2_at_zeta;
        uint256 grand_product_commitment_x;
        uint256 grand_product_commitment_y;
        uint256 grand_product_at_zeta_omega;
        uint256 quotient_polynomial_at_zeta;
        uint256 linearization_polynomial_at_zeta;
        uint256 opening_at_zeta_proof_x;
        uint256 opening_at_zeta_proof_y;
        uint256 opening_at_zeta_omega_proof_x;
        uint256 opening_at_zeta_omega_proof_y;
        uint256[] selector_commit_api_at_zeta;
        uint256[] wire_committed_commitments;
        
    }

    function get_proof() 
    internal pure returns (bytes memory)
    {
        bytes memory res;

        Proof memory proof;

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
        res = abi.encodePacked(res, proof.selector_commit_api_at_zeta[0]);
        proof.wire_committed_commitments = new uint256[](2);
        proof.wire_committed_commitments[0] =  15552480929910802332205434009033658529300932452690724290794850059288694568607;
        proof.wire_committed_commitments[1] =  4106131824108708883155969901844611304524714469488967324682353598451772881497;
        
        res = abi.encodePacked(
        res,
        proof.wire_committed_commitments[0],
        proof.wire_committed_commitments[1]
        );

        return res;
    }

}