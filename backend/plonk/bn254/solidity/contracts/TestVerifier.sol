pragma solidity ^0.8.0;
    
import {PlonkVerifier} from './Verifier.sol';
import {TestProof} from './TestProof.sol';

contract TestVerifier {

    using PlonkVerifier for *;
    using TestProof for *;

    event PrintUint256(uint256 a);

    function test_verifier() 
    public {

        uint256[] memory public_inputs = new uint256[](3);
        public_inputs[0] = 6;
        public_inputs[1] = 7;
        public_inputs[2] = 8;

        bytes memory proof = TestProof.get_proof();

        PlonkVerifier.Verify(proof, public_inputs);

    }


}