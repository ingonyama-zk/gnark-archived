pragma solidity ^0.8.0;
    
import {PlonkVerifier} from './Verifier.sol';

contract TestVerifier {

    using PlonkVerifier for *;

    event PrintUint256(uint256 a);

    function test_verifier(bytes memory proof, uint256[] memory public_inputs) public {

        PlonkVerifier.Verify(proof, public_inputs);

    }


}