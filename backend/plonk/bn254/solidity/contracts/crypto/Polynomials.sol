// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity >=0.6.0;

import {Fr} from './Fr.sol';

library Polynomials {

    using Fr for *;

    function compute_sum_li_zi(uint256[] memory inputs, uint256 z, uint256 w, uint256 n) internal view returns(uint256){
        
        if (inputs.length == 0) {
            return 0;
        }
        uint256[] memory basis = batch_compute_lagranges_at_z(inputs.length, z, w, n);
        uint256 res;
        uint256 r = Fr.r_mod;
        assembly {
            res := mulmod(mload(add(basis,0x20)),mload(add(inputs,0x20)), r)
            for {let i:=1} lt(i,mload(inputs)) {i:=add(i,1)}
            {
                let a:=mulmod(mload(add(basis, add(0x20,mul(i, 0x20)))), mload(add(inputs, add(0x20,mul(i, 0x20)))), r)
                res := addmod(res, a, r)
            }
        }

        return res;
    }

    // computes L_i(z) = w^j/n (z^n-1)/(z-w^j)
    function compute_ith_lagrange_at_z(uint256 i, uint256 z, uint256 w, uint256 n) 
    internal view returns (uint256) {

        require(i<n);
        require(z<Fr.r_mod);
        require(w<Fr.r_mod);

        uint256 r_mod = Fr.r_mod;
        assembly {

            // _n^_i [_p]
            function pow_local(_n, _i, _p)->result {
                let mPtr := mload(0x40)
                mstore(mPtr, 0x20)
                mstore(add(mPtr, 0x20), 0x20)
                mstore(add(mPtr, 0x40), 0x20)
                mstore(add(mPtr, 0x60), _n)
                mstore(add(mPtr, 0x80), _i)
                mstore(add(mPtr, 0xa0), _p)
                pop(staticcall(gas(),0x05,mPtr,0xc0,0x00,0x20))
                result := mload(0x00)
            }

            // w**i
            w := pow_local(w,i,r_mod)

            // z-w**i
            i := addmod(z, sub(r_mod, w), r_mod)

            // z**n
            z := pow_local(z, n, r_mod)

            // z**n-1
            z := addmod(z, sub(r_mod, 1), r_mod)

             // n**-1
            n := pow_local(n, sub(r_mod,2), r_mod)

            // w**i/n
            w := mulmod(w, n, r_mod)

            // (z-w**i)**-1
            i := pow_local(i, sub(r_mod,2),r_mod)

            // w**i/n*(z-w**i)**-1
            w := mulmod(w, i, r_mod)

            // w**i/n*(z**n-1)*(z-w**i)**-1
            w := mulmod(w, z, r_mod)
        }
        // require(success, "compute_ith_lagrange_at_z failed!");
        
        return w;
    }

    // computes L_0(z) = 1/n (z^n-1)/(z-1) and then recursively L_{i+1}(z) = L_i(z) * w * (z-w^i) / (z-w^{i+1}) for 0 <= i < k
    function batch_compute_lagranges_at_z(uint256 k, uint256 z, uint256 w, uint256 n) 
    internal view returns (uint256[] memory) {

        uint256 r = Fr.r_mod;
        uint256[] memory den = new uint256[](k);
        uint256 wPowI = 1;
     
        assembly {
            den := add(den, 0x20)
            for {let i:=0} lt(i,sub(k, 1)) {i:=add(i,1)}
            {
                mstore(den, addmod(z, sub(r, wPowI), r))
                wPowI := mulmod(wPowI, w, r)
                den := add(den, 0x20)
            }
            mstore(den, addmod(z, sub(r, wPowI), r))
            den := sub(den, mul(sub(k, 1), 0x20))
            mstore(den, mulmod(mload(den), n, r))
            den := sub(den, 0x20)
        }
        uint256[] memory res = Fr.batch_inverse(den);
        bool success;
        assembly {

            // wPowI <- z^n
            let mPtr := mload(0x40)
            mstore(mPtr, 0x20)
            mstore(add(mPtr, 0x20), 0x20)
            mstore(add(mPtr, 0x40), 0x20)
            mstore(add(mPtr, 0x60), z)
            mstore(add(mPtr, 0x80), n)
            mstore(add(mPtr, 0xa0), r)
            success := staticcall(gas(),0x05,mPtr,0xc0,0x00,0x20)
            wPowI := mload(0x00)

            // wPowI <- z^n-1
            wPowI := addmod(wPowI, sub(r, 1), r)

            res := add(res, 0x20)
            mstore(res, mulmod(wPowI, mload(res), r))
            den := add(den, 0x20)
            mstore(den, addmod(z, sub(r,1), r))
            
            for {let i:=1} lt(i,k) {i := add(i,1)}
            {
                res := add(res, 0x20)
                mstore(res, mulmod(mload(res), mload(den), r))              // (z-w^i) / (z-w^{i+1})
                mstore(res, mulmod(mload(res), w, r))                       //w * (z-w^i) / (z-w^{i+1})
                mstore(res, mulmod(mload(res), mload(sub(res, 0x20)), r))   // L_i(z) * w * (z-w^i) / (z-w^{i+1})
                den := add(den, 0x20)
            }
            res := sub(res, mul(k, 0x20))
        }
        require(success, "batch_compute_lagranges_at_z failed!");

        return res;
    }
}