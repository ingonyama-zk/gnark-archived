// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity >=0.6.0;

// import {Fr} from './Fr.sol';

library Polynomials {

    // using Fr for *;

    uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function pow(uint256 x, uint256 power) 
    internal view returns(uint256) 
    {
        bool success;
        uint256 result;
        assembly {
          let mPtr := mload(0x40)
          mstore(mPtr, 0x20)
          mstore(add(mPtr, 0x20), 0x20)
          mstore(add(mPtr, 0x40), 0x20)
          mstore(add(mPtr, 0x60), x)
          mstore(add(mPtr, 0x80), power)
          mstore(add(mPtr, 0xa0), r_mod)
          success := staticcall(gas(),0x05,mPtr,0xc0,0x00,0x20)
          result := mload(0x00)
        }
        require(success);
        return result;
    }

    function inverse(uint256 x) 
    internal view returns(uint256) 
    {
      bool success;
        uint256 result;
        assembly {
          let mPtr := mload(0x40)
          mstore(mPtr, 0x20)
          mstore(add(mPtr, 0x20), 0x20)
          mstore(add(mPtr, 0x40), 0x20)
          mstore(add(mPtr, 0x60), x)
          mstore(add(mPtr, 0x80), sub(r_mod, 2))
          mstore(add(mPtr, 0xa0), r_mod)
          success := staticcall(gas(),0x05,mPtr,0xc0,0x00,0x20)
          result := mload(0x00)
        }
        require(success);
        return result;
    }

    function batch_inverse(uint256[] memory x) 
    internal view returns(uint256[] memory) 
    {
      uint n = x.length;
      uint256[] memory prod_ahead = new uint256[](n);  // prod[i] = x[i] * ... * x[n-1]
      uint256[] memory res = new uint256[](n);
      bool success;

      assembly {

        let s := mload(x)
     
        prod_ahead := add(prod_ahead, add(0x20, mul(sub(s,1), 0x20)))
        x := add(x, add(0x20, mul(sub(s,1), 0x20)))
        mstore(prod_ahead, mload(x))
        for {let i:=1} lt(i, s) {i:=add(i,1)} {
          x := sub(x, 0x20)
          let a := mulmod(mload(prod_ahead), mload(x), r_mod)
          prod_ahead := sub(prod_ahead, 0x20)
          mstore(prod_ahead, a)
        }

        let mPtr := mload(0x40)
        mstore(mPtr, 0x20)
        mstore(add(mPtr, 0x20), 0x20)
        mstore(add(mPtr, 0x40), 0x20)
        mstore(add(mPtr, 0x60), mload(prod_ahead))
        mstore(add(mPtr, 0x80), sub(r_mod, 2))
        mstore(add(mPtr, 0xa0), r_mod)
        success := staticcall(gas(),0x05,mPtr,0xc0,0x00,0x20)
        let inv := mload(0x00)

        let prod_behind := 1

        res := add(res, 0x20)
        prod_ahead := add(prod_ahead, 0x20)
        for {let i:=0} lt(i,sub(s,1)) {i:=add(i,1)}{
          mstore(res, mulmod(inv, prod_behind, r_mod))
          mstore(res, mulmod(mload(res), mload(prod_ahead), r_mod))
          prod_behind := mulmod(prod_behind, mload(x), r_mod)
          x := add(x, 0x20)
          res := add(res, 0x20)
          prod_ahead := add(prod_ahead, 0x20)
        }
        mstore(res, mulmod(inv, prod_behind, r_mod))

        res := sub(res, add(0x20, mul(0x20, sub(s, 1))))
      }
      require(success, "inverse failed!");

      return res;
    }

    function compute_sum_li_zi(uint256[] memory inputs, uint256 z, uint256 w, uint256 n) internal view returns(uint256){
        
        if (inputs.length == 0) {
            return 0;
        }
        uint256[] memory basis = batch_compute_lagranges_at_z(inputs.length, z, w, n);
        uint256 res;
        // uint256 r = Fr.r_mod;
        assembly {
            res := mulmod(mload(add(basis,0x20)),mload(add(inputs,0x20)), r_mod)
            for {let i:=1} lt(i,mload(inputs)) {i:=add(i,1)}
            {
                let a:=mulmod(mload(add(basis, add(0x20,mul(i, 0x20)))), mload(add(inputs, add(0x20,mul(i, 0x20)))), r_mod)
                res := addmod(res, a, r_mod)
            }
        }

        return res;
    }

    // computes L_0(z) = 1/n (z^n-1)/(z-1) and then recursively L_{i+1}(z) = L_i(z) * w * (z-w^i) / (z-w^{i+1}) for 0 <= i < k
    function batch_compute_lagranges_at_z(uint256 k, uint256 z, uint256 w, uint256 n) 
    internal view returns (uint256[] memory) {

        uint256[] memory den = new uint256[](k);
        uint256 wPowI = 1;
     
        assembly {
            den := add(den, 0x20)
            for {let i:=0} lt(i,sub(k, 1)) {i:=add(i,1)}
            {
                mstore(den, addmod(z, sub(r_mod, wPowI), r_mod))
                wPowI := mulmod(wPowI, w, r_mod)
                den := add(den, 0x20)
            }
            mstore(den, addmod(z, sub(r_mod, wPowI), r_mod))
            den := sub(den, mul(sub(k, 1), 0x20))
            mstore(den, mulmod(mload(den), n, r_mod))
            den := sub(den, 0x20)
        }
        // uint256[] memory res = Fr.batch_inverse(den);
        uint256[] memory res = batch_inverse(den);
        bool success;
        assembly {

            // wPowI <- z^n
            let mPtr := mload(0x40)
            mstore(mPtr, 0x20)
            mstore(add(mPtr, 0x20), 0x20)
            mstore(add(mPtr, 0x40), 0x20)
            mstore(add(mPtr, 0x60), z)
            mstore(add(mPtr, 0x80), n)
            mstore(add(mPtr, 0xa0), r_mod)
            success := staticcall(gas(),0x05,mPtr,0xc0,0x00,0x20)
            wPowI := mload(0x00)

            // wPowI <- z^n-1
            wPowI := addmod(wPowI, sub(r_mod, 1), r_mod)

            res := add(res, 0x20)
            mstore(res, mulmod(wPowI, mload(res), r_mod))
            den := add(den, 0x20)
            mstore(den, addmod(z, sub(r_mod,1), r_mod))
            
            for {let i:=1} lt(i,k) {i := add(i,1)}
            {
                res := add(res, 0x20)
                mstore(res, mulmod(mload(res), mload(den), r_mod))              // (z-w^i) / (z-w^{i+1})
                mstore(res, mulmod(mload(res), w, r_mod))                       //w * (z-w^i) / (z-w^{i+1})
                mstore(res, mulmod(mload(res), mload(sub(res, 0x20)), r_mod))   // L_i(z) * w * (z-w^i) / (z-w^{i+1})
                den := add(den, 0x20)
            }
            res := sub(res, mul(k, 0x20))
        }
        require(success, "batch_compute_lagranges_at_z failed!");

        return res;
    }
}