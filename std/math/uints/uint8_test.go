package uints

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type lrotCirc struct {
	In    frontend.Variable
	Shift int
	Out   frontend.Variable
}

func (c *lrotCirc) Define(api frontend.API) error {
	uapi, err := New[U64](api)
	if err != nil {
		return err
	}
	in := uapi.ValueOf(c.In)
	out := uapi.ValueOf(c.Out)
	res := uapi.Lrot(in, c.Shift)
	uapi.AssertEq(out, res)
	return nil
}

func TestLeftRotation(t *testing.T) {
	assert := test.NewAssert(t)
	err := test.IsSolved(&lrotCirc{Shift: 2}, &lrotCirc{In: 6, Shift: 2, Out: 24}, ecc.BN254.ScalarField())
	assert.NoError(err)
	// assert.ProverSucceeded(&lrotCirc{Shift: 2}, &lrotCirc{In: 6, Shift: 2, Out: 24})
}

type tofromCirc struct {
	In frontend.Variable
}

func (c *tofromCirc) Define(api frontend.API) error {
	uapi, err := New[U64](api)
	if err != nil {
		return err
	}
	v := uapi.ValueOf(c.In)
	vv := uapi.xxxToVar(v)
	vvv := uapi.xxxFromVar(vv)
	uapi.AssertEq(v, vvv)
	return nil
}

func TestToFromCirc(t *testing.T) {
	circuit := tofromCirc{}
	witness := tofromCirc{In: 2305980498363120175}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type rshiftCircuit struct {
	In, Expected U32
	Shift        int
}

func (c *rshiftCircuit) Define(api frontend.API) error {
	uapi, err := New[U32](api)
	if err != nil {
		return err
	}
	res := uapi.Rshift(c.In, c.Shift)
	uapi.AssertEq(res, c.Expected)
	return nil
}

func TestRshift(t *testing.T) {
	assert := test.NewAssert(t)
	var err error
	err = test.IsSolved(&rshiftCircuit{Shift: 4}, &rshiftCircuit{Shift: 4, In: NewU32(0x12345678), Expected: NewU32(0x1234567)}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&rshiftCircuit{Shift: 12}, &rshiftCircuit{Shift: 12, In: NewU32(0x12345678), Expected: NewU32(0x12345)}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&rshiftCircuit{Shift: 3}, &rshiftCircuit{Shift: 3, In: NewU32(0x12345678), Expected: NewU32(0x2468acf)}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&rshiftCircuit{Shift: 11}, &rshiftCircuit{Shift: 11, In: NewU32(0x12345678), Expected: NewU32(0x2468a)}, ecc.BN254.ScalarField())
	assert.NoError(err)
}
