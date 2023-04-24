package uints

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/internal/logderivprecomp"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/rangecheck"
)

// TODO: if internal then enforce range check!

// TODO: all operations can take rand linear combinations instead. Then instead
// of one check can perform multiple at the same time.

// TODO: implement versions which take multiple inputs. Maybe can combine multiple together

// TODO: instantiate tables only when we first query. Maybe do not need to build!

// TODO: maybe can store everything in a single table? Later! Or if we have a
// lot of queries then makes sense to extract into separate table?

// TODO: in ValueOf ensure consistency

// TODO: distinguish between when we set constant in-circuit or witness
// assignment. For constant we don't have to range check but for witness
// assignment we have to.

type U8 struct {
	Val      frontend.Variable
	internal bool
}

// GnarkInitHook describes how to initialise the element.
func (e *U8) GnarkInitHook() {
	fmt.Println("here")
	if e.Val == nil {
		e.Val = 0
		e.internal = false // we need to constrain in later.
	}
}

type U64 [8]U8
type U32 [4]U8

type Long interface{ U32 | U64 }

type BinaryField[T U32 | U64] struct {
	api        frontend.API
	xorT, andT *logderivprecomp.Precomputed
	rchecker   frontend.Rangechecker
	allOne     U8
}

func New[T Long](api frontend.API) (*BinaryField[T], error) {
	xorT, err := logderivprecomp.New(api, xorHint, []uint{8})
	if err != nil {
		return nil, fmt.Errorf("new xor table: %w", err)
	}
	andT, err := logderivprecomp.New(api, andHint, []uint{8})
	if err != nil {
		return nil, fmt.Errorf("new and table: %w", err)
	}
	rchecker := rangecheck.New(api)
	bf := &BinaryField[T]{
		api:      api,
		xorT:     xorT,
		andT:     andT,
		rchecker: rchecker,
	}
	// TODO: this is const. add way to init constants
	allOne := bf.ByteValueOf(0xff)
	bf.allOne = allOne
	return bf, nil
}

func NewU8(v uint8) U8 {
	// TODO: don't have to check constants
	return U8{Val: v, internal: true}
}

func NewU32(v uint32) U32 {
	return [4]U8{
		NewU8(uint8((v >> (0 * 8)) & 0xff)),
		NewU8(uint8((v >> (1 * 8)) & 0xff)),
		NewU8(uint8((v >> (2 * 8)) & 0xff)),
		NewU8(uint8((v >> (3 * 8)) & 0xff)),
	}
}

func NewU64(v uint64) U64 {
	return [8]U8{
		NewU8(uint8((v >> (0 * 8)) & 0xff)),
		NewU8(uint8((v >> (1 * 8)) & 0xff)),
		NewU8(uint8((v >> (2 * 8)) & 0xff)),
		NewU8(uint8((v >> (3 * 8)) & 0xff)),
		NewU8(uint8((v >> (4 * 8)) & 0xff)),
		NewU8(uint8((v >> (5 * 8)) & 0xff)),
		NewU8(uint8((v >> (6 * 8)) & 0xff)),
		NewU8(uint8((v >> (7 * 8)) & 0xff)),
	}
}

func NewU8Array(v []uint8) []U8 {
	ret := make([]U8, len(v))
	for i := range v {
		ret[i] = NewU8(v[i])
	}
	return ret
}

func NewU32Array(v []uint32) []U32 {
	ret := make([]U32, len(v))
	for i := range v {
		ret[i] = NewU32(v[i])
	}
	return ret
}

func NewU64Array(v []uint64) []U64 {
	ret := make([]U64, len(v))
	for i := range v {
		ret[i] = NewU64(v[i])
	}
	return ret
}

func (bf *BinaryField[T]) ByteValueOf(a frontend.Variable) U8 {
	bf.rchecker.Check(a, 8)
	return U8{Val: a, internal: true}
}

func (bf *BinaryField[T]) ValueOf(a frontend.Variable) T {
	var r T
	bts, err := bf.api.Compiler().NewHint(toBytes, len(r), len(r), a)
	if err != nil {
		panic(err)
	}
	// TODO: add constraint which ensures that map back to
	for i := range bts {
		r[i] = bf.ByteValueOf(bts[i])
	}
	return r
}

func (bf *BinaryField[T]) ToValue(a T) frontend.Variable {
	v := make([]frontend.Variable, len(a))
	for i := range v {
		v[i] = bf.api.Mul(a[i].Val, 1<<(i*8))
	}
	vv := bf.api.Add(v[0], v[1], v[2:]...)
	return vv
}

func (bf *BinaryField[T]) PackMSB(a ...U8) T {
	var ret T
	for i := range a {
		ret[len(a)-i-1] = a[i]
	}
	return ret
}

func (bf *BinaryField[T]) PackLSB(a ...U8) T {
	var ret T
	for i := range a {
		ret[i] = a[i]
	}
	return ret
}

func (bf *BinaryField[T]) twoArgFn(tbl *logderivprecomp.Precomputed, a ...U8) U8 {
	ret := tbl.Query(a[0].Val, a[1].Val)[0]
	for i := 2; i < len(a); i++ {
		ret = tbl.Query(ret, a[i].Val)[0]
	}
	return U8{Val: ret}
}

func (bf *BinaryField[T]) and(a ...U8) U8 { return bf.twoArgFn(bf.andT, a...) }
func (bf *BinaryField[T]) xor(a ...U8) U8 { return bf.twoArgFn(bf.xorT, a...) }

func (bf *BinaryField[T]) twoArgWideFn(tbl *logderivprecomp.Precomputed, a ...T) T {
	var r T
	for i, v := range reslice(a) {
		r[i] = bf.twoArgFn(tbl, v...)
	}
	return r
}

func (bf *BinaryField[T]) And(a ...T) T { return bf.twoArgWideFn(bf.andT, a...) }
func (bf *BinaryField[T]) Xor(a ...T) T { return bf.twoArgWideFn(bf.xorT, a...) }

func (bf *BinaryField[T]) not(a U8) U8 {
	ret := bf.xorT.Query(a.Val, bf.allOne.Val)
	return U8{Val: ret[0]}
}

func (bf *BinaryField[T]) Not(a T) T {
	var r T
	for i := 0; i < len(a); i++ {
		r[i] = bf.not(a[i])
	}
	return r
}

func (bf *BinaryField[T]) Add(a ...T) T {
	va := make([]frontend.Variable, len(a))
	for i := range a {
		va[i] = bf.ToValue(a[i])
	}
	vres := bf.api.Add(va[0], va[1], va[2:]...)
	res := bf.ValueOf(vres)
	// TODO: should also check the that carry we omitted is correct.
	return res
}

// TODO: implement Rrot?

func (bf *BinaryField[T]) Lrot(a T, c int) T {
	// TODO: think about it bit more. Right now just want to get working.
	v := bf.xxxToVar(a)
	b := len(a) * 8
	res := make([]frontend.Variable, b)
	for i := range res {
		res[i] = v[(i-c+b)%b]
	}
	return bf.xxxFromVar(res)
}

func (bf *BinaryField[T]) Rshift(a T, c int) T {
	// TODO: think about it bit more. Right now just want to get working.
	v := bf.xxxToVar(a)
	b := len(a) * 8
	res := make([]frontend.Variable, b)
	for i := 0; i < len(res)-c; i++ {
		res[i] = v[i+c]
	}
	for i := len(res) - c; i < len(res); i++ {
		res[i] = 0
	}
	return bf.xxxFromVar(res)
}

func (bf *BinaryField[T]) xxxToVar(a T) []frontend.Variable {
	vv := bf.ToValue(a)
	ret := make([]frontend.Variable, len(a)*8)
	bts := bits.ToBinary(bf.api, vv, bits.WithNbDigits(len(ret)))
	for i := range ret {
		ret[i] = bts[i]
	}
	return ret
}

func (bf *BinaryField[T]) xxxFromVar(a []frontend.Variable) T {
	var ret T
	for i := 0; i < len(ret); i++ {
		v := bits.FromBinary(bf.api, a[8*i:8*i+8])
		ret[i] = U8{Val: v, internal: true}
	}
	return ret
}

func (bf *BinaryField[T]) assertEq(a, b U8) {
	bf.api.AssertIsEqual(a.Val, b.Val)
}

func (bf *BinaryField[T]) AssertEq(a, b T) {
	for i := 0; i < len(a); i++ {
		bf.assertEq(a[i], b[i])
	}
}

func xorHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Xor(inputs[0], inputs[1])
	return nil
}

func andHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].And(inputs[0], inputs[1])
	return nil
}

func orHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Or(inputs[0], inputs[1])
	return nil
}

func addHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Add(inputs[0], inputs[1])
	outputs[0].And(outputs[0], big.NewInt((1<<8)-1))
	return nil
}

func toBytes(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("input must be 2 elements")
	}
	if !inputs[0].IsUint64() {
		return fmt.Errorf("first input must be uint64")
	}
	nbLimbs := int(inputs[0].Uint64())
	if len(outputs) != nbLimbs {
		return fmt.Errorf("output must be 8 elements")
	}
	if !inputs[1].IsUint64() {
		return fmt.Errorf("input must be 64 bits")
	}
	base := new(big.Int).Lsh(big.NewInt(1), uint(8))
	tmp := new(big.Int).Set(inputs[1])
	for i := 0; i < nbLimbs; i++ {
		outputs[i].Mod(tmp, base)
		tmp.Rsh(tmp, 8)
	}
	return nil
}

func reslice[T U32 | U64](in []T) [][]U8 {
	if len(in) == 0 {
		panic("zero-length input")
	}
	ret := make([][]U8, len(in[0]))
	for i := range ret {
		ret[i] = make([]U8, len(in))
	}
	for i := 0; i < len(in); i++ {
		for j := 0; j < len(in[0]); j++ {
			ret[j][i] = in[i][j]
		}
	}
	return ret
}
