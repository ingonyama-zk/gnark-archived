//go:build ignore

package sha2

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark/std/math/uints"
)

func str8(v uints.U8) string {
	switch vv := v.Val.(type) {
	case uint8:
		return fmt.Sprintf("%d", vv)
	case *big.Int:
		return vv.String()
	case big.Int:
		return vv.String()
	default:
		return "?"
	}
}

func str32(v uints.U32) string {
	switch v[0].Val.(type) {
	case uint8:
		res := uint32(v[0].Val.(uint8)) |
			(uint32(v[1].Val.(uint8)) << 8) |
			(uint32(v[2].Val.(uint8)) << 16) |
			(uint32(v[3].Val.(uint8)) << 24)
		return fmt.Sprintf("%d", res)
	case *big.Int:
		res := new(big.Int).Set(v[3].Val.(*big.Int))
		res.Lsh(res, 8)
		res.Add(res, v[2].Val.(*big.Int))
		res.Lsh(res, 8)
		res.Add(res, v[1].Val.(*big.Int))
		res.Lsh(res, 8)
		res.Add(res, v[0].Val.(*big.Int))
		return res.String()
	default:
		return "?"
	}
}

func str[T uints.U8 | uints.U32](v T) string {
	switch vv := any(v).(type) {
	case uints.U8:
		return str8(vv)
	case uints.U32:
		return str32(vv)
	}
	panic("")
}

func printArray[T uints.U8 | uints.U32](tag string, array []T) {
	a := make([]string, len(array)+1)
	a[0] = tag
	for i := range array {
		a[i+1] = str(array[i])
	}
	fmt.Println("CIRC", strings.Join(a, " "))
}

func PrintArray[T uint8 | uint32](tag string, array []T) {
	a := make([]string, len(array)+1)
	a[0] = tag
	for i := range array {
		a[i+1] = fmt.Sprintf("%d", array[i])
	}
	fmt.Println("REAL", strings.Join(a, " "))
}
