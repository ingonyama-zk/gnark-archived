package groth16

import (
	icicle "goicicle/curves/bn254"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

/*
* Adapters - these adapters convert between icicle and gnark
* todo: add conditional rendering
 */

func NttBN254GnarkAdapter(scalars []fr.Element, isInverse bool, decimation int, deviceId int) []fr.Element {
	nttResult := icicle.BatchConvertFromFrGnark[icicle.ScalarField](scalars)
	icicle.NttBN254(&nttResult, isInverse, decimation, deviceId)

	return icicle.BatchConvertToFrGnark[icicle.ScalarField](nttResult)
}

func MsmBN254GnarkAdapter(points []curve.G1Affine, scalars []fr.Element) (curve.G1Jac, error) {
	out := new(icicle.PointBN254)
	parsedScalars := icicle.BatchConvertFromFrGnark[icicle.ScalarField](scalars)
	parsedPoints := icicle.BatchConvertFromG1Affine(points)

	_, err := icicle.MsmBN254(out, parsedPoints, parsedScalars, 0)

	return *out.ToGnarkJac(), err
}
