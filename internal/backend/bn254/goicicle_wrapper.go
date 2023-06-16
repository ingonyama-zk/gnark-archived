package groth16

import (
	"icbn254/curves/bn254"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

/*
* Adapters - these adapters convert between icicle and gnark
* todo: add conditional rendering
 */

func NttBN254GnarkAdapter(scalars []fr.Element, isInverse bool, decimation int, deviceId int) []fr.Element {
	nttResult := bn254.BatchConvertFromFrGnark[bn254.ScalarField](scalars)
	bn254.NttBN254(&nttResult, isInverse, decimation, deviceId)

	return bn254.BatchConvertToFrGnark[bn254.ScalarField](nttResult)
}

func MsmBN254GnarkAdapter(points []curve.G1Affine, scalars []fr.Element) (curve.G1Jac, error) {
	out := new(bn254.PointBN254)
	parsedPoints := bn254.BatchConvertFromG1Affine(points)
	parsedScalars := bn254.BatchConvertFromFrGnark[bn254.ScalarField](scalars)

	_, err := bn254.MsmBN254(out, parsedPoints, parsedScalars, 0)

	return out.toGnarkJac(), err
}
