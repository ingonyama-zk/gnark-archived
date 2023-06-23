package groth16

import (
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

func G2MultiExpWrapper(p *bn254.G2Jac, points []bn254.G2Affine, scalars []fr.Element, config ecc.MultiExpConfig) (*bn254.G2Jac, error) {
	defer TimeTrack(time.Now(), "MSM G2")
	return p.MultiExp(points, scalars, config)
}

func MultiExpWrapper(p *bn254.G1Jac, points []bn254.G1Affine, scalars []fr.Element, config ecc.MultiExpConfig) (*bn254.G1Jac, error) {
	defer TimeTrack(time.Now(), "MSM G1")
	return p.MultiExp(points, scalars, config)
}

func FFTWrapper(domain *fft.Domain, a []fr.Element, decimation fft.Decimation, opts ...fft.Option) {
	defer TimeTrack(time.Now(), "FFT")
	domain.FFT(a, decimation, opts...)
}

func FFTInverseWrapper(domain *fft.Domain, a []fr.Element, decimation fft.Decimation, opts ...fft.Option) {
	defer TimeTrack(time.Now(), "FFT INVERSE")
	domain.FFTInverse(a, decimation, opts...)
}
