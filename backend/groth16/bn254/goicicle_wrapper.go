package groth16

import (
	"runtime"
	"sync"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/ingonyama-zk/icicle/goicicle/curves/bn254"
)

// Execute process in parallel the work function
func Execute(nbIterations int, work func(int, int), maxCpus ...int) {

	nbTasks := runtime.NumCPU()
	if len(maxCpus) == 1 {
		nbTasks = maxCpus[0]
		if nbTasks < 1 {
			nbTasks = 1
		} else if nbTasks > 512 {
			nbTasks = 512
		}
	}

	if nbTasks == 1 {
		// no go routines
		work(0, nbIterations)
		return
	}

	nbIterationsPerCpus := nbIterations / nbTasks

	// more CPUs than tasks: a CPU will work on exactly one iteration
	if nbIterationsPerCpus < 1 {
		nbIterationsPerCpus = 1
		nbTasks = nbIterations
	}

	var wg sync.WaitGroup

	extraTasks := nbIterations - (nbTasks * nbIterationsPerCpus)
	extraTasksOffset := 0

	for i := 0; i < nbTasks; i++ {
		wg.Add(1)
		_start := i*nbIterationsPerCpus + extraTasksOffset
		_end := _start + nbIterationsPerCpus
		if extraTasks > 0 {
			_end++
			extraTasks--
			extraTasksOffset++
		}
		go func() {
			work(_start, _end)
			wg.Done()
		}()
	}

	wg.Wait()
}

/*
* Adapters - these adapters convert between icicle and gnark
* todo: add conditional rendering
 */

func NttBN254GnarkAdapter(domain *fft.Domain, coset bool, scalars []fr.Element, isInverse bool, decimation int, deviceId int) []fr.Element {
	if coset && !isInverse {
		scale := func(cosetTable []fr.Element) {
			Execute(len(scalars), func(start, end int) {
				for i := start; i < end; i++ {
					scalars[i].Mul(&scalars[i], &cosetTable[i])
				}
			}, runtime.NumCPU())
		}
		if decimation == bn254.DIT {
			scale(domain.CosetTableReversed)
		} else {
			scale(domain.CosetTable)
		}
	}

	nttResult := bn254.BatchConvertFromFrGnark[bn254.ScalarField](scalars)
	bn254.NttBN254(&nttResult, isInverse, decimation, deviceId)

	if coset && isInverse {
		res := bn254.BatchConvertToFrGnark[bn254.ScalarField](nttResult)

		scale := func(cosetTable []fr.Element) {
			Execute(len(res), func(start, end int) {
				for i := start; i < end; i++ {
					res[i].Mul(&res[i], &cosetTable[i])
				}
			}, runtime.NumCPU())
		}
		if decimation == bn254.DIT {
			scale(domain.CosetTableInv)
		} else {
			scale(domain.CosetTableInvReversed)
		}

		return res
	}

	return bn254.BatchConvertToFrGnark[bn254.ScalarField](nttResult)
}

func MsmBN254GnarkAdapter(points []curve.G1Affine, scalars []fr.Element) (curve.G1Jac, error) {
	out := new(bn254.PointBN254)
	parsedScalars := bn254.BatchConvertFromFrGnark[bn254.ScalarField](scalars)
	parsedPoints := bn254.BatchConvertFromG1Affine(points)

	_, err := bn254.MsmBN254(out, parsedPoints, parsedScalars, 0)

	return *out.ToGnarkJac(), err
}
