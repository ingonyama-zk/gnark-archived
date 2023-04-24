//go:build ignore

package sha2

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const chunk = 64

var (
	init0 = uints.NewU32(0x6A09E667)
	init1 = uints.NewU32(0xBB67AE85)
	init2 = uints.NewU32(0x3C6EF372)
	init3 = uints.NewU32(0xA54FF53A)
	init4 = uints.NewU32(0x510E527F)
	init5 = uints.NewU32(0x9B05688C)
	init6 = uints.NewU32(0x1F83D9AB)
	init7 = uints.NewU32(0x5BE0CD19)
)

type digest struct {
	h    [8]uints.U32
	x    [chunk]uints.U8 // 64 byte
	nx   int
	len  uint64
	api  frontend.API
	uapi *uints.BinaryField[uints.U32]
}

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
}

func New(api frontend.API) digest {
	res := digest{}
	// res.id = ecc.BN254
	res.api = api
	res.nx = 0
	res.len = 0
	res.Reset()
	return res
}

// p: byte array
func (d *digest) Write(p []frontend.Variable) (nn int, err error) {
	in := make([]uints.U8, len(p))
	for i := range p {
		in[i] = d.uapi.ByteValueOf(p[i])
	}
	return d.write(in)

}

func (d *digest) write(p []uints.U8) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)

	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			d.h = Permute(d.api, d.h, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}

	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		d.h = Permute(d.api, d.h, p[:n])
		p = p[n:]
	}

	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}

	return
}

func (d *digest) Sum() []frontend.Variable {

	d0 := *d
	hash := d0.checkSum()

	return hash[:]
}

func (d *digest) checkSum() []frontend.Variable {
	// Padding
	len := d.len
	var tmp [64]uints.U8
	tmp[0] = uints.NewU8(0x80)
	for i := 1; i < 64; i++ {
		tmp[i] = uints.NewU8(0x0)
	}
	if len%64 < 56 {
		d.write(tmp[0 : 56-len%64])
	} else {
		d.write(tmp[0 : 64+56-len%64])
	}

	// fill length bit
	len <<= 3
	PutUint64(d.api, tmp[:], newUint64API(d.api).asUint64(len))
	d.write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [32]xuint8

	// h[0]..h[7]
	PutUint32(d.api, digest[0:], d.h[0])
	PutUint32(d.api, digest[4:], d.h[1])
	PutUint32(d.api, digest[8:], d.h[2])
	PutUint32(d.api, digest[12:], d.h[3])
	PutUint32(d.api, digest[16:], d.h[4])
	PutUint32(d.api, digest[20:], d.h[5])
	PutUint32(d.api, digest[24:], d.h[6])
	PutUint32(d.api, digest[28:], d.h[7])

	var dv []frontend.Variable

	u8api := newUint8API(d.api)

	for i := 0; i < 32; i++ {
		dv[i] = uints.NewU8()
		dv = append(dv, u8api.fromUint8(digest[i]))
	}
	return dv
}
