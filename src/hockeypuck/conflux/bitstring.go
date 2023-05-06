/*
   conflux - Distributed database synchronization library
	Based on the algorithm described in
		"Set Reconciliation with Nearly Optimal	Communication Complexity",
			Yaron Minsky, Ari Trachtenberg, and Richard Zippel, 2004.

   Copyright (c) 2012-2015  Casey Marshall <cmars@cmarstech.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Package conflux provides set reconciliation core functionality
// and the supporting math: polynomial arithmetic over finite fields,
// factoring and rational function interpolation.
//
// The Conflux API is versioned with gopkg. Use in your projects with:
//
// import "hockeypuck/conflux"
package conflux

import (
	"bytes"
	"fmt"
	"math/big"
)

// Bitstring describes a sequence of bits.
type Bitstring struct {
	buf  []byte
	bits int
}

// NewBitstream creates a new zeroed Bitstring of the specified number of bits.
func NewBitstring(bits int) *Bitstring {
	n := bits / 8
	if bits%8 != 0 {
		n++
	}
	return &Bitstring{buf: make([]byte, n), bits: bits}
}

// NewZpBitstring creates a new Bitstring from a Zp integer over a finite field.
func NewZpBitstring(zp *Zp) *Bitstring {
	bs := NewBitstring(zp.P().BitLen())
	bs.SetBytes(zp.Bytes())
	return bs
}

// BitLen returns the number of bits in the Bitstring.
func (bs *Bitstring) BitLen() int {
	return bs.bits
}

// ByteLen returns the number of bytes the Bitstring occupies in memory.
func (bs *Bitstring) ByteLen() int {
	return len(bs.buf)
}

func (bs *Bitstring) bitIndex(bit int) (int, uint) {
	return bit / 8, uint(bit % 8)
}

// Get returns the bit value at the given position.
// If the bit position is greater than the Bitstring size, or less than zero,
// Get panics.
func (bs *Bitstring) Get(bit int) int {
	if bit > bs.bits || bit < 0 {
		panic("bit index out of range")
	}
	bytePos, bitPos := bs.bitIndex(bit)
	if (bs.buf[bytePos] & (byte(1) << (8 - bitPos - 1))) != 0 {
		return 1
	}
	return 0
}

// Set sets the bit at the given position to a 1.
func (bs *Bitstring) Set(bit int) {
	if bit > bs.bits || bit < 0 {
		panic("bit index out of range")
	}
	bytePos, bitPos := bs.bitIndex(bit)
	bs.buf[bytePos] |= (byte(1) << (8 - bitPos - 1))
}

// Clear clears the bit at the given position to a 0.
func (bs *Bitstring) Clear(bit int) {
	if bit > bs.bits || bit < 0 {
		panic("bit index out of range")
	}
	bytePos, bitPos := bs.bitIndex(bit)
	bs.buf[bytePos] &^= (byte(1) << (8 - bitPos - 1))
}

// Flip inverts the bit at the given position.
func (bs *Bitstring) Flip(bit int) {
	if bit > bs.bits || bit < 0 {
		panic("bit index out of range")
	}
	bytePos, bitPos := bs.bitIndex(bit)
	bs.buf[bytePos] ^= (byte(1) << (8 - bitPos - 1))
}

// SetBytes sets the Bitstring bits to the contents of the given buffer. If the
// buffer is smaller than the Bitstring, the remaining bits are cleared.
func (bs *Bitstring) SetBytes(buf []byte) {
	for i := 0; i < len(bs.buf); i++ {
		if i < len(buf) {
			bs.buf[i] = buf[i]
		} else {
			bs.buf[i] = byte(0)
		}
	}
	bytePos, bitPos := bs.bitIndex(bs.bits)
	if bitPos != 0 {
		mask := ^((byte(1) << (8 - bitPos)) - 1)
		bs.buf[bytePos] &= mask
	}
}

// Lsh shifts all bits to the left by one position.
func (bs *Bitstring) Lsh(n uint) {
	i := big.NewInt(int64(0)).SetBytes(bs.buf)
	i.Lsh(i, n)
	bs.SetBytes(i.Bytes())
}

// Rsh shifts all bits to the right by one position.
func (bs *Bitstring) Rsh(n uint) {
	i := big.NewInt(int64(0)).SetBytes(bs.buf)
	i.Rsh(i, n)
	bs.SetBytes(i.Bytes())
}

// String renders the Bitstring to a string as a binary number.
func (bs *Bitstring) String() string {
	if bs == nil {
		return "nil"
	}
	w := bytes.NewBuffer(nil)
	for i := 0; i < bs.bits; i++ {
		fmt.Fprintf(w, "%d", bs.Get(i))
	}
	return w.String()
}

// Bytes returns a new buffer initialized to the contents of the Bitstring.
func (bs *Bitstring) Bytes() []byte {
	w := bytes.NewBuffer(nil)
	w.Write(bs.buf)
	return w.Bytes()
}
