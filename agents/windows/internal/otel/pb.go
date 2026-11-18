package otel

// pb.go - a minimal protobuf wire-format reader. It exists because the offline
// build has no protobuf library; it covers only what OTLP traces and logs need
// (varint, fixed32/64, length-delimited). Unknown fields are skipped, so newer
// OTLP versions decode as long as the fields we use keep their numbers.

import (
	"encoding/binary"
	"errors"
	"math"
)

var errPB = errors.New("otel: malformed protobuf")

const (
	wireVarint = 0
	wire64     = 1
	wireBytes  = 2
	wire32     = 5
)

// pbMaxDepth bounds message nesting (AnyValue arrays/kvlists can nest).
const pbMaxDepth = 8

type pbReader struct {
	b []byte
}

func (r *pbReader) done() bool { return len(r.b) == 0 }

func (r *pbReader) varint() (uint64, error) {
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		return 0, errPB
	}
	r.b = r.b[n:]
	return v, nil
}

// next reads a field header and returns the field number and wire type.
func (r *pbReader) next() (field int, wire int, err error) {
	k, err := r.varint()
	if err != nil {
		return 0, 0, err
	}
	if k>>3 == 0 || k>>3 > math.MaxInt32 {
		return 0, 0, errPB
	}
	return int(k >> 3), int(k & 7), nil
}

func (r *pbReader) bytes() ([]byte, error) {
	l, err := r.varint()
	if err != nil || l > uint64(len(r.b)) {
		return nil, errPB
	}
	out := r.b[:l]
	r.b = r.b[l:]
	return out, nil
}

func (r *pbReader) fixed64() (uint64, error) {
	if len(r.b) < 8 {
		return 0, errPB
	}
	v := binary.LittleEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v, nil
}

func (r *pbReader) fixed32() (uint32, error) {
	if len(r.b) < 4 {
		return 0, errPB
	}
	v := binary.LittleEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v, nil
}

// skip discards a field value of the given wire type.
func (r *pbReader) skip(wire int) error {
	switch wire {
	case wireVarint:
		_, err := r.varint()
		return err
	case wire64:
		_, err := r.fixed64()
		return err
	case wireBytes:
		_, err := r.bytes()
		return err
	case wire32:
		_, err := r.fixed32()
		return err
	}
	return errPB
}
