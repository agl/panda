package panda

import (
	"bytes"
	"crypto/rand"
	"testing"
)

type pair struct {
	a, b []byte
}

type Server struct {
	tags map[string]*pair
}

func (s *Server) Transact(tag, message []byte) []byte {
	t := string(tag)
	p, ok := s.tags[t]
	if !ok {
		p = new(pair)
		s.tags[t] = p
	}

	switch {
	case len(p.a) == 0:
		p.a = append([]byte(nil), message...)
		return nil
	case len(p.b) == 0:
		if bytes.Equal(p.a, message) {
			return nil
		}
		p.b = append([]byte(nil), message...)
		return append([]byte(nil), p.a...)
	}

	if bytes.Equal(p.a, message) {
		return append([]byte(nil), p.b...)
	}
	if bytes.Equal(p.b, message) {
		return append([]byte(nil), p.a...)
	}
	panic("collision")
}

func marshalUnmarshal(ex *Exchange) *Exchange {
	marshaled := ex.Marshal()
	duplicate, err := Unmarshal(marshaled)
	if err != nil {
		panic(err)
	}
	return duplicate
}

func TestPANDA(t *testing.T) {
	testingMode = true

	aMessage := []byte("0123456789")
	bMessage := []byte("abcdefghij")
	key := []byte("foo")
	a, err := New(rand.Reader, key, aMessage)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(rand.Reader, key, bMessage)
	if err != nil {
		t.Fatal(err)
	}
	a = marshalUnmarshal(a)
	b = marshalUnmarshal(b)

	server := &Server{make(map[string]*pair)}

	var aResult, bResult []byte

	for len(aResult) == 0 || len(bResult) == 0 {
		if len(aResult) == 0 {
			tag, msg := a.NextRequest()
			reply := server.Transact(tag, msg)
			if len(reply) > 0 {
				a = marshalUnmarshal(a)
				if aResult, err = a.Process(reply); err != nil {
					t.Fatalf("Error from a: %s", err)
				}
			}
		}

		if len(bResult) == 0 {
			tag, msg := b.NextRequest()
			reply := server.Transact(tag, msg)
			if len(reply) > 0 {
				b = marshalUnmarshal(b)
				if bResult, err = b.Process(reply); err != nil {
					t.Fatalf("Error from b: %s", err)
				}
			}
		}
	}

	if !bytes.Equal(aMessage, bResult) {
		t.Errorf("got %x from b, expected %x", bResult, aMessage)
	}
	if !bytes.Equal(bMessage, aResult) {
		t.Errorf("got %x from a, expected %x", aResult, bMessage)
	}
}
