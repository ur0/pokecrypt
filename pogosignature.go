package crypto

import (
	"encoding/binary"
	"log"
	"runtime"
	"math"
)

const (
	hashLocation1 = iota
	hashLocation2
	hashRequest
)

type HashRequest struct {
	HashType   int
	Lat        float64
	Lng        float64
	Alt        float64
	AuthTicket []byte
	Request    []byte

	Result chan uint64
}

func locationToBuffer(lat, lng, alt float64) []byte {
	buffer := make([]byte, 24)

	binary.BigEndian.PutUint64(buffer[0:], math.Float64bits(lat))
	binary.BigEndian.PutUint64(buffer[8:], math.Float64bits(lng))
	binary.BigEndian.PutUint64(buffer[16:], math.Float64bits(alt))

	return buffer
}

type PogoSignature struct {
	requestChannel chan *HashRequest
}

func NewPogoSignature() *PogoSignature {
	return &PogoSignature{
		make(chan *HashRequest),
	}
}

func (ps *PogoSignature) ProcessSignatureRequests() error {
	runtime.LockOSThread()

	nh, err := NewNianticHash()
	if err != nil {
		log.Fatal(err)
	}

	for {
		hr := <-ps.requestChannel

		switch hr.HashType {
		case hashLocation1:
			seed, err := nh.Hash32(hr.AuthTicket)
			if err != nil {
				log.Printf("HashLocation1(): Unicorn returned error: %v", err)
				hr.Result <- 0
				continue
			}

			payload := locationToBuffer(hr.Lat, hr.Lng, hr.Alt)

			hash, err := nh.Hash32Salt(payload, seed)
			if err != nil {
				log.Printf("HashLocation1(): Unicorn returned error: %v", err)
				hr.Result <- 0
				continue
			}

			hr.Result <- uint64(hash)
		case hashLocation2:
			payload := locationToBuffer(hr.Lat, hr.Lng, hr.Alt)
			hash, err := nh.Hash32(payload)
			if err != nil {
				log.Printf("HashLocation2(): Unicorn returned error: %v", err)
				hr.Result <- 0
				continue
			}
			hr.Result <- uint64(hash)
		case hashRequest:
			seed, err := nh.Hash64(hr.AuthTicket)
			if err != nil {
				log.Printf("HashRequest(): Unicorn returned error: %v", err)
				hr.Result <- 0
				continue
			}

			hash, err := nh.Hash64Salt64(hr.Request, seed)
			if err != nil {
				log.Printf("HashRequest(): Unicorn returned error: %v", err)
				hr.Result <- 0
				continue
			}

			hr.Result <- hash
		}
	}
}

func (ps *PogoSignature) HashLocation1(authTicket []byte, lat, lng, alt float64) uint32 {
	resultChannel := make(chan uint64, 1)
	ps.requestChannel <- &HashRequest{
		HashType:   hashLocation1,
		AuthTicket: authTicket,
		Lat:        lat,
		Lng:        lng,
		Alt:        alt,
		Result:     resultChannel,
	}
	return uint32(<-resultChannel)
}

func (ps *PogoSignature) HashLocation2(lat, lng, alt float64) uint32 {
	resultChannel := make(chan uint64, 1)
	ps.requestChannel <- &HashRequest{
		HashType: hashLocation2,
		Lat:      lat,
		Lng:      lng,
		Alt:      alt,
		Result:   resultChannel,
	}
	return uint32(<-resultChannel)
}

func (ps *PogoSignature) HashRequest(authTicket, request []byte) uint64 {
	resultChannel := make(chan uint64, 1)
	ps.requestChannel <- &HashRequest{
		HashType:   hashRequest,
		AuthTicket: authTicket,
		Request:    request,
		Result:     resultChannel,
	}
	return <-resultChannel
}

func (ps *PogoSignature) Hash25() int64 {
	return 4773719081358681275
}
