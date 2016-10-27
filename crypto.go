package pokecrypt // import "github.com/ur0/pokecrypt"

import (
  "math/rand"
)

type Pokecrypt struct{
  msSinceStart uint32
}

// CreateIV returns a new IV from the cRand spec
func (p *Pokecrypt) CreateIV() []byte {
  // Re-init struct
  p.msSinceStart = uint32(rand.Int31)

  // This is defunct now
  iv := make([]byte, 16)
  return iv
}

// Encrypt encrypts in with iv
func (p *Pokecrypt) Encrypt(in []byte, iv []byte) ([]byte, error) {
  return fpm_encrypt(in, p.msSinceStart)
}
