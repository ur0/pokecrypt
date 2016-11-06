package pokecrypt // import "github.com/ur0/pokecrypt"

type Pokecrypt struct {
	msSinceStart uint32
}

func New() Pokecrypt {
	return Pokecrypt{}
}

// CreateIV returns a new IV from the cRand spec
func (p *Pokecrypt) CreateIV(ts uint32) []byte {
	// Re-init struct
	p.msSinceStart = ts

	// This is defunct now
	iv := make([]byte, 16)
	return iv
}

// Encrypt encrypts in with iv
func (p *Pokecrypt) Encrypt(in, _ []byte) ([]byte, error) {
	r := fpm_encrypt(in, p.msSinceStart)
	return r, nil
}

func (p *Pokecrypt) Enabled() bool {
	return true
}
