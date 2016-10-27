package crypto

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

const hashSeed uint32 = 0x61247FBF

type NianticHash struct {
}

	func NewNianticHash() (*NianticHash, error) {
		nh := &NianticHash{}
		return nh, nil
	}

func (nh *NianticHash) hash(buffer []byte) (uint64, error) {
	res := make([]byte, 8)

	conn, err := net.Dial("tcp", "127.0.0.1:1500")
	if err != nil {
		fmt.Println(err)
		return 0, err
	}
	conn.Write(buffer);

	numRead, err := conn.Read(res)
	if err != nil {
		fmt.Println(err)
		return 0, err
	}
	if (numRead == 0) {
		fmt.Printf("Connection closed by remote host\n")
		return 0, err
	}

	num := binary.LittleEndian.Uint64(res);
	fmt.Printf("%x\n", uint64(num))

	conn.Close()
	return num, nil;
}

func (nh *NianticHash) Hash32(buffer []byte) (uint32, error) {
	return nh.Hash32Salt(buffer, hashSeed)
}

func (nh *NianticHash) Hash32Salt(buffer []byte, salt uint32) (uint32, error) {
	ret, err := nh.Hash64Salt(buffer, salt)
	if err != nil {
		return 0, err
	}

	return uint32(ret) ^ uint32(ret>>32), nil
}

func (nh *NianticHash) Hash64(buffer []byte) (uint64, error) {
	return nh.Hash64Salt(buffer, hashSeed)
}

func (nh *NianticHash) Hash64Salt(buffer []byte, salt uint32) (uint64, error) {
	newBuffer := make([]byte, len(buffer)+4)
	binary.BigEndian.PutUint32(newBuffer, salt)
	copy(newBuffer[4:], buffer)

	return nh.hash(newBuffer)
}

func (nh *NianticHash) Hash64Salt64(buffer []byte, salt uint64) (uint64, error) {
	newBuffer := make([]byte, len(buffer)+8)
	binary.BigEndian.PutUint64(newBuffer, salt)
	copy(newBuffer[8:], buffer)

	return nh.hash(newBuffer)
}

func main() {
    buf := make([]byte, 0x18)
    res := make([]byte, 8)

    conn, err := net.Dial("tcp", "127.0.0.1:1500")
    if err != nil {
      fmt.Println(err)
      os.Exit(1)
    }
    conn.Write(buf);

    numRead, err := conn.Read(res)
    if err != nil {
      fmt.Println(err)
      os.Exit(1)
    }
    if (numRead == 0) {
      fmt.Printf("Connection closed by remote host\n")
      os.Exit(1)
    }

    num := binary.LittleEndian.Uint64(res);
    fmt.Printf("%x\n", uint64(num))

    conn.Close();
}
