package mcpackets

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type Packet struct {
	Bytes  []byte
	Size   int
	Offset int
}

type EncryptionHolder struct {
	LocalBoundCryptoStream cipher.Stream
	RemoteBoundCryptoStream cipher.Stream
}

func NewEncryptionHolder(sharedSecret []byte) EncryptionHolder {
	e,  _ := aes.NewCipher(sharedSecret)
	e2, _ := aes.NewCipher(sharedSecret)
	return EncryptionHolder{
		LocalBoundCryptoStream: NewCFB8(e, sharedSecret, true),
		RemoteBoundCryptoStream: NewCFB8(e2, sharedSecret, false),
	}
}
func (c EncryptionHolder) EncryptPacket(p Packet) []byte {
	out := make([]byte, p.Size)
	c.RemoteBoundCryptoStream.XORKeyStream(p.Bytes, out)
	return out
}
func (c EncryptionHolder) DecryptPacket(p []byte) Packet {
	out := make([]byte, len(p))
	c.LocalBoundCryptoStream.XORKeyStream(p, out)
	return NewPacket_A(out)
}

// Constructor mayhem

// Create Packet from Array
func NewPacket_A(arr []byte) Packet {
	return Packet{
		Bytes:  arr,
		Size:   len(arr),
		Offset: 0,
	}
}

// Create empty Packet from size
func NewPacket_S(size int) Packet {
	return Packet{
		Bytes:  make([]byte, size),
		Size:   size,
		Offset: 0,
	}
}

func (p *Packet) WriteByte(r byte) {
	size := &p.Size     // Optimize away manually to obfuscate my code :^)
	offset := &p.Offset // Ditto
	if *offset+1 > *size {
		*size = *offset + 1
		p.Bytes = append(p.Bytes, 0)
	}
	p.Bytes[*offset] = r
	*offset += 1
}
func (p *Packet) ReadByte() byte {
	offset := &p.Offset // Cruel optimizations.
	*offset += 1
	return p.Bytes[*offset-1]
}

func (p *Packet) WriteShort(r uint16) {
	size := &p.Size     // Optimize away manually to obfuscate my code :^)
	offset := &p.Offset // Ditto
	if *offset+2 > *size {
		add   := 2 - (*size - *offset)
		*size += add
		p.Bytes  = append(p.Bytes, make([]byte, add)...)
	}
	p.Bytes[*offset] = byte(r & 0xFF)
	p.Bytes[*offset+1] = byte((r >> 8) & 0xFF)
	*offset += 2
}
func (p *Packet) ReadShort() uint16 {
	offset := &p.Offset // Cruel optimizations.
	*offset += 2
	return uint16(p.Bytes[*offset-2]) | uint16(p.Bytes[*offset-1]) << 8
}

func (p *Packet) WriteInt(r uint32) {
	size := &p.Size     // Optimize away manually to obfuscate my code :^)
	offset := &p.Offset // Ditto
	if *offset+4 > *size {
		add   := 4 - (*size - *offset)
		*size += add
		p.Bytes  = append(p.Bytes, make([]byte, add)...)
	}
	p.Bytes[*offset] = byte(r & 0xFF)
	p.Bytes[*offset+1] = byte((r >> 8) & 0xFF)
	p.Bytes[*offset+2] = byte((r >> 16) & 0xFF)
	p.Bytes[*offset+3] = byte((r >> 24) & 0xFF)
	*offset += 4
}
func (p *Packet) ReadInt() uint32 {
	offset := &p.Offset // Cruel optimizations.
	*offset += 4
	fmt.Println(p.Bytes[*offset-4])
	return uint32(p.Bytes[*offset-4]) | uint32(p.Bytes[*offset-3]) << 8 | uint32(p.Bytes[*offset-2]) << 16 | uint32(p.Bytes[*offset-1]) << 24
}

func (p *Packet) WriteLong(r uint64) {
	size := &p.Size     // Optimize away manually to obfuscate my code :^)
	offset := &p.Offset // Ditto
	if *offset+8 > *size {
		add   := 8 - (*size - *offset)
		*size += add
		p.Bytes  = append(p.Bytes, make([]byte, add)...)
	}
	p.Bytes[*offset] = byte(r & 0xFF)
	p.Bytes[*offset+1] = byte((r >> 8) & 0xFF)
	p.Bytes[*offset+2] = byte((r >> 16) & 0xFF)
	p.Bytes[*offset+3] = byte((r >> 24) & 0xFF)
	p.Bytes[*offset+4] = byte((r >> 32) & 0xFF)
	p.Bytes[*offset+5] = byte((r >> 40) & 0xFF)
	p.Bytes[*offset+6] = byte((r >> 48) & 0xFF)
	p.Bytes[*offset+7] = byte((r >> 56) & 0xFF)
	*offset += 8
}
func (p *Packet) ReadLong() uint64 {
	offset := &p.Offset // Cruel optimizations.
	*offset += 8
	return uint64(p.Bytes[*offset-8]) | uint64(p.Bytes[*offset-7]) << 8 | uint64(p.Bytes[*offset-6]) << 16 | uint64(p.Bytes[*offset-5]) << 24 |
		uint64(p.Bytes[*offset-4]) << 32 | uint64(p.Bytes[*offset-3]) << 40 | uint64(p.Bytes[*offset-2]) << 48 | uint64(p.Bytes[*offset-1]) << 56
}
func (p *Packet) WriteString(str string) {
	strlen := len(str)
	p.WriteVarInt(uint(strlen))
	size := &p.Size
	offset := &p.Offset
	if *offset + strlen > *size {
		add   := strlen - (*size - *offset)
		*size += add
		p.Bytes  = append(p.Bytes, make([]byte, add)...)
	}
	copy(p.Bytes[*offset:], str)
	*offset += len(str)
}
func (p *Packet) ReadString() string {
	offset := &p.Offset
	len := p.ReadVarInt()
	ret := p.Bytes[*offset:uint(*offset)+len]
	return string(ret)
}

// Use for VarLong aswell
func (p *Packet) WriteVarInt(r uint) {
	value := r
	for {
		temp := value & 0b01111111
		value >>= 7
		if value != 0 {
			temp |= 0b10000000
		}
		p.WriteByte(byte(temp))
		if value == 0 {
			break
		}
	}
	// @TODO: Cruel Optimizations
}

// Use for VarLong aswell
func (p *Packet) ReadVarInt() uint {
	result := 0
	i := 0
	for {
		read := p.ReadByte()
		val := read & 0b01111111
		result |= int(val) << int(7 * i)
		i++
		if read & 0b10000000 == 0 {
			break
		}
	}
	return uint(result)
	// @TODO: Cruel Optimizations
}
