# MCPACKETS

### For more information on varints see: https://wiki.vg/Protocol#VarInt_and_VarLong

## Installation
Install this package by running
``go get -u github.com/Sascha-T/mcpackets``

## Packet
```
type Packet struct {
	Bytes  []byte
	Size   int
	Offset int
}
```

Can be created using:
- ``func NewPacket_A(arr []byte)``\
Creates a new packet from a byte array
- ``func NewPacket_S(size int)``\
Creates a new packet with a byte array of size ``size`` filled with 0s

Methods:
- ``func (p *Packet) WriteByte(r byte)`` \
Writes one byte and increments offset
- ``func (p *Packet) ReadByte() byte`` \
Reads one byte and increments offset
- ``func (p *Packet) WriteShort(r uint16)`` \
Writes  two bytes (uint16) and increments offset
- ``func (p *Packet) ReadShort() uint16`` \
Reads two bytes (uint16) and increments offset
- ``func (p *Packet) WriteInt(r uint32)`` \
Writes four byte (uint32) and increments offset
- ``func (p *Packet) ReadInt() uint32`` \
Reads four byte (uint32) and increments offset
- ``func (p *Packet) WriteLong(r uint64)`` \
Writes eight bytes (uint64) and increments offset
- ``func (p *Packet) ReadLong() uint64`` \
Reads eight bytes (uint64) and increments offset 


- ``func (p *Packet) WriteVarInt(r uint)`` \
Writes a varint and increments offset
- ``func (p *Packet) ReadVarInt() uint`` \
Reads a varint and increments offset 


- ``func (p *Packet) WriteString(str string)`` \
Writes a varint with the size of the string and the string and increments offset
- ``func (p *Packet) ReadString() string`` \
Reads a varint then reads a string with size being the read varint

## EncryptionHolder

```
type EncryptionHolder struct {
	LocalBoundCryptoStream cipher.Stream
	RemoteBoundCryptoStream cipher.Stream
}
```

Can be created using:
- ``func NewEncryptionHolder(sharedSecret []byte) EncryptionHolder`` \
Shared secret is the byte array sent by the server encrypted using the client's public key

Methods:
- ``func (c EncryptionHolder) EncryptPacket(p Packet) []byte`` \
Encrypts packet ``p`` with the outbound AES stream into a byte array

- ``func (c EncryptionHolder) DecryptPacket(p []byte) Packet`` \
Decrypts byte array ``p`` with the inbound AES stream into a packet

