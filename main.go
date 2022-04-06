package main

import (
	"circl/hpke"
	"circl/kem"
	"fmt"
)

type iECHConfigBuilder interface {
	setVersion(version uint16) iECHConfigBuilder
	setConfigId(configId uint8) iECHConfigBuilder
	setPublicKey(kem.PublicKey) iECHConfigBuilder
}

type ECHConfigBuilder struct {
	version uint16
	configId uint8
	publicKey kem.PublicKey
}

func (b *ECHConfigBuilder) setVersion(version uint16) iECHConfigBuilder {
	b.version = version
	return b
}

func (b *ECHConfigBuilder) setConfigId(configId uint8) iECHConfigBuilder {
	b.configId = configId
	return b
}

func (b  *ECHConfigBuilder) setPublicKey(publicKey kem.PublicKey) iECHConfigBuilder {
	b.publicKey = publicKey
	return b
}

type ECHConfigInner struct {

}


func main() {
	var builder ECHConfigBuilder
	test(&builder)
	fmt.Printf("%+v", builder)
}

func test(builder iECHConfigBuilder) {
	publicKey, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	
	builder.setConfigId(6).setVersion(16).setPublicKey(publicKey)
}