package main

import (
	"circl/kem"
	"fmt"
)

type iECHConfigBuilder interface {
	setVersion(version uint16) iECHConfigBuilder
	setConfigId(configId uint8) iECHConfigBuilder
}

type ECHConfigBuilder struct {
	version uint16
	configId uint8
	publicKey *kem.PublicKey
}

func (b *ECHConfigBuilder) setVersion(version uint16) iECHConfigBuilder {
	b.version = version

	return b
}

func (b *ECHConfigBuilder) setConfigId(configId uint8) iECHConfigBuilder {
	b.configId = configId

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
	builder.setConfigId(6).setVersion(16)
}