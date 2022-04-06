package main

import (
	"circl/kem"
	"fmt"
)

type iECHConfigBuilder interface {
	setVersion(version uint16)
	setConfigId(configId uint8)
}

type ECHConfigBuilder struct {
	version uint16
	configId uint8
	publicKey *kem.PublicKey
}

func (b *ECHConfigBuilder) setVersion(version uint16) {
	b.version = version
}

func (b *ECHConfigBuilder) setConfigId(configId uint8) {
	b.configId = configId
}

type ECHConfigInner struct {

}


func main() {
	var builder ECHConfigBuilder
	test(builder)
	fmt.Println("Hello, World! 222")
}

func test(builder *iECHConfigBuilder) {

}