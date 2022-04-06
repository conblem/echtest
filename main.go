package main

import (
	"circl/hpke"
	"circl/kem"
	"crypto/tls"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

type iECHConfigBuilder interface {
	setVersion(version uint16) iECHConfigBuilder
	setConfigId(configId uint8) iECHConfigBuilder
	setPublicKey(kem.PublicKey) iECHConfigBuilder
	build() tls.ECHConfig
}

type ECHConfigBuilder struct {
	version   uint16
	configId  uint8
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

func (b *ECHConfigBuilder) setPublicKey(publicKey kem.PublicKey) iECHConfigBuilder {
	b.publicKey = publicKey
	return b
}

func (b *ECHConfigBuilder) build() tls.ECHConfig {
	var config tls.ECHConfig
	return config
}

type ECHConfigInner struct {
	version uint16
}

func (c ECHConfigInner) MarshalECHConfig() []byte {
	var builder cryptobyte.Builder
	builder.AddUint16(c.version)
	builder.

	// todo: fix this
	return make([]byte, 0)
}

func main() {
	/*ctx := context.Background()

	provider := cloudflare.Provider{APIToken: "topsecret"}
	_, err := provider.SetRecords(ctx, "conblem.me", []libdns.Record{
		{
			Type:  "A",
			Name:  "sub",
			Value: "1.2.3.4",
		},
	})
	if err != nil {
		panic(err)
	}*/

	var builder ECHConfigBuilder
	test(&builder)
	fmt.Printf("%+v", builder)
}

func test(builder iECHConfigBuilder) tls.ECHConfig {
	publicKey, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	config := builder.setConfigId(6).setVersion(16).setPublicKey(publicKey).build()

	return config
}
