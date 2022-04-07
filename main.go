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
	setCipherSuite(hpke.Suite) iECHConfigBuilder
	build() tls.ECHConfig
}

type ECHConfigBuilder struct {
	version   uint16
	configId  uint8
	publicKey kem.PublicKey
	suite     hpke.Suite
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

func (b *ECHConfigBuilder) setCipherSuite(suite hpke.Suite) iECHConfigBuilder {
	b.suite = suite

	return b
}

func (b *ECHConfigBuilder) build() tls.ECHConfig {
	inner := echConfigInner{
		configId:  b.configId,
		publicKey: b.publicKey,
		// todo: figure out what this should be
		maximumNameLen: 0,
		// todo: set to gschide value
		publicName:   "test",
		cipherSuites: []hpke.Suite{b.suite},
	}
	innerBytes := inner.marshalECHConfig()

	// todo: fix this hack
	var arrayBuilder cryptobyte.Builder
	arrayBuilder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(innerBytes)
	})
	arrayBytes, err := arrayBuilder.Bytes()
	if err != nil {
		panic(err)
	}

	//configs, err := tls.UnmarshalECHConfigs(innerBytes)
	configs, err := tls.UnmarshalECHConfigs(arrayBytes)
	if err != nil {
		panic(err)
	}

	return configs[0]
}

type echConfigInner struct {
	configId       uint8
	publicKey      kem.PublicKey
	cipherSuites   []hpke.Suite
	maximumNameLen uint8
	publicName     string
}

func (c echConfigInner) marshalECHConfig() []byte {
	var builder cryptobyte.Builder
	builder.AddUint16(0xfe0d)
	builder.AddUint16LengthPrefixed(c.marshalECHConfigContents)

	bytes, err := builder.Bytes()
	if err != nil {
		panic(err)
	}
	return bytes
}

func (c echConfigInner) marshalHpkeKeyConfig(builder *cryptobyte.Builder) {
	kem, _, _ := c.cipherSuites[0].Params()
	builder.AddUint8(c.configId)
	builder.AddUint16(uint16(kem))

	// add public key
	publicKey, err := c.publicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	builder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(publicKey)
	})

	// add ciphersuites
	// check if kem id is correct
	builder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		for _, cipherSuite := range c.cipherSuites {
			_, kdf, aead := cipherSuite.Params()
			child.AddUint16(uint16(kdf))
			child.AddUint16(uint16(aead))
		}
	})

}

func (c echConfigInner) marshalECHConfigContents(builder *cryptobyte.Builder) {
	fmt.Println("test")

	// HpkeKeyConfig
	c.marshalHpkeKeyConfig(builder)

	// maximum_name_length
	builder.AddUint8(c.maximumNameLen)

	// public name
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(c.publicName))
	})

	// disable extensions for the moment so we just add a length of 0
	builder.AddUint16(0)
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
	config := test(&builder)
	fmt.Printf("%+v", config)
}

func test(builder iECHConfigBuilder) tls.ECHConfig {
	publicKey, _, err := hpke.KEM_P384_HKDF_SHA384.Scheme().GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	kemID := hpke.KEM_P384_HKDF_SHA384
	kdfID := hpke.KDF_HKDF_SHA384
	aeadID := hpke.AEAD_AES256GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	config := builder.setConfigId(6).setVersion(16).setPublicKey(publicKey).setCipherSuite(suite).build()

	return config
}
