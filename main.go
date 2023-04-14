package main

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"

	"golang.org/x/crypto/cryptobyte"
)

type iECHConfigBuilder interface {
	setVersion(version uint16) iECHConfigBuilder
	setConfigId(configId uint8) iECHConfigBuilder
	setPublicKey(kem.PublicKey) iECHConfigBuilder
	setCipherSuite(hpke.Suite) iECHConfigBuilder
	build() (*tls.ECHConfig, error)
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

func (b *ECHConfigBuilder) build() (*tls.ECHConfig, error) {
	inner := echConfigInner{
		configId:  b.configId,
		publicKey: b.publicKey,
		// todo: figure out what this should be
		maximumNameLen: 0,
		// todo: set to gschide value
		publicName:   "test",
		cipherSuites: []hpke.Suite{b.suite},
	}
	innerBytes, err := inner.marshalECHConfig()
	if err != nil {
		return nil, err
	}

	var arrayBuilder cryptobyte.Builder
	arrayBuilder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(innerBytes)
	})
	arrayBytes, err := arrayBuilder.Bytes()
	if err != nil {
		return nil, err
	}

	configs, err := tls.UnmarshalECHConfigs(arrayBytes)
	if err != nil {
		return nil, err
	}

	return &configs[0], nil
}

type echConfigInner struct {
	configId       uint8
	publicKey      kem.PublicKey
	cipherSuites   []hpke.Suite
	maximumNameLen uint8
	publicName     string
}

func (c echConfigInner) marshalECHConfig() ([]byte, error) {
	var builder cryptobyte.Builder

	builder.AddUint16(0xfe0d)

	var err error
	builder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		err = c.marshalECHConfigContents(child)
	})
	if err != nil {
		return nil, err
	}

	bytes, err := builder.Bytes()
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (c echConfigInner) marshalECHConfigContents(builder *cryptobyte.Builder) error {
	// HpkeKeyConfig
	err := c.marshalHpkeKeyConfig(builder)
	if err != nil {
		return err
	}

	// maximum_name_length
	builder.AddUint8(c.maximumNameLen)

	// public name
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(c.publicName))
	})

	// disable extensions for the moment so we just add a length of 0
	builder.AddUint16(0)

	return nil
}

func (c echConfigInner) marshalHpkeKeyConfig(builder *cryptobyte.Builder) error {
	if len(c.cipherSuites) < 1 {
		return errors.New("no ciphers found")
	}

	firstKem, _, _ := c.cipherSuites[0].Params()

	builder.AddUint8(c.configId)
	builder.AddUint16(uint16(firstKem))

	// add public key
	publicKey, err := c.publicKey.MarshalBinary()
	if err != nil {
		return err
	}
	builder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(publicKey)
	})

	// add ciphersuites
	builder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		for _, cipherSuite := range c.cipherSuites {
			kem, kdf, aead := cipherSuite.Params()
			if firstKem != kem {
				err = errors.New("not all kems are the same")
				return
			}

			child.AddUint16(uint16(kdf))
			child.AddUint16(uint16(aead))
		}
	})

	return err
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

	config, err := builder.
		setConfigId(6).
		setVersion(16).
		setPublicKey(publicKey).
		setCipherSuite(suite).
		build()

	if err != nil {
		panic(err)
	}

	return *config
}

// interface guards
var _ iECHConfigBuilder = (*ECHConfigBuilder)(nil)
