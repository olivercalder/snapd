// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2015-2016 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package asserts

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // be explicit about supporting SHA256
	_ "crypto/sha512" // be explicit about needing SHA512
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/sha3"
)

const (
	maxEncodeLineLength = 76
	v1                  = 0x1
)

var (
	v1Header         = []byte{v1}
	v1FixedTimestamp = time.Unix(1, 0)
)

func encodeV1(data []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Grow(base64.StdEncoding.EncodedLen(len(data) + 1))
	enc := base64.NewEncoder(base64.StdEncoding, buf)
	enc.Write(v1Header)
	enc.Write(data)
	enc.Close()
	flat := buf.Bytes()
	flatSize := len(flat)

	buf = new(bytes.Buffer)
	buf.Grow(flatSize + flatSize/maxEncodeLineLength + 1)
	off := 0
	for {
		endOff := off + maxEncodeLineLength
		if endOff > flatSize {
			endOff = flatSize
		}
		buf.Write(flat[off:endOff])
		off = endOff
		if off >= flatSize {
			break
		}
		buf.WriteByte('\n')
	}

	return buf.Bytes()
}

type keyEncoder interface {
	keyEncode(w io.Writer) error
}

func encodeKey(key keyEncoder, kind string) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := key.keyEncode(buf)
	if err != nil {
		return nil, fmt.Errorf("cannot encode %s: %v", kind, err)
	}
	return encodeV1(buf.Bytes()), nil
}

type openpgpSigner interface {
	sign(content []byte) (*packet.Signature, error)
}

func signContent(content []byte, privateKey PrivateKey) ([]byte, error) {
	signer, ok := privateKey.(openpgpSigner)
	if !ok {
		panic(fmt.Errorf("not an internally supported PrivateKey: %T", privateKey))
	}

	sig, err := signer.sign(content)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	err = sig.Serialize(buf)
	if err != nil {
		return nil, err
	}

	return encodeV1(buf.Bytes()), nil
}

func decodeV1(b []byte, kind string) (packet.Packet, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty %s", kind)
	}
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(buf, b)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot decode base64 data: %v", kind, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("empty decoded %s", kind)
	}
	buf = buf[:n]
	if buf[0] != v1 {
		return nil, fmt.Errorf("unsupported %s format version: %d", kind, buf[0])
	}
	rd := bytes.NewReader(buf[1:])
	pkt, err := packet.Read(rd)
	if err != nil {
		return nil, fmt.Errorf("cannot decode %s data: %v", kind, err)
	}
	if rd.Len() != 0 {
		return nil, fmt.Errorf("%s has spurious trailer data", kind)
	}
	return pkt, nil
}

// Signature is a cryptographic signature.
type Signature interface {
	// KeyID() returns a suffix of the signing key fingerprint
	KeyID() string
}

type openpgpSignature struct {
	sig *packet.Signature
}

func (opgSig openpgpSignature) KeyID() string {
	return fmt.Sprintf("%016x", *opgSig.sig.IssuerKeyId)
}

func verifyContentSignature(content []byte, sig Signature, pubKey *packet.PublicKey) error {
	opgSig, ok := sig.(openpgpSignature)
	if !ok {
		panic(fmt.Errorf("not an internally supported Signature: %T", sig))
	}

	h := opgSig.sig.Hash.New()
	h.Write(content)
	return pubKey.VerifySignature(h, opgSig.sig)
}

func decodeSignature(signature []byte) (Signature, error) {
	pkt, err := decodeV1(signature, "signature")
	if err != nil {
		return nil, err
	}
	sig, ok := pkt.(*packet.Signature)
	if !ok {
		return nil, fmt.Errorf("expected signature, got instead: %T", pkt)
	}
	if sig.IssuerKeyId == nil {
		return nil, fmt.Errorf("expected issuer key id in signature")
	}
	return openpgpSignature{sig}, nil
}

// PublicKey is the public part of a cryptographic private/public key pair.
type PublicKey interface {
	// ID returns the id of the key as used to match signatures to their signing key.
	ID() string

	// SHA3_384 returns the hash of the key  used to match signatures to their signing key.
	SHA3_384() string

	// verify verifies signature is valid for content using the key.
	verify(content []byte, sig Signature) error

	keyEncoder
}

type openpgpPubKey struct {
	pubKey   *packet.PublicKey
	fp       string
	sha3_384 string
}

func (opgPubKey *openpgpPubKey) Fingerprint() string {
	return opgPubKey.fp
}

func (opgPubKey *openpgpPubKey) ID() string {
	// the key id is defined as the 64 bits suffix of the 160 bits fingerprint
	return opgPubKey.fp[24:40]
}

func (opgPubKey *openpgpPubKey) SHA3_384() string {
	return opgPubKey.sha3_384
}

func (opgPubKey *openpgpPubKey) verify(content []byte, sig Signature) error {
	return verifyContentSignature(content, sig, opgPubKey.pubKey)
}

func (opgPubKey openpgpPubKey) keyEncode(w io.Writer) error {
	return opgPubKey.pubKey.Serialize(w)
}

func newOpenPGPPubKey(intPubKey *packet.PublicKey) *openpgpPubKey {
	fp := hex.EncodeToString(intPubKey.Fingerprint[:])
	h := sha3.New384()
	h.Write(v1Header)
	err := intPubKey.Serialize(h)
	if err != nil {
		panic("internal error: cannot compute public key sha3-384")
	}
	sha3_384, err := EncodeDigest(crypto.SHA3_384, h.Sum(nil))
	if err != nil {
		panic("internal error: cannot compute public key sha3-384")
	}
	return &openpgpPubKey{pubKey: intPubKey, fp: fp, sha3_384: sha3_384}
}

// RSAPublicKey returns a database useable public key out of rsa.PublicKey.
func RSAPublicKey(pubKey *rsa.PublicKey) PublicKey {
	intPubKey := packet.NewRSAPublicKey(v1FixedTimestamp, pubKey)
	return newOpenPGPPubKey(intPubKey)
}

func decodePublicKey(pubKey []byte) (PublicKey, error) {
	pkt, err := decodeV1(pubKey, "public key")
	if err != nil {
		return nil, err
	}
	pubk, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected public key, got instead: %T", pkt)
	}
	rsaPubKey, ok := pubk.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA public key, got instead: %T", pubk.PublicKey)
	}
	return RSAPublicKey(rsaPubKey), nil
}

// EncodePublicKey serializes a public key, typically for embedding in an assertion.
func EncodePublicKey(pubKey PublicKey) ([]byte, error) {
	return encodeKey(pubKey, "public key")
}

// PrivateKey is a cryptographic private/public key pair.
type PrivateKey interface {
	// PublicKey returns the public part of the pair.
	PublicKey() PublicKey

	keyEncoder
}

type openpgpPrivateKey struct {
	privk *packet.PrivateKey
}

func (opgPrivK openpgpPrivateKey) PublicKey() PublicKey {
	return newOpenPGPPubKey(&opgPrivK.privk.PublicKey)
}

func (opgPrivK openpgpPrivateKey) keyEncode(w io.Writer) error {
	return opgPrivK.privk.Serialize(w)
}

var openpgpConfig = &packet.Config{
	DefaultHash: crypto.SHA512,
}

func (opgPrivK openpgpPrivateKey) sign(content []byte) (*packet.Signature, error) {
	privk := opgPrivK.privk
	sig := new(packet.Signature)
	sig.PubKeyAlgo = privk.PubKeyAlgo
	sig.Hash = openpgpConfig.Hash()
	sig.CreationTime = time.Now()
	sig.IssuerKeyId = &privk.KeyId

	h := openpgpConfig.Hash().New()
	h.Write(content)

	err := sig.Sign(h, privk, openpgpConfig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func decodePrivateKey(privKey []byte) (PrivateKey, error) {
	pkt, err := decodeV1(privKey, "private key")
	if err != nil {
		return nil, err
	}
	privk, ok := pkt.(*packet.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected private key, got instead: %T", pkt)
	}
	if _, ok := privk.PrivateKey.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("expected RSA private key, got instead: %T", privk.PrivateKey)
	}
	return openpgpPrivateKey{privk}, nil
}

// RSAPrivateKey returns a PrivateKey for database use out of a rsa.PrivateKey.
func RSAPrivateKey(privk *rsa.PrivateKey) PrivateKey {
	intPrivk := packet.NewRSAPrivateKey(v1FixedTimestamp, privk)
	return openpgpPrivateKey{intPrivk}
}

// GenerateKey generates a private/public key pair.
func GenerateKey() (PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return RSAPrivateKey(priv), nil
}

func encodePrivateKey(privKey PrivateKey) ([]byte, error) {
	return encodeKey(privKey, "private key")
}

// externally held key pairs

type extPGPPrivateKey struct {
	pubKey         PublicKey
	from           string
	extFingerprint string
	doSign         func(extFingerprint string, content []byte) ([]byte, error)
}

func newExtPGPPrivateKey(exportedPubKeyStream io.Reader, from string, sign func(fingerprint string, content []byte) ([]byte, error)) (PrivateKey, error) {
	var pubKey *packet.PublicKey

	rd := packet.NewReader(exportedPubKeyStream)
	for {
		pkt, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("cannot read exported public key: %v", err)
		}
		cand, ok := pkt.(*packet.PublicKey)
		if ok {
			if cand.IsSubkey {
				continue
			}
			if pubKey != nil {
				return nil, fmt.Errorf("cannot select exported public key, found many")
			}
			pubKey = cand
		}
	}

	if pubKey == nil {
		return nil, fmt.Errorf("cannot read exported public key, found none (broken export)")

	}

	rsaPubKey, ok := pubKey.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a RSA key")
	}

	bitLen := rsaPubKey.N.BitLen()
	if bitLen < 4096 {
		return nil, fmt.Errorf("need at least 4096 bits key, got %d", bitLen)
	}

	return &extPGPPrivateKey{
		pubKey:         RSAPublicKey(rsaPubKey),
		from:           from,
		doSign:         sign,
		extFingerprint: fmt.Sprintf("%x", pubKey.Fingerprint),
	}, nil
}

func (expk *extPGPPrivateKey) PublicKey() PublicKey {
	return expk.pubKey
}

func (expk *extPGPPrivateKey) keyEncode(w io.Writer) error {
	return fmt.Errorf("cannot access external private key to encode it")
}

func (expk *extPGPPrivateKey) sign(content []byte) (*packet.Signature, error) {
	out, err := expk.doSign(expk.extFingerprint, content)
	if err != nil {
		return nil, err
	}

	badSig := fmt.Sprintf("bad %s produced signature: ", expk.from)

	sigpkt, err := packet.Read(bytes.NewBuffer(out))
	if err != nil {
		return nil, fmt.Errorf(badSig+"%v", err)
	}

	sig, ok := sigpkt.(*packet.Signature)
	if !ok {
		return nil, fmt.Errorf(badSig+"got %T", sigpkt)
	}

	opgSig := openpgpSignature{sig}

	if sig.IssuerKeyId == nil {
		return nil, fmt.Errorf(badSig + "no key id in the signature")
	}

	sigKeyID := opgSig.KeyID()
	wantedID := expk.pubKey.ID()
	if sigKeyID != wantedID {
		return nil, fmt.Errorf(badSig+"wrong key id (expected %q): %s", wantedID, sigKeyID)
	}

	if sig.Hash != crypto.SHA512 {
		return nil, fmt.Errorf(badSig + "expected SHA512 digest")
	}

	err = expk.pubKey.verify(content, opgSig)
	if err != nil {
		return nil, fmt.Errorf(badSig+"it does not verify: %v", err)
	}

	return sig, nil
}
