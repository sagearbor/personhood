// Command mdoc-testvector mints a specimen mobile driving licence with the
// test issuer (Utopia, "UT"; no real person, no real issuer) and has a test
// wallet present it for one fixed issuer session, writing everything the
// spike needs to prove it (spikes/mobile-id) as JSON on stdout.
//
//	go run ./mdoczk/cmd/mdoc-testvector -doc UT1234567 > vector.json
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	mrand "math/rand"
	"os"
	"time"

	"github.com/sagearbor/personhood/src/methods/document-chip/mdoczk"
	"github.com/sagearbor/personhood/src/methods/document-chip/zkproof"
)

func main() {
	doc := flag.String("doc", "UT1234567", "document number")
	challengeHex := flag.String("challenge", "", "32-byte session challenge, hex (default: SHA-256(\"mdoc-test\"))")
	holder := flag.String("holder", "session:mdoc-test", "holder binding the issuer uses")
	nowS := flag.String("now", time.Now().UTC().Format("2006-01-02T15:04:05Z"), "the proof's now")
	handover := flag.String("handover", "dcapi", "dcapi (ISO 18013-7 Annex C) or openid4vp")
	extra := flag.Int("extra", 0, "extra namespace elements (to grow the MSO)")
	flag.Parse()
	now, err := time.Parse("2006-01-02T15:04:05Z", *nowS)
	must(err)
	issuer, err := mdoczk.NewTestIssuer("UT", "", now)
	must(err)
	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	portrait := append([]byte{0xff, 0xd8, 0xff, 0xe0}, []byte("specimen portrait, not a photo")...)
	els := mdoczk.SpecimenElements(*doc, portrait)
	for i := 0; i < *extra; i++ {
		els = append(els, mdoczk.TestElement{NameSpace: "org.iso.18013.5.1.aamva", Identifier: "extra_" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Value: "x"})
	}
	m, err := issuer.Issue(mdoczk.TestCredential{
		DocType: mdoczk.DocTypeMDL, Elements: els, DeviceKey: devKey,
		Signed: now.Add(-time.Hour), ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(30 * 24 * time.Hour),
		Shuffle: mrand.New(mrand.NewSource(7)),
	})
	must(err)

	var ch [32]byte
	if *challengeHex != "" {
		b, err := hex.DecodeString(*challengeHex)
		must(err)
		copy(ch[:], b)
	} else {
		ch = sha256.Sum256([]byte("mdoc-test"))
	}
	nonce := mdoczk.Nonce(ch, *holder)
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	origin := "android:apk-key-hash:c3BlY2ltZW4tYXBwLXNpZ25pbmcta2V5LWhhc2gtMDAwMDA"
	encInfo := base64.RawURLEncoding.EncodeToString(mdoczk.EncryptionInfo(nonce, mdoczk.COSEKey(&recipient.PublicKey)))
	var transcript []byte
	var thumb []byte
	if *handover == "openid4vp" {
		t := sha256.Sum256([]byte("specimen jwk thumbprint"))
		thumb = t[:]
		transcript = mdoczk.OpenID4VPSessionTranscript(origin, mdoczk.NonceString(nonce), thumb)
	} else {
		transcript = mdoczk.SessionTranscript(encInfo, origin)
	}
	resp, err := m.Present(transcript, map[string][]string{mdoczk.NameSpaceMDL: {"document_number", "portrait"}})
	must(err)

	reg, err := mdoczk.BuildRegistry(certs(issuer.IACACert), nil)
	must(err)
	th := sha256.Sum256(transcript)
	scope := mdoczk.ServiceScope()
	out := map[string]any{
		"note":                 "Specimen licence from the personhood test issuer (Utopia). Not a real person or issuer.",
		"device_response_b64":  base64.StdEncoding.EncodeToString(resp),
		"iaca_pem":             string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.IACACert})),
		"registry":             reg,
		"iaca_index":           0,
		"iaca_path":            reg.Path(0),
		"challenge_hex":        hex.EncodeToString(ch[:]),
		"holder":               *holder,
		"handover":             *handover,
		"encryption_info_b64u": encInfo,
		"origin":               origin,
		"jwk_thumbprint_hex":   hex.EncodeToString(thumb),
		"session_transcript":   hex.EncodeToString(transcript),
		"transcript_hash":      hex.EncodeToString(th[:]),
		"now":                  *nowS,
		"scope":                "0x" + hex.EncodeToString(scope[:]),
		"document_number":      *doc,
		"mso_bytes":            len(m.MSO),
		"expected_nullifier":   zkproof.FieldHex(mdoczk.ExpectedNullifier(scope, "UT", *doc)),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	must(enc.Encode(out))
}

func certs(der []byte) []*x509.Certificate {
	c, err := x509.ParseCertificate(der)
	must(err)
	return []*x509.Certificate{c}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
