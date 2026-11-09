# Document anchor: passport chips and signed-QR ID cards

Two anchor methods, both off unless `DOCUMENT_CHIP_ANCHOR=1`:

| Method | What the phone does | Strength |
|---|---|---|
| `document-chip` | Reads an ePassport or eID card chip over NFC (ICAO 9303). The MRZ (typed or pasted) unlocks it with BAC or PACE. | 80 (70 if chips without Active Authentication are allowed) |
| `document-signed-qr` | Scans the QR on a national ID card with the camera. No NFC needed. First format: India's Aadhaar Secure QR. | 60 |

No vendor and no per-check fee. Code: `src/methods/document-chip/` (`icao/`
for the passport crypto, `signedqr/` for QR formats) and
`src/server/documentanchor.go`. Wallet side: OpenLine
`mobile/modules/document-chip` (JMRTD).

## What it proves, and what it does not

**Passive authentication** checks that the document signer certificate in
EF.SOD chains to the issuing state's CSCA, that EF.SOD's signature is
valid, and that DG1 (the MRZ data) hashes to the value EF.SOD lists. Together
these prove that a state wrote this data. It works offline, needs no
vendor, and is free.

**Passive authentication does not stop a cloned chip.** Anyone who has once
read the chip's files (a hotel or airline reader, for example) can replay
them, and the replay passes passive authentication.

**Active Authentication** (AA, DG15) is what stops clones. The issuer sends
a fresh 8-byte challenge, the phone passes it to the chip, and the chip
signs it with a key that cannot be read out of it. The issuer checks the
signature against DG15, and DG15 is itself covered by the signed SOD. If the
SOD lists DG15, AA is mandatory. Otherwise a clone could simply leave DG15
out.

**Chip Authentication** (EAC, DG14) also proves the chip is genuine, but
only to the phone that runs it. It produces session keys, not a signature,
so the issuer cannot check it after the fact. It is not used here.

**Chips without AA.** Some passports have no DG15. With
`DOCUMENT_CHIP_ALLOW_PASSIVE_ONLY=1` they are accepted at strength 70. Without
that setting they get `active_auth_unavailable`, and the wallet points the
person to another path (selfie, vouching). Nobody is told the passport is
fake.

**Signed QR** proves only that the authority issued the card data and photo.
A QR is a static blob: a photocopy, or a photo of someone else's card, scans
just as well. All of the binding to the person rests on the face match,
which is why this method is 60, not 80.

**Face bind.** The phone compares the document photo (DG2, or the photo in
the QR) with a live selfie that has passed a short active-liveness check
(the selfie anchor's models, at `/face-bind`). It sends only `match` and
`liveness`, plus an optional 32-byte face template. The photo never leaves
the phone. This is a claim made by the phone: a modified app can lie about
it. Pair the method with `app-attest-device` (a real, locked phone running
the real app) to make that expensive. The match threshold is a descriptor
distance of 0.55, a little under dlib's usual 0.6, because document photos
are older and smaller than selfies. It has not been measured on real
passport photos yet.

## Uniqueness and privacy

- **Chip:** the identifier is
  `chip:<CSCA country>:SHA-256(country, document number)`. The issuer then
  keys it with `HMAC(IDENTIFIER_HMAC_KEY, "document" || identifier)` and binds
  it to a nullifier seed, exactly as it does for an email address
  (`identifier.go`, kind `document`, which ranks above phone and email). The
  same passport therefore always gets the same nullifier commitment:
  enrolling again re-issues the same identity, it does not create a new
  person. The namespace is the country of the trusted CSCA, not the DG1
  issuing state, so a state can mint numbers only in its own namespace.
- **Aadhaar:** the QR does not carry the full Aadhaar number, only its last
  4 digits. The identifier hashes those 4 digits, the birth date, the
  gender, and a SHA-256 of the enrolment photo. UIDAI embeds the same photo
  in every QR it issues for a person. If UIDAI updates the photo, the person
  gets a new identifier once; the dual-document flag below catches that.
- **Never stored:** the document number, name, birth date, MRZ, and photo.
  DG1 reaches the issuer, because its hash has to be checked against the
  SOD. It is parsed in memory and dropped. Nothing is logged.
- `IDENTIFIER_HMAC_KEY` is required. The issuer refuses to start with
  `DOCUMENT_CHIP_ANCHOR=1` without it. Never rotate it: rotating it forgets
  every binding.

## Dual citizens, renewals, and the no-false-lockout rule

A person with two passports, or a renewed or replaced passport (which has a
new number), gets a second document identifier. If the phone sends a face
template, the issuer checks it against a document-only face index. When the
face matches an identity enrolled with a different document, the issuer
does **not** refuse. It issues the credential and records a review case:
session, matched face commitment, and country, with no personal data. Admins
list these cases with `GET /v1/admin/document-reviews` (bearer
`ADMIN_TOKEN`). The case is also logged at NOTICE.

Why not refuse? The face model's false match rate is about 0.2% per pair
(docs/selfie-anchor.md). At a few hundred enrolled people, some honest
newcomer will match someone by chance. Refusing would lock that person out.

The face index is kept separate from the selfie anchor's accumulator, so
enrolling a document never makes the selfie anchor refuse the same person
later.

What remains open: deciding a review case (merge the two identities, revoke
one, or clear the flag) is a manual step, and there is no tool for it yet.

## Every refusal has a next step

| Reason | Meaning | Next step the wallet offers |
|---|---|---|
| `csca_untrusted` | The issuing state's CSCA is not in the trust list | Use another document, or the selfie or vouch path; tell the operator |
| `signature_unsupported` | The document uses crypto this code does not implement | Selfie or vouch path |
| `sod_invalid`, `dg_hash_mismatch` | The data was altered, or the read went wrong | Read the chip again; if it fails again, use another path |
| `mrz_invalid` | DG1's check digits are wrong | Read again |
| `document_expired` | The document has expired | Use a valid document, or another path |
| `active_auth_missing` / `active_auth_failed` | The chip has AA but did not answer, or answered wrongly | Hold the phone still and read again (a new begin issues a new challenge) |
| `active_auth_unavailable` | The chip has no AA and the issuer requires it | Selfie or vouch path |
| `face_bind_missing` / `face_bind_failed` | No face match was sent, or it failed | Try again in better light; otherwise use another path |
| `qr_format_unknown` / `qr_signature_invalid` / `qr_invalid` | The QR is not a supported signed format, or has been altered | Scan again; use another document or path |

Each begin issues one Active Authentication challenge, and one completion
uses it up. A retry starts a new begin and a new chip read.

## Updating the CSCA trust

The issuer embeds `src/methods/document-chip/trust/DE_ML_*.ml`. This is the
German master list, which BSI publishes free of charge. It holds about 600
CSCA and link certificates from about 120 states, including the US and
India. Before trusting any certificate in a list, the issuer checks that
list's CMS signature against the pinned `csca-germany` fingerprint in
`trust.go`. BSI publishes that fingerprint on its CSCA page. It was checked
on 2026-11-04 as `20:84:AE:D7:…:91:AD:A8`.

To refresh the list (BSI republishes it roughly monthly; do it at least
quarterly):

1. Download `GermanMasterList.zip` from bsi.bund.de (search for "German
   Master List") and unzip it.
2. Replace the `.ml` file in `trust/`. Delete the old one; only one is
   needed.
3. Run `go test ./src/methods/document-chip/...`. `TestGermanMasterList`
   verifies the list against the pin. If BSI has rolled `csca-germany`
   over, the test fails: check the new fingerprint on the BSI page, add it
   to `GermanCSCASHA256`, and run the test again.
4. Open a PR and redeploy.

To add more certificates:

- **Another state's list, or a CSCA a state publishes directly:** convert
  it to PEM and set `DOCUMENT_CHIP_CSCA_PEM=/path/file.pem`. These
  certificates are trusted as given, so only add certificates whose origin
  you have checked.
- **The ICAO PKD master list:** it is free to download from icao.int after
  you accept its terms. It is also a CMS SignedData; pin its signer's CSCA
  the same way and drop it in `trust/`. Coverage is similar to Germany's.

Not checked yet: CSCA and DSC revocation lists (CRLs). A state that revokes
a compromised document signer key is not seen. Validity periods on the
chain are deliberately not enforced, because document signer certificates
expire while the passports they signed stay valid (ICAO 9303 Part 12). The
document's own expiry date is enforced.

## Signed QR formats are data

A format is a JSON file (`signedqr/formats/*.json`) plus the authority's
certificates. The file gives the encoding, compression, where the signature
is, field positions, the photo position, the signing time, and which fields
make a card unique. Set `DOCUMENT_QR_FORMATS_DIR` to load more formats. A
country whose QR fits the "decimal number, zlib/gzip, 0xFF-delimited,
trailing RSA signature" family needs only a file. A different family, for
example CBOR/COSE or base45, needs a decoder in `signedqr.go`.

The signing key must have been valid when the QR was signed (the timestamp
in Aadhaar's reference id). That lets old cards keep working after UIDAI
rotates its key. The shipped UIDAI certificates run until 2024-02 and
2026-02. **Add UIDAI's current certificate from uidai.gov.in before relying
on Aadhaar QRs made after February 2026.**

## Test vectors

- `icao/testdata/` is generated by `gen.py` with the openssl CLI, which is
  independent of the Go code under test. It uses the real ICAO file formats
  (EF.SOD CMS, DG1 with a TD3 MRZ, DG15) for the specimen state Utopia:
  RSA-PSS, brainpoolP256r1 with explicit parameters, and P-256 chains, an
  expired document (the ICAO 9303 specimen MRZ, L898902C3, which expired
  2012-04-15), and a rogue CSCA. The negative tests cover a tampered DG, a
  tampered SOD, the wrong CSCA, an expired document, AA replayed over
  another challenge, and DG15 omitted.
- The real German master list is verified end to end. 596 of its 609
  certificates chain under this code. The 13 that do not are link
  certificates whose older key is not in the list (GB was checked with
  openssl).
- `signedqr/testdata/` holds anon-aadhaar's MIT test QR: the real Aadhaar V2
  format with fictitious data, signed with their test key. It verifies
  against that key, fails against UIDAI's keys, and fails after tampering.
- Not done: a real passport. BSI's and ICAO's test passports and test PKI
  have to be requested, and were not available to this work. The Pixel 10
  test below is the first real-chip check.

## Zero-knowledge variant

`document-chip-zk` (design in docs/zk-passport.md) proves the same
passive-authentication facts, and Active Authentication when the chip has
DG15, on the phone, so DG1, DG15 and the AA signature never reach the
issuer. Same strengths (80 with AA, 70 without DG15) and the same clone rule
(EF.SOD lists DG15 but no AA: refused, routed). The OpenLine wallet uses only
the zero-knowledge method for passports; this method stays available to
other clients and is off on the live issuer.
