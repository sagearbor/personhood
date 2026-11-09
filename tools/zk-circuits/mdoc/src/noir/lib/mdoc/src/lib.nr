// Private mobile driving licence (ISO/IEC 18013-5 mdoc) proof for
// personhood's mobile-id-zk method (docs/mobile-id.md). Apache-2.0, written
// for personhood. Uses only Noir's built-in secp256r1 black box, the
// Apache-2.0 noir-lang sha256 and poseidon libraries; no third-party curve
// library.
//
// One proof shows, without revealing the licence:
//
//   1. an IACA (issuing authority root) in the issuer's published registry
//      (a Poseidon2 Merkle root) signed a document signer certificate;
//   2. that document signer signed the Mobile Security Object (COSE_Sign1);
//   3. the MSO's docType is the public doc_type, and validFrom <= now <=
//      validUntil for the public `now`;
//   4. an IssuerSignedItem with elementIdentifier "document_number" in the
//      public namespace hashes to its digest in the MSO's valueDigests;
//   5. the MSO's device key (held in the phone's secure hardware) signed
//      DeviceAuthentication over a session transcript whose SHA-256 is
//      public (the issuer derives it from its own nonce): copy protection;
//   6. nullifier = Poseidon2(scope, jurisdiction, pack(document_number),
//      len), where jurisdiction comes from the IACA's registry leaf.
//
// Public: registry root, now, doc type, namespace, transcript hash, scope,
// nullifier. Private: everything else (keys, certificates, signatures, the
// MSO, the document number, which jurisdiction).

use poseidon::poseidon2::Poseidon2;
use sha256::sha256_var;

pub global REGISTRY_DEPTH: u32 = 16;
// Leaf type tag: "mdoc-iaca" packed.
pub global LEAF_TAG: Field = 0x6d646f632d69616361;

// ------------------------------------------------------------ bytes

pub fn expect_at<let N: u32, let M: u32>(a: [u8; N], pos: u32, pat: [u8; M]) {
    for i in 0..M {
        assert(a[pos + i] == pat[i], "unexpected bytes");
    }
}

/// A CBOR head at pos: (major type, head length, argument). Arguments up
/// to 65535 (1, 2 or 3 byte heads).
pub fn cbor_head<let N: u32>(a: [u8; N], pos: u32) -> (u8, u32, u32) {
    let b0 = a[pos];
    let major = b0 >> 5;
    let info = (b0 & 0x1f) as u32;
    if info < 24 {
        (major, 1, info)
    } else if info == 24 {
        (major, 2, a[pos + 1] as u32)
    } else {
        assert(info == 25, "CBOR length too large");
        (major, 3, (a[pos + 1] as u32) * 256 + (a[pos + 2] as u32))
    }
}

/// A DER header at pos: (header length, content length).
pub fn der_header<let N: u32>(a: [u8; N], pos: u32) -> (u32, u32) {
    let b1 = a[pos + 1] as u32;
    let b2 = a[pos + 2] as u32;
    let b3 = a[pos + 3] as u32;
    if b1 < 0x80 {
        (2, b1)
    } else if b1 == 0x81 {
        (3, b2)
    } else {
        assert(b1 == 0x82, "unsupported DER length");
        (4, b2 * 256 + b3)
    }
}

/// Big-endian pack of a[pos..pos+len] (len <= 31) into one field.
pub fn pack_be<let N: u32>(a: [u8; N], pos: u32, len: u32) -> Field {
    assert(len <= 31, "value longer than 31 bytes");
    let mut acc: Field = 0;
    for i in 0..31 {
        if i < len {
            acc = acc * 256 + (a[pos + i] as Field);
        }
    }
    acc
}

pub fn read32<let N: u32>(a: [u8; N], pos: u32) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    for i in 0..32 {
        out[i] = a[pos + i];
    }
    out
}

/// zkPassport's pack_be_bytes_into_fields for 64 bytes (31-byte limbs from
/// the least significant end): [bytes 33..64, bytes 2..33, bytes 0..2].
pub fn pack_point(x: [u8; 32], y: [u8; 32]) -> [Field; 3] {
    let mut b: [u8; 64] = [0; 64];
    for i in 0..32 {
        b[i] = x[i];
        b[32 + i] = y[i];
    }
    let mut out: [Field; 3] = [0; 3];
    let mut f0: Field = 0;
    for i in 33..64 {
        f0 = f0 * 256 + (b[i] as Field);
    }
    let mut f1: Field = 0;
    for i in 2..33 {
        f1 = f1 * 256 + (b[i] as Field);
    }
    out[0] = f0;
    out[1] = f1;
    out[2] = (b[0] as Field) * 256 + (b[1] as Field);
    out
}

pub fn hash_to_fields(h: [u8; 32]) -> (Field, Field) {
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + (h[i] as Field);
        lo = lo * 256 + (h[16 + i] as Field);
    }
    (hi, lo)
}

pub fn verify_p256(x: [u8; 32], y: [u8; 32], sig: [u8; 64], digest: [u8; 32]) -> bool {
    std::ecdsa_secp256r1::verify_signature(x, y, sig, digest)
}

// ------------------------------------------------------------ registry

pub fn registry_leaf(jurisdiction: Field, x: [u8; 32], y: [u8; 32]) -> Field {
    let p = pack_point(x, y);
    Poseidon2::hash([LEAF_TAG, jurisdiction, p[0], p[1], p[2]], 5)
}

pub fn merkle_root(leaf: Field, index: u32, path: [Field; REGISTRY_DEPTH]) -> Field {
    let mut cur = leaf;
    for i in 0..REGISTRY_DEPTH {
        let right = ((index >> i) & 1) == 1;
        cur = if right {
            Poseidon2::hash([path[i], cur], 2)
        } else {
            Poseidon2::hash([cur, path[i]], 2)
        };
    }
    cur
}

// ------------------------------------------------------------ certificate

// SubjectPublicKeyInfo of an uncompressed P-256 key, up to the point.
global SPKI_P256: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

/// Walks a TBSCertificate's DER (version, serial, signature, issuer,
/// validity, subject) to its SubjectPublicKeyInfo, which must be a P-256
/// key; returns (x, y).
pub fn ds_public_key<let N: u32>(tbs: [u8; N], tbs_len: u32) -> ([u8; 32], [u8; 32]) {
    assert(tbs[0] == 0x30, "TBS is not a SEQUENCE");
    let (h0, l0) = der_header(tbs, 0);
    assert(h0 + l0 == tbs_len, "TBS length");
    let mut p = h0;
    if tbs[p] == 0xa0 {
        let (h, l) = der_header(tbs, p);
        p += h + l;
    }
    assert(tbs[p] == 0x02, "serial");
    let (h, l) = der_header(tbs, p);
    p += h + l;
    for _ in 0..4 {
        // signature AlgorithmIdentifier, issuer, validity, subject
        assert(tbs[p] == 0x30, "TBS field");
        let (h, l) = der_header(tbs, p);
        p += h + l;
    }
    expect_at(tbs, p, SPKI_P256);
    assert(p + 91 <= tbs_len, "SPKI");
    (read32(tbs, p + 27), read32(tbs, p + 59))
}

// ------------------------------------------------------------ COSE_Sign1

/// Parses Sig_structure = ["Signature1", protected, h'', payload] where
/// payload = #6.24(bstr inner). Returns (inner start, inner length); the
/// inner bytes end exactly at msg_len.
pub fn sig_structure_inner<let N: u32>(msg: [u8; N], msg_len: u32) -> (u32, u32) {
    expect_at(msg, 0, [0x84, 0x6a]);
    expect_at(msg, 2, "Signature1".as_bytes());
    let (m1, h1, plen) = cbor_head(msg, 12);
    assert((m1 == 2) & (plen >= 1), "protected header");
    let mut o = 12 + h1 + plen;
    assert(msg[o] == 0x40, "external_aad");
    o += 1;
    let (m2, h2, payload_len) = cbor_head(msg, o);
    assert(m2 == 2, "payload");
    o += h2;
    assert(o + payload_len == msg_len, "payload length");
    expect_at(msg, o, [0xd8, 0x18]);
    o += 2;
    let (m3, h3, inner_len) = cbor_head(msg, o);
    assert(m3 == 2, "embedded CBOR");
    assert(2 + h3 + inner_len == payload_len, "embedded length");
    (o + h3, inner_len)
}

// ------------------------------------------------------------ MSO

/// Checks a tstr at pos equals the packed public value; returns the end.
pub fn assert_tstr_packed<let N: u32>(a: [u8; N], pos: u32, packed: Field) -> u32 {
    let (m, h, l) = cbor_head(a, pos);
    assert((m == 3) & (l >= 1) & (l <= 31), "text");
    assert(a[pos + h] != 0, "leading NUL");
    assert(pack_be(a, pos + h, l) == packed, "text differs");
    pos + h + l
}

/// "YYYY-MM-DDTHH:MM:SSZ" after `key` C0 74 at pos (in [lo, hi)); returns
/// it packed (20 bytes, big-endian, so numeric order is time order).
pub fn tdate_after<let N: u32, let K: u32>(a: [u8; N], pos: u32, key: [u8; K], lo: u32, hi: u32) -> Field {
    assert((pos >= lo) & (pos + K + 22 <= hi), "date outside the MSO");
    expect_at(a, pos, key);
    expect_at(a, pos + K, [0xc0, 0x74]);
    pack_be(a, pos + K + 2, 20)
}

/// MSO deviceKeyInfo.deviceKey as {1: 2, -1: 1, -2: x, -3: y}.
pub fn device_key<let N: u32>(a: [u8; N], pos: u32, lo: u32, hi: u32) -> ([u8; 32], [u8; 32]) {
    assert((pos >= lo) & (pos + 85 <= hi), "device key outside the MSO");
    expect_at(a, pos, [0x69]);
    expect_at(a, pos + 1, "deviceKey".as_bytes());
    expect_at(a, pos + 10, [0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20]);
    expect_at(a, pos + 50, [0x22, 0x58, 0x20]);
    (read32(a, pos + 18), read32(a, pos + 53))
}

/// The valueDigests entry for the item: the namespace key (tstr, packed
/// public value) at ns_pos, followed by its map of digestID -> bstr(32);
/// walks the map's entries and returns (position, head length) of the
/// entry_index-th one (its digestID head and digest).
pub fn digest_entry<let N: u32, let E: u32>(a: [u8; N], ns_pos: u32, name_space: Field, entry_index: u32, lo: u32, hi: u32) -> u32 {
    assert(ns_pos >= lo, "namespace outside the MSO");
    let m = assert_tstr_packed(a, ns_pos, name_space);
    let (mm, mh, count) = cbor_head(a, m);
    assert(mm == 5, "valueDigests namespace is not a map");
    assert((count <= E) & (entry_index < count), "digest entry index");
    let mut pos = m + mh;
    let mut found = 0;
    for i in 0..E {
        if i < count {
            let (km, kh, _) = cbor_head(a, pos);
            assert(km == 0, "digestID is not an unsigned integer");
            expect_at(a, pos + kh, [0x58, 0x20]);
            if i == entry_index {
                found = pos;
            }
            pos += kh + 34;
        }
    }
    assert(pos <= hi, "valueDigests outside the MSO");
    found
}

// ------------------------------------------------------------ IssuerSignedItem

/// Parses IssuerSignedItemBytes = #6.24(bstr {digestID, random,
/// elementIdentifier: "document_number", elementValue: tstr}) fully (keys in
/// any order). Returns (digestID head position, digestID head length,
/// value position, value length).
pub fn parse_item<let N: u32>(item: [u8; N], item_len: u32) -> (u32, u32, u32, u32) {
    expect_at(item, 0, [0xd8, 0x18]);
    let (m0, h0, l0) = cbor_head(item, 2);
    assert((m0 == 2) & (2 + h0 + l0 == item_len), "item length");
    let c = 2 + h0;
    assert(item[c] == 0xa4, "item is not a 4-entry map");
    let mut pos = c + 1;
    let mut seen: [bool; 4] = [false; 4];
    let mut did_pos = 0;
    let mut did_len = 0;
    let mut val_pos = 0;
    let mut val_len = 0;
    for _ in 0..4 {
        let (km, kh, kl) = cbor_head(item, pos);
        assert(km == 3, "item key is not text");
        let k = pos + kh;
        let vp = k + kl;
        let (vm, vh, vl) = cbor_head(item, vp);
        if kl == 8 {
            expect_at(item, k, "digestID".as_bytes());
            assert(vm == 0, "digestID");
            assert(!seen[0], "duplicate key");
            seen[0] = true;
            did_pos = vp;
            did_len = vh;
            pos = vp + vh;
        } else if kl == 6 {
            expect_at(item, k, "random".as_bytes());
            assert(vm == 2, "random");
            assert(!seen[1], "duplicate key");
            seen[1] = true;
            pos = vp + vh + vl;
        } else if kl == 17 {
            expect_at(item, k, "elementIdentifier".as_bytes());
            assert((vm == 3) & (vl == 15), "elementIdentifier");
            expect_at(item, vp + vh, "document_number".as_bytes());
            assert(!seen[2], "duplicate key");
            seen[2] = true;
            pos = vp + vh + vl;
        } else {
            assert(kl == 12, "unknown item key");
            expect_at(item, k, "elementValue".as_bytes());
            assert((vm == 3) & (vl >= 1) & (vl <= 31), "elementValue");
            assert(!seen[3], "duplicate key");
            seen[3] = true;
            val_pos = vp + vh;
            val_len = vl;
            pos = vp + vh + vl;
        }
    }
    assert(pos == item_len, "item has trailing bytes");
    (did_pos, did_len, val_pos, val_len)
}

// ------------------------------------------------------------ device

/// DeviceAuthentication inside the device Sig_structure:
/// 84 74 "DeviceAuthentication" SessionTranscript DocType
/// DeviceNameSpacesBytes. Returns SHA-256 of the session transcript (the
/// transcript_len bytes after the header) and checks the docType follows it.
pub fn device_transcript_hash<let N: u32, let T: u32>(dev: [u8; N], dev_len: u32, transcript_len: u32, doc_type: Field) -> [u8; 32] {
    let (start, inner_len) = sig_structure_inner(dev, dev_len);
    expect_at(dev, start, [0x84, 0x74]);
    expect_at(dev, start + 2, "DeviceAuthentication".as_bytes());
    let t = start + 22;
    assert(transcript_len <= T, "transcript too long");
    let mut tr: [u8; T] = [0; T];
    for i in 0..T {
        if i < transcript_len {
            tr[i] = dev[t + i];
        }
    }
    let after = assert_tstr_packed(dev, t + transcript_len, doc_type);
    // DeviceNameSpacesBytes: #6.24(bstr), the rest of DeviceAuthentication.
    expect_at(dev, after, [0xd8, 0x18]);
    let (m, h, l) = cbor_head(dev, after + 2);
    assert(m == 2, "DeviceNameSpacesBytes");
    assert(after + 2 + h + l == start + inner_len, "DeviceAuthentication length");
    sha256_var(tr, transcript_len)
}

// ------------------------------------------------------------ main logic

pub fn nullifier(scope: Field, jurisdiction: Field, value: Field, len: u32) -> Field {
    Poseidon2::hash([scope, jurisdiction, value, len as Field], 4)
}
