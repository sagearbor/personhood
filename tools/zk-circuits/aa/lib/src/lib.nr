// Active Authentication (ICAO 9303 part 11, 6.1) proved in zero knowledge,
// for document-chip-zk (personhood docs/zk-passport.md, "Active
// Authentication and clones"). Apache-2.0, written for personhood; it reuses
// zkPassport's commitment and utils libraries and Apache-2.0 hash and bignum
// libraries, and nothing without a license (no noir_bigcurve).
//
// An `aa` sub-proof opens the same commitment the `integrity` sub-proof
// opens (the `id` sub-proof's comm_out: salt, issuing state, signed
// attributes, DG1, eContent, private nullifier), so it speaks about the same
// passport, and then proves ONE of:
//
//   aa_absent  EF.SOD's eContent lists no DG15: the chip has no AA key.
//   aa_dg_<h>_<alg>_<h'>
//              eContent lists hash <h>(DG15) for a DG15 this proof holds,
//              and the signature the chip returned for the issuer's 8-byte
//              challenge verifies under DG15's public key (<alg>: RSA with
//              ISO/IEC 9796-2 scheme 1, or ECDSA on P-256 in plain r||s
//              form, per BSI TR-03110 / TR-03111; <h'> is the AA hash).
//
// Public inputs: comm_in and the challenge (one field, 8 bytes big-endian).
// Nothing about DG15, the signature or the passport is public.
use bignum::{BigNum, fields::secp256r1Fq::Secp256r1_Fq, params::BigNumParams, RuntimeBigNum};
use common::{get_country_from_dg1, hash_salt_country_signed_attr_dg1_e_content_private_nullifier};
use sha1::sha1;
use sha256::{sha224_var, sha256_var};
use sha512::{sha384, sha512};
use utils::{
    constants::ECONTENT_LENGTH,
    pack_be_bytes_into_u128s,
    types::{DG1Data, EContentData, SignedAttrsData},
};

/// EF.DG15 is padded with zeros to this length.
pub global DG15_MAX_LENGTH: u32 = 512;
/// ICAO 9303 part 11: the AA challenge (RND.IFD) is 8 bytes.
pub global AA_CHALLENGE_LENGTH: u32 = 8;

// ------------------------------------------------------------ chaining

/// Asserts that comm_in opens to this passport's `id` commitment, exactly as
/// the `integrity` circuit checks it (commit_to_disclosure).
pub fn check_id_commitment(
    comm_in: Field,
    salt_in: Field,
    dg1: DG1Data,
    signed_attributes: SignedAttrsData,
    signed_attributes_size: Field,
    e_content: EContentData,
    private_nullifier: Field,
) {
    let country = get_country_from_dg1(dg1);
    assert(
        comm_in
            == hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
                salt_in,
                country,
                signed_attributes,
                signed_attributes_size,
                dg1,
                e_content,
                private_nullifier,
            ),
        "comm_in does not open to this passport's id commitment",
    );
}

/// The 8 challenge bytes from the public challenge field (asserts < 2^64).
pub fn challenge_bytes(aa_challenge: Field) -> [u8; AA_CHALLENGE_LENGTH] {
    aa_challenge.to_be_bytes()
}

// ------------------------------------------------------------ DER

/// The DER header of the element at `pos`: (header length including the
/// tag, content length). Short form, 0x81 and 0x82 long forms only, and only
/// minimal encodings. Reads a[pos + 3], so callers keep pos + 3 < N.
pub fn der_header<let N: u32>(a: [u8; N], pos: u32) -> (u32, u32) {
    let b1 = a[pos + 1] as u32;
    let b2 = a[pos + 2] as u32;
    let b3 = a[pos + 3] as u32;
    if b1 < 0x80 {
        (2, b1)
    } else if b1 == 0x81 {
        assert(b2 >= 0x80, "non-minimal DER length");
        (3, b2)
    } else {
        assert(b1 == 0x82, "unsupported DER length");
        let l = b2 * 256 + b3;
        assert(l >= 256, "non-minimal DER length");
        (4, l)
    }
}

/// eContent's length (LDSSecurityObject: one DER SEQUENCE at offset 0), from
/// its own header. Constrained: this is what keeps a DG15 entry hidden in
/// the zero padding after eContent from counting.
pub fn econtent_size(e_content: EContentData) -> u32 {
    assert(e_content[0] == 0x30, "eContent is not a SEQUENCE");
    let (h, l) = der_header(e_content, 0);
    let size = h + l;
    assert(size <= ECONTENT_LENGTH, "eContent too long");
    size
}

/// EF.DG15's length (tag 0x6F around a SubjectPublicKeyInfo), from its
/// header. Bytes after it must be zero (the hash functions take a
/// BoundedVec, which checks that).
pub fn dg15_length<let N: u32>(dg15: [u8; N]) -> u32 {
    assert(dg15[0] == 0x6F, "EF.DG15 is not tag 0x6F");
    let (h, l) = der_header(dg15, 0);
    let len = h + l;
    assert(len + 4 <= N, "EF.DG15 too long");
    len
}

// ------------------------------------------------------------ eContent

// A DataGroupHash for DG15 is SEQUENCE { INTEGER 15, OCTET STRING hash }:
// 30 <5+H> 02 01 0F 04 <H> <hash>.

unconstrained fn find_dg15_entry(e_content: EContentData, hash_len: u32) -> u32 {
    let mut idx = 0;
    let mut found = false;
    for i in 2..(ECONTENT_LENGTH - 5) {
        if !found
            & (e_content[i] == 0x02)
            & (e_content[i + 1] == 0x01)
            & (e_content[i + 2] == 0x0F)
            & (e_content[i + 3] == 0x04)
            & (e_content[i + 4] as u32 == hash_len) {
            idx = i;
            found = true;
        }
    }
    idx
}

/// Asserts that eContent (within its DER length) lists `dg15_hash` as the
/// hash of DG15.
pub fn assert_dg15_listed<let H: u32>(e_content: EContentData, dg15_hash: [u8; H]) {
    let size = econtent_size(e_content);
    // Safety: the offset is only a hint; every byte it points at is checked below.
    let idx = unsafe { find_dg15_entry(e_content, H) };
    assert(idx >= 2, "EF.SOD does not list DG15");
    assert(e_content[idx - 2] == 0x30, "DG15 entry is not a SEQUENCE");
    assert(e_content[idx - 1] as u32 == 5 + H, "DG15 entry has the wrong length");
    assert(e_content[idx] == 0x02);
    assert(e_content[idx + 1] == 0x01);
    assert(e_content[idx + 2] == 0x0F);
    assert(e_content[idx + 3] == 0x04);
    assert(e_content[idx + 4] as u32 == H);
    assert(idx + 5 + H <= size, "DG15 entry lies outside eContent");
    for i in 0..H {
        assert(e_content[idx + 5 + i] == dg15_hash[i], "DG15 does not match its hash in EF.SOD");
    }
}

/// Asserts that eContent lists no DG15: no `02 01 0F 04` (INTEGER 15 then an
/// OCTET STRING, the start of every DER DataGroupHash for DG15) anywhere in
/// the 700-byte array. Scanning the padding too is sound (an honest prover
/// pads with zeros) and needs no length. A passport without DG15 whose
/// hashes happen to contain those four bytes (about 1 in 6 million) cannot
/// prove this and is routed to the other ways in.
pub fn assert_dg15_not_listed(e_content: EContentData) {
    for i in 0..(ECONTENT_LENGTH - 3) {
        let hit = (e_content[i] == 0x02)
            & (e_content[i + 1] == 0x01)
            & (e_content[i + 2] == 0x0F)
            & (e_content[i + 3] == 0x04);
        assert(!hit, "EF.SOD lists DG15: prove Active Authentication instead");
    }
}

// ------------------------------------------------------------ hashes

pub fn sha1_of<let N: u32>(msg: [u8; N], len: u32) -> [u8; 20] {
    sha1::sha1_var(BoundedVec::from_parts(msg, len))
}

pub fn sha224_of<let N: u32>(msg: [u8; N], len: u32) -> [u8; 28] {
    sha224_var(msg, len)
}

pub fn sha256_of<let N: u32>(msg: [u8; N], len: u32) -> [u8; 32] {
    sha256_var(msg, len)
}

pub fn sha384_of<let N: u32>(msg: [u8; N], len: u32) -> [u8; 48] {
    sha384::sha384_var(BoundedVec::from_parts(msg, len))
}

pub fn sha512_of<let N: u32>(msg: [u8; N], len: u32) -> [u8; 64] {
    sha512::sha512_var(BoundedVec::from_parts(msg, len))
}

// ------------------------------------------------------------ RSA (ISO/IEC 9796-2 scheme 1)

global RSA_ENCRYPTION_OID: [u8; 11] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

/// The RSA public key in EF.DG15: (modulus, exponent). The modulus must be
/// exactly K bytes with its top bit set; the exponent 1 to 3 bytes. Every
/// header on the way is checked, and the key must end exactly where DG15
/// ends, so the prover cannot point at other bytes of DG15.
pub fn parse_rsa_dg15<let N: u32, let K: u32>(dg15: [u8; N], dg15_len: u32) -> ([u8; K], u32) {
    let (h0, _) = der_header(dg15, 0);
    let mut p = h0;
    assert(dg15[p] == 0x30, "DG15: SubjectPublicKeyInfo");
    let (h1, l1) = der_header(dg15, p);
    assert(p + h1 + l1 == dg15_len, "DG15: SubjectPublicKeyInfo length");
    p += h1;
    assert(dg15[p] == 0x30, "DG15: AlgorithmIdentifier");
    let (h2, l2) = der_header(dg15, p);
    for i in 0..11 {
        assert(dg15[p + h2 + i] == RSA_ENCRYPTION_OID[i], "DG15: not an RSA key");
    }
    p += h2 + l2;
    assert(dg15[p] == 0x03, "DG15: BIT STRING");
    let (h3, l3) = der_header(dg15, p);
    assert(p + h3 + l3 == dg15_len, "DG15: BIT STRING length");
    assert(dg15[p + h3] == 0x00, "DG15: BIT STRING unused bits");
    p += h3 + 1;
    assert(dg15[p] == 0x30, "DG15: RSAPublicKey");
    let (h4, l4) = der_header(dg15, p);
    assert(p + h4 + l4 == dg15_len, "DG15: RSAPublicKey length");
    p += h4;
    assert(dg15[p] == 0x02, "DG15: modulus");
    let (h5, l5) = der_header(dg15, p);
    assert(l5 == K + 1, "DG15: modulus size does not match this circuit");
    assert(dg15[p + h5] == 0x00, "DG15: modulus sign byte");
    p += h5 + 1;
    let mut n: [u8; K] = [0; K];
    for i in 0..K {
        n[i] = dg15[p + i];
    }
    assert(n[0] >= 0x80, "DG15: modulus is shorter than this circuit's size");
    p += K;
    assert(dg15[p] == 0x02, "DG15: exponent");
    let el = dg15[p + 1] as u32;
    assert((el >= 1) & (el <= 3), "DG15: exponent size");
    let mut e: u32 = 0;
    for i in 0..3 {
        if i < el {
            e = e * 256 + dg15[p + 2 + i] as u32;
        }
    }
    assert(p + 2 + el == dg15_len, "DG15: trailing bytes after the key");
    (n, e)
}

/// sig^e mod n by square-and-multiply, for an odd e in [3, 2^17). Same
/// algorithm as noir_rsa's exponentiate_signature (Apache-2.0), which is not
/// exported.
fn rsa_pow<let L: u32, let BITS: u32>(sig: RuntimeBigNum<L, BITS>, exponent: u32) -> RuntimeBigNum<L, BITS> {
    (exponent as Field - 3).assert_max_bit_size::<17>();
    (exponent as Field).assert_max_bit_size::<17>();
    let bits: [bool; 17] = (exponent as Field).to_le_bits::<17>();
    assert(bits[0], "RSA exponent must be odd");
    let mut result = RuntimeBigNum::one(sig.params);
    let mut base = sig;
    for i in 0..17 {
        if bits[i] {
            result = result * base;
        }
        if i != 16 {
            base = base * base;
        }
    }
    result
}

/// Recover the ISO/IEC 9796-2 representative J = sig^e mod n (or n - J,
/// which a signer may send instead: J always ends in the nibble 0xC) and
/// check its header (0x6A: partial recovery, no padding) and trailer.
/// Returns (J, trailer length). `hash_id` is the trailer's hash byte
/// (0x33 SHA-1, 0x38 SHA-224, 0x34 SHA-256, 0x36 SHA-384, 0x35 SHA-512);
/// for SHA-1 the implicit trailer 0xBC is accepted too.
pub fn rsa_aa_recover<let K: u32, let H: u32>(
    modulus: [u8; K],
    exponent: u32,
    signature: [u8; ((K * 8) + 7) / 8],
    redc_param: [u8; K + 1],
    hash_id: u8,
) -> ([u8; K], u32) {
    let n = pack_be_bytes_into_u128s::<K, (K + 14) / 15, 15>(modulus);
    let redc = pack_be_bytes_into_u128s::<K + 1, _, 15>(redc_param);
    let params = BigNumParams::new(false, n, redc);
    // Constrained: the signature is < n.
    let s = RuntimeBigNum::from_be_bytes(params, signature);
    let j = rsa_pow::<_, K * 8>(s, exponent);
    // Constrained (to_be_bytes validates the value is canonical, < n).
    let jb = j.to_be_bytes();
    let alt = (-j).to_be_bytes();
    let use_alt = (jb[K - 1] & 0x0F) != 0x0C;
    let mut rep: [u8; K] = [0; K];
    for i in 0..K {
        rep[i] = if use_alt { alt[i] } else { jb[i] };
    }
    assert((rep[K - 1] & 0x0F) == 0x0C, "AA: bad ISO 9796-2 trailer");
    assert(rep[0] == 0x6A, "AA: bad ISO 9796-2 header");
    let last = rep[K - 1];
    let t: u32 = if (H == 20) & (last == 0xBC) {
        1
    } else {
        assert(last == 0xCC, "AA: bad ISO 9796-2 trailer");
        assert(rep[K - 2] == hash_id, "AA: ISO 9796-2 hash does not match this circuit");
        2
    };
    (rep, t)
}

/// The message the chip hashed: M1 (the recovered part of J) followed by the
/// challenge M2. Returns (message padded with zeros, its length).
pub fn rsa_aa_message<let K: u32, let H: u32>(
    rep: [u8; K],
    trailer_len: u32,
    challenge: [u8; AA_CHALLENGE_LENGTH],
) -> ([u8; K + AA_CHALLENGE_LENGTH], u32) {
    let m1_len = K - 1 - H - trailer_len;
    let mut msg: [u8; K + AA_CHALLENGE_LENGTH] = [0; K + AA_CHALLENGE_LENGTH];
    for i in 0..(K - 1) {
        if i < m1_len {
            msg[i] = rep[i + 1];
        }
    }
    for c in 0..AA_CHALLENGE_LENGTH {
        msg[m1_len + c] = challenge[c];
    }
    (msg, m1_len + AA_CHALLENGE_LENGTH)
}

/// The digest inside J must be H(M1 || challenge).
pub fn rsa_aa_check_digest<let K: u32, let H: u32>(rep: [u8; K], trailer_len: u32, digest: [u8; H]) {
    let base = K - trailer_len - H;
    for i in 0..H {
        assert(rep[base + i] == digest[i], "AA: signature does not cover the challenge");
    }
}

// ------------------------------------------------------------ ECDSA P-256 (plain r || s)

global EC_PUBLIC_KEY_OID: [u8; 9] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
global P256_B: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];

/// The EC public point in EF.DG15 (an id-ecPublicKey SubjectPublicKeyInfo,
/// named or explicit domain parameters): the uncompressed point that ends
/// DG15. The curve itself is checked by assert_on_p256: a point of another
/// curve is (except with negligible probability) not on P-256.
pub fn parse_ec_dg15_p256<let N: u32>(dg15: [u8; N], dg15_len: u32) -> ([u8; 32], [u8; 32]) {
    let (h0, _) = der_header(dg15, 0);
    let mut p = h0;
    assert(dg15[p] == 0x30, "DG15: SubjectPublicKeyInfo");
    let (h1, l1) = der_header(dg15, p);
    assert(p + h1 + l1 == dg15_len, "DG15: SubjectPublicKeyInfo length");
    p += h1;
    assert(dg15[p] == 0x30, "DG15: AlgorithmIdentifier");
    let (h2, l2) = der_header(dg15, p);
    for i in 0..9 {
        assert(dg15[p + h2 + i] == EC_PUBLIC_KEY_OID[i], "DG15: not an EC key");
    }
    p += h2 + l2;
    assert(dg15[p] == 0x03, "DG15: BIT STRING");
    assert(dg15[p + 1] == 0x42, "DG15: not a 256-bit uncompressed point");
    assert(dg15[p + 2] == 0x00, "DG15: BIT STRING unused bits");
    assert(dg15[p + 3] == 0x04, "DG15: point is not uncompressed");
    assert(p + 68 == dg15_len, "DG15: trailing bytes after the key");
    let mut x: [u8; 32] = [0; 32];
    let mut y: [u8; 32] = [0; 32];
    for i in 0..32 {
        x[i] = dg15[p + 4 + i];
        y[i] = dg15[p + 36 + i];
    }
    (x, y)
}

/// Asserts (x, y) is a point of NIST P-256: x, y < p and y^2 = x^3 - 3x + b.
pub fn assert_on_p256(x: [u8; 32], y: [u8; 32]) {
    // from_be_bytes is constrained to canonical values (< p).
    let xf = Secp256r1_Fq::from_be_bytes(x);
    let yf = Secp256r1_Fq::from_be_bytes(y);
    let b = Secp256r1_Fq::from_be_bytes(P256_B);
    assert(yf * yf == xf * xf * xf - xf - xf - xf + b, "DG15: point is not on P-256");
}

/// ECDSA's e for a 256-bit group order from a digest of at most 32 bytes:
/// the digest as a big-endian integer (left-padded).
pub fn ecdsa_e_short<let H: u32>(digest: [u8; H]) -> [u8; 32] {
    let mut e: [u8; 32] = [0; 32];
    for i in 0..H {
        e[32 - H + i] = digest[i];
    }
    e
}

/// ECDSA's e for a 256-bit group order from a longer digest: its leftmost
/// 256 bits.
pub fn ecdsa_e_long<let H: u32>(digest: [u8; H]) -> [u8; 32] {
    let mut e: [u8; 32] = [0; 32];
    for i in 0..32 {
        e[i] = digest[i];
    }
    e
}

/// Verify a plain (r || s) ECDSA P-256 signature with Noir's built-in
/// secp256r1 black box (no third-party curve library).
pub fn verify_p256(x: [u8; 32], y: [u8; 32], signature: [u8; 64], e: [u8; 32]) {
    assert_on_p256(x, y);
    assert(
        std::ecdsa_secp256r1::verify_signature(x, y, signature, e),
        "AA: ECDSA signature invalid",
    );
}
