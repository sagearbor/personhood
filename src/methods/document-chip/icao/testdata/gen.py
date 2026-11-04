#!/usr/bin/env python3
"""Generate ePassport test vectors in the real ICAO 9303 file formats.

Run from this directory:  python3 -I gen.py
Needs only the openssl CLI (3.x+). Re-running replaces every file with new
keys; the Go tests read whatever is here.

The CMS SignedData in each EF.SOD is produced by `openssl cms`, an
implementation independent of the Go code under test, so the tests check
the Go parser against a second implementation rather than against itself.

Vectors (one directory each):
  rsa-pss/     CSCA RSA-3072, DSC RSA-2048, SOD signed RSASSA-PSS/SHA-256
               (the German style), DG15 RSA-1024 Active Authentication key
  bp256/       CSCA + DSC on brainpoolP256r1 with EXPLICIT curve parameters,
               SOD signed ecdsa-with-SHA256, DG15 brainpool AA key
  p256/        CSCA + DSC on NIST P-256 (named curve), SOD ecdsa-with-SHA384,
               no DG15 (a chip without Active Authentication)
  expired/     as p256 but DG1 is the ICAO 9303 Part 4 specimen MRZ
               (ERIKSSON ANNA MARIA, L898902C3, expired 2012-04-15)
  rogue-csca/  a CSCA that is not in any trust list, signing a DSC and SOD
               in the same format (the "wrong CSCA" negative case)

All names are the ICAO specimen state Utopia ("UT" in certificates, "UTO" in
the MRZ). No real person or document is represented.
"""
import os
import shutil
import subprocess
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))


def run(*args, inp=None):
    return subprocess.run(args, check=True, capture_output=True, input=inp).stdout


def tlv(tag: bytes, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    elif n < 0x10000:
        ln = bytes([0x82, n >> 8, n & 0xFF])
    else:
        ln = bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])
    return tag + ln + value


def der_int(v: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return tlv(b"\x02", b)


def der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(enc))
    return tlv(b"\x06", out)


def seq(*items: bytes) -> bytes:
    return tlv(b"\x30", b"".join(items))


def check_digit(s: str) -> str:
    total = 0
    for i, c in enumerate(s):
        if c.isdigit():
            v = int(c)
        elif c.isalpha():
            v = ord(c) - ord("A") + 10
        else:
            v = 0
        total += v * (7, 3, 1)[i % 3]
    return str(total % 10)


def td3(number: str, dob: str, expiry: str, nationality="UTO", sex="F", optional="ZE184226B") -> str:
    num = (number + "<" * 9)[:9]
    opt = (optional + "<" * 14)[:14]
    line1 = ("P<UTOERIKSSON<<ANNA<MARIA" + "<" * 44)[:44]
    l2 = num + check_digit(num) + nationality + dob + check_digit(dob) + sex + expiry + check_digit(expiry) + opt + check_digit(opt)
    composite = l2[0:10] + l2[13:20] + l2[21:43]
    return line1 + l2 + check_digit(composite)


SPECIMEN_EXPIRED = (
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
    "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
)


def dg1(mrz: str) -> bytes:
    return tlv(b"\x61", tlv(b"\x5f\x1f", mrz.encode()))


def keygen(path: str, kind: str):
    if kind.startswith("rsa"):
        bits = kind[3:]
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}", "-out", path)
    elif kind == "bp256":
        run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP256r1",
            "-pkeyopt", "ec_param_enc:explicit", "-out", path)
    elif kind == "p256":
        run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", path)
    else:
        raise ValueError(kind)


def make_chain(d: str, csca_kind: str, dsc_kind: str, pss: bool, cn: str):
    keygen(f"{d}/csca.key", csca_kind)
    keygen(f"{d}/dsc.key", dsc_kind)
    sigopt = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"] if pss else []
    run("openssl", "req", "-new", "-x509", "-key", f"{d}/csca.key", "-out", f"{d}/csca.pem", "-days", "5475",
        "-subj", f"/C=UT/O=Utopia/OU=Passport Office/CN={cn}", "-sha256", *sigopt,
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-new", "-key", f"{d}/dsc.key", "-out", f"{d}/dsc.csr",
        "-subj", f"/C=UT/O=Utopia/OU=Passport Office/CN={cn} Document Signer")
    with open(f"{d}/dsc.ext", "w") as f:
        f.write("keyUsage=critical,digitalSignature\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n")
    run("openssl", "x509", "-req", "-in", f"{d}/dsc.csr", "-CA", f"{d}/csca.pem", "-CAkey", f"{d}/csca.key",
        "-CAcreateserial", "-out", f"{d}/dsc.pem", "-days", "3650", "-sha256", "-extfile", f"{d}/dsc.ext", *sigopt)
    for f in ("dsc.csr", "dsc.ext", "csca.srl"):
        if os.path.exists(f"{d}/{f}"):
            os.remove(f"{d}/{f}")


def make_sod(d: str, dgs: dict, md: str, pss: bool, lds_hash="sha256"):
    hash_oid = {"sha256": "2.16.840.1.101.3.4.2.1", "sha384": "2.16.840.1.101.3.4.2.2"}[lds_hash]
    hashes = b"".join(seq(der_int(n), tlv(b"\x04", hashlib.new(lds_hash, v).digest())) for n, v in sorted(dgs.items()))
    lds = seq(der_int(0), seq(der_oid(hash_oid)), seq(hashes))
    with open(f"{d}/lds.der", "wb") as f:
        f.write(lds)
    keyopt = ["-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_pss_saltlen:32"] if pss else []
    cms = run("openssl", "cms", "-sign", "-binary", "-nodetach", "-nosmimecap", "-in", f"{d}/lds.der",
              "-econtent_type", "2.23.136.1.1.1", "-md", md, "-signer", f"{d}/dsc.pem", "-inkey", f"{d}/dsc.key",
              "-outform", "DER", *keyopt)
    os.remove(f"{d}/lds.der")
    with open(f"{d}/EF.SOD", "wb") as f:
        f.write(tlv(b"\x77", cms))


def write(d: str, name: str, data: bytes):
    with open(f"{d}/{name}", "wb") as f:
        f.write(data)


def dg15_for(d: str, kind: str) -> bytes:
    keygen(f"{d}/aa.key", kind)
    spki = run("openssl", "pkey", "-in", f"{d}/aa.key", "-pubout", "-outform", "DER")
    return tlv(b"\x6f", spki)


def vector(name, csca_kind, dsc_kind, pss, md, mrz, aa_kind=None, lds_hash="sha256", cn="CSCA Utopia"):
    d = os.path.join(HERE, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    make_chain(d, csca_kind, dsc_kind, pss, cn)
    dgs = {1: dg1(mrz), 2: tlv(b"\x75", b"specimen face image placeholder, not a photo")}
    if aa_kind:
        dgs[15] = dg15_for(d, aa_kind)
    for n, v in dgs.items():
        write(d, f"EF.DG{n}", v)
    make_sod(d, dgs, md, pss, lds_hash)
    os.remove(f"{d}/dsc.key")
    os.remove(f"{d}/csca.key")


if __name__ == "__main__":
    valid = td3("L898902C3", "740812", "340415")
    vector("rsa-pss", "rsa3072", "rsa2048", True, "sha256", valid, aa_kind="rsa1024")
    vector("bp256", "bp256", "bp256", False, "sha256", valid, aa_kind="bp256")
    vector("p256", "p256", "p256", False, "sha384", valid, lds_hash="sha384")
    vector("expired", "p256", "p256", False, "sha256", SPECIMEN_EXPIRED)
    vector("rogue-csca", "p256", "p256", False, "sha256", valid, cn="CSCA Utopia")
    print("ok")
