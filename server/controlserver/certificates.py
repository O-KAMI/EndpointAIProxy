"""Generate the same RSA/IP leaf certificate profile as the original 0.1.19 tool."""
import base64
import hashlib
import ipaddress
import json
import os
from datetime import timedelta
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from .backup import atomic_json
from .security import utcnow, timestamp


def certificate_info(cert, ip):
    if not isinstance(cert.public_key(), rsa.RSAPublicKey) or cert.public_key().key_size != 3072:
        raise ValueError("Certificate must use RSA 3072")
    now = utcnow()
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError("Certificate is not currently valid")
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if list(names) != [x509.IPAddress(ipaddress.ip_address(ip))]:
        raise ValueError("Certificate IP SAN does not match the requested IP")
    if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("A server leaf certificate is required")
    if list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) != [ExtendedKeyUsageOID.SERVER_AUTH]:
        raise ValueError("Certificate must allow server authentication only")
    public_key = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return dict(ip=ip, rsaKeySize=3072, notBefore=timestamp(cert.not_valid_before_utc),
        notAfter=timestamp(cert.not_valid_after_utc),
        spkiSha256=base64.b64encode(hashlib.sha256(public_key).digest()).decode("ascii"),
        sha256Fingerprint=cert.fingerprint(hashes.SHA256()).hex().upper())


def ensure_certificate(directory, ip="10.220.22.112", days=365):
    if not 1 <= days <= 825:
        raise ValueError("Certificate lifetime must be between 1 and 825 days")
    ip = str(ipaddress.ip_address(ip))
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert_path, key_path = directory / "server.crt", directory / "server.key"
    if cert_path.exists() != key_path.exists():
        raise ValueError("Incomplete certificate/key pair; refusing to overwrite")
    if not cert_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip)])
        now = utcnow()
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
        # Exclusive creation prevents accidentally replacing an installed private key.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        with cert_path.open("xb") as file:
            file.write(cert.public_bytes(serialization.Encoding.PEM))
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise ValueError("Certificate and private key do not match")
    result = certificate_info(cert, ip)
    public = directory / "control-server.cer"
    public.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    atomic_json(directory / "certificate.json", result)
    return result
