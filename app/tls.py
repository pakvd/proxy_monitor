from __future__ import annotations

import datetime
import ipaddress
import logging
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger("proxy_monitor")


def ensure_certificate(directory: Path, names: list[str]) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    stamp_path = directory / "names"
    wanted = _stamp(names)
    if cert_path.is_file() and key_path.is_file() and stamp_path.is_file() and stamp_path.read_text() == wanted:
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "proxy-monitor")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(_alt_names(names)), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    stamp_path.write_text(wanted)
    logger.info("выпущен самоподписанный сертификат: %s", wanted.replace(",", ", "))
    return cert_path, key_path


def _stamp(names: list[str]) -> str:
    clean = []
    seen = set()
    for raw in ["localhost", "127.0.0.1", *names]:
        item = raw.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        clean.append(item)
    return ",".join(sorted(clean))


def _alt_names(names: list[str]) -> list[x509.GeneralName]:
    alt: list[x509.GeneralName] = []
    for item in _stamp(names).split(","):
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(item)))
            continue
        except ValueError:
            pass
        try:
            alt.append(x509.DNSName(item))
        except ValueError:
            logger.warning("пропущено имя сертификата: %s", item)
    if not alt:
        alt.append(x509.DNSName("localhost"))
    return alt
