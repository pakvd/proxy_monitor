import ipaddress
import tempfile
import unittest
from pathlib import Path

from cryptography import x509

from app.tls import ensure_certificate


class CertificateTests(unittest.TestCase):
    def test_names_are_saved_and_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            cert, key = ensure_certificate(directory, ["203.0.113.10", "panel.example"])
            again, same_key = ensure_certificate(directory, ["panel.example", "203.0.113.10"])
            self.assertEqual(key.read_bytes(), same_key.read_bytes())
            self.assertEqual(cert.read_bytes(), again.read_bytes())
            loaded = x509.load_pem_x509_certificate(cert.read_bytes())
            alt = loaded.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertIn("panel.example", alt.get_values_for_type(x509.DNSName))
            self.assertIn("localhost", alt.get_values_for_type(x509.DNSName))
            self.assertIn(ipaddress.ip_address("203.0.113.10"), alt.get_values_for_type(x509.IPAddress))
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)

            original = cert.read_bytes()
            renewed, _ = ensure_certificate(directory, ["198.51.100.8"])
            self.assertNotEqual(original, renewed.read_bytes())


if __name__ == "__main__":
    unittest.main()
