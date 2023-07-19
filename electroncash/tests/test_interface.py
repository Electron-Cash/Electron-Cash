import unittest
import ssl

from .. import interface


class TestInterfaceSSLVerify(unittest.TestCase):
    """Test CA certificate verification using https://badssl.com"""

    def has_ca_signed_valid_cert(self, server: str) -> bool:
        retries = 0
        while retries < 5:
            try:
                i = interface.TcpConnection(server=server, queue=None, config_path=None)
                s = i._get_socket_and_verify_ca_cert()
                s.close()
                return bool(s)
            except TimeoutError:
                retries += 1

    def test_verify_good_ca_cert(self):
        # These are also a wildcard certificate
        self.assertTrue(self.has_ca_signed_valid_cert("badssl.com:443:s"))
        self.assertTrue(self.has_ca_signed_valid_cert("sha256.badssl.com:443:s"))

    def test_verify_bad_ca_cert(self):
        # See https://github.com/openssl/openssl/blob/70c2912f635aac8ab28629a2b5ea0c09740d2bda/include/openssl/x509_vfy.h#L99
        # for a list of verify error codes

        with self.assertRaises(ssl.SSLCertVerificationError) as cm:
            self.has_ca_signed_valid_cert("expired.badssl.com:443:s")
        self.assertEqual(cm.exception.verify_code, 10)  # X509_V_ERR_CERT_HAS_EXPIRED

        with self.assertRaises(ssl.SSLCertVerificationError) as cm:
            self.has_ca_signed_valid_cert("wrong.host.badssl.com:443:s")
        self.assertEqual(cm.exception.verify_code, 62)  # X509_V_ERR_HOSTNAME_MISMATCH

        with self.assertRaises(ssl.SSLCertVerificationError) as cm:
            self.has_ca_signed_valid_cert("self-signed.badssl.com:443:s")
        self.assertEqual(cm.exception.verify_code, 18)  # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT

        with self.assertRaises(ssl.SSLCertVerificationError) as cm:
            self.has_ca_signed_valid_cert("untrusted-root.badssl.com:443:s")
        self.assertEqual(cm.exception.verify_code, 19)  # X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN

    def test_verify_good_tls_version(self):
        self.assertTrue(self.has_ca_signed_valid_cert("tls-v1-2.badssl.com:1012:s"))

    def test_verify_bad_tls_version(self):
        with self.assertRaises(ssl.SSLError) as cm:
            self.has_ca_signed_valid_cert("tls-v1-0.badssl.com:1010:s")
        self.assertEqual(cm.exception.reason, "UNSUPPORTED_PROTOCOL")
