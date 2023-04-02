from OpenSSL.crypto import (
    FILETYPE_ASN1, X509Store, X509StoreContext, X509StoreContextError,
    load_certificate)
from base64 import b64decode


class VerificationError(ValueError):
    pass


class BaseCert:
    @classmethod
    def from_pem(cls, pem_data, type):

        try:
            assert isinstance(pem_data, str), pem_data
            if type == "ca":
                pem_lines = [x.strip() for x in pem_data.strip().split('\n')]
            else:
                pem_lines = [x.strip() for x in pem_data.strip().split('\t')]
            assert pem_lines, 'Empty data'
            assert pem_lines[0] == '-----BEGIN CERTIFICATE-----', 'Bad begin'
            assert pem_lines[-1] == '-----END CERTIFICATE-----', 'Bad end'
        except AssertionError as e:
            raise ValueError('{} in {!r}'.format(e.args[0], pem_data)) from e

        try:
            der_data = b64decode(''.join(pem_lines[1:-1]))
        except ValueError as e:
            raise ValueError('Illegal base64 in {!r}'.format(pem_data)) from e

        return cls.from_der(der_data)

    @classmethod
    def from_der(cls, der_data):
        assert isinstance(der_data, bytes)
        cert = load_certificate(FILETYPE_ASN1, der_data)
        return cls(cert)

    def __init__(self, x509):
        self._x509 = x509
        self._revoked_fingerprints = set()

    def __str__(self):
        try:
            cn = self.get_common_name()
        except Exception:
            cn = '<could_not_get_common_name>'
        try:
            issuer = self.get_issuer_common_name()
        except Exception:
            issuer = '<could_not_get_issuer>'

        return '{} issued by {}'.format(cn, issuer)

    def get_common_name(self):
        return self._get_common_name_from_components(self._x509.get_subject())

    def get_fingerprints(self):
        ret = {
            'SHA-1': self._x509.digest('sha1').decode('ascii'),
            'SHA-256': self._x509.digest('sha256').decode('ascii'),
        }
        assert len(ret['SHA-1']) == 59, ret
        assert all(i in '0123456789ABCDEF:' for i in ret['SHA-1']), ret
        assert len(ret['SHA-256']) == 95, ret
        assert all(i in '0123456789ABCDEF:' for i in ret['SHA-256']), ret
        return ret

    def get_issuer_common_name(self):
        return self._get_common_name_from_components(self._x509.get_issuer())

    def _get_common_name_from_components(self, obj):
        return (
            # May contain other components as well, 'C', 'O', etc..
            dict(obj.get_components())[b'CN'].decode('utf-8'))

    def set_trusted_ca(self, cert):
        self._trusted_ca = cert

    def add_revoked_fingerprint(self, fingerprint_type, fingerprint):
        if fingerprint_type not in ('SHA-1', 'SHA-256'):
            raise ValueError('fingerprint_type should be SHA-1 or SHA-256')

        fingerprint = fingerprint.upper()
        assert all(i in '0123456789ABCDEF:' for i in fingerprint), fingerprint
        self._revoked_fingerprints.add((fingerprint_type, fingerprint))

    def verify(self):
        self.verify_expiry()
        self.verify_against_revoked()
        self.verify_against_ca()

    def verify_expiry(self):
        if self._x509.has_expired():
            raise VerificationError(str(self), 'is expired')

    def verify_against_revoked(self):
        fingerprints = self.get_fingerprints()
        for fingerprint_type, fingerprint in self._revoked_fingerprints:
            if fingerprints.get(fingerprint_type) == fingerprint:
                raise VerificationError(
                    str(self), 'matches revoked fingerprint', fingerprint)

    def verify_against_ca(self):
        if not hasattr(self, '_trusted_ca'):
            raise VerificationError(str(self), 'did not load trusted CA')

        store = X509Store()
        store.add_cert(self._trusted_ca._x509)
        store_ctx = X509StoreContext(store, self._x509)
        try:
            store_ctx.verify_certificate()
        except X509StoreContextError as e:
            # [20, 0, 'unable to get local issuer certificate']
            raise VerificationError(str(self), *e.args)
