import environ
from rest_framework import permissions
from rest_framework.exceptions import APIException
from authapp.tlshelper import BaseCert, VerificationError
from authapp.messages import (UNAUTHORISED_USER, AGENT_NOT_REGISTERED,
                             CERT_REQUIRED, VERIFICATION_FAILED)

env = environ.Env()
environ.Env.read_env()

class ClientAuthentication(permissions.BasePermission):
    def has_permission(self, request, view):
        pem = request.META.get('HTTP_X_CLIENT_CERT')
        with open(env('CA_CERT'), 'r') as f:
            cacert = f.read()

        try:
            ca = BaseCert.from_pem(cacert, "ca")
            cert = BaseCert.from_pem(pem, "client")
            cert.set_trusted_ca(ca)
        except ValueError:
            raise APIException(CERT_REQUIRED)

        try:
            status = BaseCert.verify(cert)
            print(status)
        except VerificationError:
            raise APIException(VERIFICATION_FAILED)
        return True
