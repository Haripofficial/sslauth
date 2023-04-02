from rest_framework.generics import GenericAPIView
from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist

from authapp.permissions import ClientAuthentication
from authapp.messages import SUCCESS, SUCCESS_STATUS



class ProtectedView(GenericAPIView):
    permission_classes = [ClientAuthentication]

    def get(self, request, **kwargs):
        return Response(
            {
                "status_code": 200,
                "status": SUCCESS_STATUS,
                "message": SUCCESS,
            },
            status=status.HTTP_200_OK,
        )

class FreeView(GenericAPIView):
    def get(self, request, **kwargs):
        return Response(
            {
                "status_code": 200,
                "status": SUCCESS_STATUS,
                "message": SUCCESS,
            },
            status=status.HTTP_200_OK,
        )