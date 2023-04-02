from django.urls import path
from authapp.views import ProtectedView, FreeView

urlpatterns = [
    path('pro', ProtectedView.as_view(), name='agent'),
    path('free', FreeView.as_view(), name='free'),
]
