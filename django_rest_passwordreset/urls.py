""" URL Configuration for core auth
"""
from django.conf.urls import url, include
from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm, reset_password_check

app_name = 'password_reset'

urlpatterns = [
    url(r'^confirm', reset_password_confirm, name="reset-password-confirm"),
    url(r'^check', reset_password_check, name="reset-password-check"),
    url(r'^', reset_password_request_token, name="reset-password-request"),
]
