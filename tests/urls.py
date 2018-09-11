""" Tests App URL Config """
from django.conf.urls import url, include
from rest_framework.documentation import include_docs_urls

urlpatterns = [
    url(r'^api/password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),
    url(r'^api/docs/', include_docs_urls(title='Django Rest Password Reset')),
]
