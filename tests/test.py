from django.contrib.auth.models import User
from django.conf import settings
from django.utils import timezone
from django.test.utils import override_settings
from rest_framework import status
from rest_framework.test import APITestCase
from django_rest_passwordreset.models import ResetPasswordToken
from datetime import datetime, timedelta

try:
    from unittest.mock import patch
except:
    # Python 2.7 fallback
    from mock import patch

# try getting reverse from django.urls
try:
    # Django 1.10 +
    from django.urls import reverse
except:
    # Django 1.8 and 1.9
    from django.core.urlresolvers import reverse


def get_password_reset_token_expiry_time(is_long_token=False):
    """
    Returns the password reset token expirty time in hours (default: 24)
    Set Django SETTINGS.DJANGO_REST_MULTITOKENAUTH_RESET_TOKEN_EXPIRY_TIME to overwrite this time
    :return: expiry time
    """

    if is_long_token:
        return getattr(settings, 'DJANGO_REST_MULTITOKENAUTH_RESET_TOKEN_LONG_EXPIRY_TIME', 48)

    # get token validation time
    return getattr(settings, 'DJANGO_REST_MULTITOKENAUTH_RESET_TOKEN_EXPIRY_TIME', 24)


class HelperMixin:
    """
    Mixin which encapsulates methods for login, logout, request reset password and reset password confirm
    """

    def setUpUrls(self):
        """ set up urls by using djangos reverse function """
        self.reset_password_request_url = reverse('password_reset:reset-password-request')
        self.reset_password_confirm_url = reverse('password_reset:reset-password-confirm')
        self.reset_password_check_url = reverse('password_reset:reset-password-check')

    def django_check_login(self, username, password):
        """
        Checks the django login by querying the user from the database and calling check_password()
        :param username:
        :param password:
        :return:
        """
        user = User.objects.filter(username=username).first()

        return user.check_password(password)

    def rest_do_request_reset_token(self, email, HTTP_USER_AGENT='', REMOTE_ADDR='127.0.0.1'):
        """ REST API wrapper for requesting a password reset token """
        data = {
            'email': email
        }

        return self.client.post(
            self.reset_password_request_url,
            data,
            format='json',
            HTTP_USER_AGENT=HTTP_USER_AGENT,
            REMOTE_ADDR=REMOTE_ADDR
        )

    def rest_do_reset_password_with_token(self, token, new_password, HTTP_USER_AGENT='', REMOTE_ADDR='127.0.0.1'):
        """ REST API wrapper for requesting a password reset token """
        data = {
            'token': token,
            'password': new_password
        }

        return self.client.post(
            self.reset_password_confirm_url,
            data,
            format='json',
            HTTP_USER_AGENT=HTTP_USER_AGENT,
            REMOTE_ADDR=REMOTE_ADDR
        )

    def rest_do_reset_password_check_token(self, token,  HTTP_USER_AGENT='', REMOTE_ADDR='127.0.0.1'):
        data = {
            'token': token,
        }

        return self.client.post(
            self.reset_password_check_url,
            data,
            format='json',
            HTTP_USER_AGENT=HTTP_USER_AGENT,
            REMOTE_ADDR=REMOTE_ADDR
        )


class AuthTestCase(APITestCase, HelperMixin):
    """
    Several Test Cases for the Multi Auth Token Django App
    """

    def setUp(self):
        self.setUpUrls()
        self.user1 = User.objects.create_user("user1", "user1@mail.com", "secret1")
        self.user2 = User.objects.create_user("user2", "user2@mail.com", "secret2")

    @patch('django_rest_passwordreset.signals.reset_password_token_created.send')
    def test_reset_password(self, mock_reset_password_token_created):
        """ Tests resetting a password """

        # there should be zero tokens
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 0)

        response = self.rest_do_request_reset_token(email="user1@mail.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # check that the signal was sent once
        self.assertTrue(mock_reset_password_token_created.called)
        self.assertEqual(mock_reset_password_token_created.call_count, 1)
        last_reset_password_token = mock_reset_password_token_created.call_args[1]['reset_password_token']
        self.assertNotEqual(last_reset_password_token.key, "")

        # there should be one token
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 1)

        # if the same user tries to reset again, the user will get the same token again
        response = self.rest_do_request_reset_token(email="user1@mail.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(mock_reset_password_token_created.call_count, 2)
        last_reset_password_token = mock_reset_password_token_created.call_args[1]['reset_password_token']
        self.assertNotEqual(last_reset_password_token.key, "")

        # there should be one token
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 1)
        # and it should be assigned to user1
        self.assertEqual(
            ResetPasswordToken.objects.filter(key=last_reset_password_token.key).first().user.username,
            "user1"
        )

        # try to reset the password
        response = self.rest_do_reset_password_with_token(last_reset_password_token.key, "new_secret")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # there should be zero tokens
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 0)

        # try to login with the old username/password (should fail)
        self.assertFalse(
            self.django_check_login("user1", "secret1"),
            msg="User 1 should not be able to login with the old credentials"
        )

        # try to login with the new username/Password (should work)
        self.assertTrue(
            self.django_check_login("user1", "new_secret"),
            msg="User 1 should be able to login with the modified credentials"
        )

    def test_reset_password_expiration(self):
        token_creation_time = timezone.now() - timedelta(hours=get_password_reset_token_expiry_time() + 1)

        # create expired token
        token = ResetPasswordToken.objects.create(user=self.user1)
        token.created_at = token_creation_time
        token.save()  # can't fake created_at in model creation

        # there should be one tokens
        self.assertEqual(ResetPasswordToken.objects.filter(used=False, expired=False).count(), 1)

        response = self.rest_do_request_reset_token(email=self.user1.email)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # there should be two tokens - one expired and one valid
        self.assertEqual(ResetPasswordToken.objects.all().count(), 2)
        self.assertEqual(ResetPasswordToken.objects.filter(used=True, expired=True).count(), 1)
        self.assertEqual(ResetPasswordToken.objects.filter(used=False, expired=False).count(), 1)

    def test_reset_password_long_expiration(self):
        token_creation_time = timezone.now() - timedelta(hours=get_password_reset_token_expiry_time(True) + 1)

        # create expired token
        token = ResetPasswordToken.objects.create(user=self.user1)
        token.is_long_token = True
        token.created_at = token_creation_time
        token.save()  # can't fake created_at in model creation

        # there should be one tokens
        self.assertEqual(ResetPasswordToken.objects.filter(used=False, expired=False).count(), 1)

        response = self.rest_do_request_reset_token(email=self.user1.email)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # there should be two tokens - one expired and one valid
        self.assertEqual(ResetPasswordToken.objects.all().count(), 2)
        self.assertEqual(ResetPasswordToken.objects.filter(used=True, expired=True).count(), 1)
        self.assertEqual(ResetPasswordToken.objects.filter(used=False, expired=False).count(), 1)

    def test_reset_password_side_channel_attacks(self):
        start = datetime.now()
        response = self.rest_do_request_reset_token(email=self.user1.email)
        end = datetime.now()
        valid_mail_diff = end - start
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        start = datetime.now()
        response = self.rest_do_request_reset_token(email='user3@mail.com')
        end = datetime.now()
        unvalid_mail_diff = end - start
        #  make sure server returns normal response for non-valid email
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(unvalid_mail_diff >= valid_mail_diff)

    @patch('django_rest_passwordreset.signals.reset_password_token_created.send')
    def test_reset_password_multiple_users(self, mock_reset_password_token_created):
        """ Checks whether multiple password reset tokens can be created for different users """
        # connect signal
        # we need to check whether the signal is getting called

        # create a token for user 1
        response = self.rest_do_request_reset_token(email="user1@mail.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 1)
        self.assertTrue(mock_reset_password_token_created.called)
        self.assertEquals(mock_reset_password_token_created.call_count, 1)
        token1 = mock_reset_password_token_created.call_args[1]['reset_password_token']

        # create another token for user 2
        response = self.rest_do_request_reset_token(email="user2@mail.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tokens = ResetPasswordToken.objects.filter(used=False)
        self.assertEqual(tokens.count(), 2)
        self.assertEquals(mock_reset_password_token_created.call_count, 2)
        token2 = mock_reset_password_token_created.call_args[1]['reset_password_token']

        # validate that those two tokens are different
        self.assertNotEqual(tokens[0].key, tokens[1].key)

        # try to request another token, there should still always be two keys
        response = self.rest_do_request_reset_token(email="user1@mail.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 2)

        # create another token for user 2
        response = self.rest_do_request_reset_token(email="user2@mail.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 2)

        # try to reset password of user2
        response = self.rest_do_reset_password_with_token(token2.key, "secret2_new")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # now there should only be one token left (token1)
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 1)
        self.assertEqual(ResetPasswordToken.objects.filter(key=token1.key).count(), 1)

        # user 2 should be able to login with "secret2_new" now
        self.assertTrue(
            self.django_check_login("user2", "secret2_new"),
        )

        # try to reset again with token2 (should not work)
        response = self.rest_do_reset_password_with_token(token2.key, "secret2_fake_new")
        self.assertEquals(response.status_code, status.HTTP_404_NOT_FOUND)

        # user 2 should still be able to login with "secret2_new" now
        self.assertTrue(
            self.django_check_login("user2", "secret2_new"),
        )

    @patch('django_rest_passwordreset.signals.reset_password_token_created.send')
    @patch('django_rest_passwordreset.signals.pre_password_reset.send')
    @patch('django_rest_passwordreset.signals.post_password_reset.send')
    def test_signals(self,
                     mock_post_password_reset,
                     mock_pre_password_reset,
                     mock_reset_password_token_created
                     ):
        # check that all mocks have not been called yet
        self.assertFalse(mock_reset_password_token_created.called)
        self.assertFalse(mock_post_password_reset.called)
        self.assertFalse(mock_pre_password_reset.called)

        # request token for user1
        response = self.rest_do_request_reset_token(email="user1@mail.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 1)

        # verify that the reset_password_token_created signal was fired
        self.assertTrue(mock_reset_password_token_created.called)
        self.assertEquals(mock_reset_password_token_created.call_count, 1)

        token1 = mock_reset_password_token_created.call_args[1]['reset_password_token']
        self.assertNotEqual(token1.key, "",
                            msg="Verify that the reset_password_token of the reset_password_Token_created signal is not empty")

        # verify that the other two signals have not yet been called
        self.assertFalse(mock_post_password_reset.called)
        self.assertFalse(mock_pre_password_reset.called)

        # reset password
        response = self.rest_do_reset_password_with_token(token1.key, "new_secret")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # now the other two signals should have been called
        self.assertTrue(mock_post_password_reset.called)
        self.assertTrue(mock_pre_password_reset.called)

    @patch('django_rest_passwordreset.signals.reset_password_token_created.send')
    @override_settings(DJANGO_REST_MULTITOKENAUTH_USE_USERNAME=True)
    def test_username_as_email(self, mock_reset_password_token_created):
        # there should be zero tokens
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 0)

        user = User.objects.create_user(username="username@mail.com",
                                        email="email@mail.com",
                                        password="need_to_have_this")

        response = self.rest_do_request_reset_token(email=user.username)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # check that the signal was sent once
        self.assertTrue(mock_reset_password_token_created.called)
        self.assertEqual(mock_reset_password_token_created.call_count, 1)
        last_reset_password_token = mock_reset_password_token_created.call_args[1]['reset_password_token']
        self.assertNotEqual(last_reset_password_token.key, "")
        self.assertEqual(last_reset_password_token.user.id, user.id)

    @patch('django_rest_passwordreset.signals.reset_password_token_created.send')
    def test_multiple_uses_of_same_token(self, mock_reset_password_token_created):
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 0)

        user = User.objects.create_user(username="username",
                                        email="email@mail.com",
                                        password="need_to_have_this")

        response = self.rest_do_request_reset_token(email=user.email)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        token = mock_reset_password_token_created.call_args[1]['reset_password_token']

        first_reset_password = self.rest_do_reset_password_with_token(token.key, 'new_password')
        self.assertEqual(first_reset_password.status_code, status.HTTP_200_OK)

        second_reset_password = self.rest_do_reset_password_with_token(token.key, 'other_new_password')
        self.assertEqual(second_reset_password.status_code, status.HTTP_404_NOT_FOUND)

    @patch('django_rest_passwordreset.signals.reset_password_token_created.send')
    def test_token_with_url_parameter(self, mock_reset_password_token_created):
        # there should be zero tokens
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 0)

        response = self.rest_do_request_reset_token(email="user1@mail.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # check that the signal was sent once
        self.assertTrue(mock_reset_password_token_created.called)
        self.assertEqual(mock_reset_password_token_created.call_count, 1)
        last_reset_password_token = mock_reset_password_token_created.call_args[1]['reset_password_token']
        self.assertNotEqual(last_reset_password_token.key, "")

        # there should be one token
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 1)

        reset_token_with_parameter = f'{last_reset_password_token.key}?parameter=value'

        response = self.rest_do_reset_password_check_token(reset_token_with_parameter)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.rest_do_reset_password_with_token(reset_token_with_parameter, "new_secret")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # there should be zero tokens
        self.assertEqual(ResetPasswordToken.objects.filter(used=False).count(), 0)

        # try to login with the old username/password (should fail)
        self.assertFalse(
            self.django_check_login("user1", "secret1"),
            msg="User 1 should not be able to login with the old credentials"
        )

        # try to login with the new username/Password (should work)
        self.assertTrue(
            self.django_check_login("user1", "new_secret"),
            msg="User 1 should be able to login with the modified credentials"
        )
