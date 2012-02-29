"""
Run Keeper OAuth2 support.

This contribution adds support for Run Keeper OAuth2 service. The settings
RUNKEEPER_CLIENT_ID and RUNKEEPER_CLIENT_SECRET must be defined with the values
given by Flickr application registration process.

By default account id, username and token expiration time are stored in
extra_data field, check OAuthBackend class for details on how to extend it.
"""
try:
    from urlparse import parse_qs
    parse_qs  # placate pyflakes
except ImportError:
    # fall back for Python 2.5
    from cgi import parse_qs

from oauth2 import Token

from social_auth.utils import setting
from social_auth.backends import ConsumerBasedOAuth, OAuthBackend, USERNAME


# Run Keeper configuration
RUNKEEPER_SERVER = 'https://runkeeper.com/apps'
RUNKEEPER_AUTHORIZATION_URL = '%s/authorize' % RUNKEEPER_SERVER
RUNKEEPER_ACCESS_TOKEN_URL = '%s/token' % RUNKEEPER_SERVER


class RunKeeperBackend(OAuthBackend):
    """Run Keeper OAuth2 authentication backend"""
    name = 'runkeeper'
    # Default extra data to store
    EXTRA_DATA = [
        ('id', 'id'),
        ('username', 'username'),
        ('expires', setting('SOCIAL_AUTH_EXPIRATION', 'expires'))
    ]

    def get_user_details(self, response):
        """Return user details from Flickr account"""
        return {USERNAME: response.get('id'),
                'email': '',
                'first_name': response.get('fullname')}


class RunKeeperAuth(ConsumerBasedOAuth):
    """Run Keeper OAuth2 authentication mechanism"""
    AUTHORIZATION_URL = RUNKEEPER_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = RUNKEEPER_ACCESS_TOKEN_URL
    SERVER_URL = RUNKEEPER_SERVER
    AUTH_BACKEND = RunKeeperBackend
    SETTINGS_KEY_NAME = 'RUNKEEPER_CLIENT_ID'
    SETTINGS_SECRET_NAME = 'RUNKEEPER_CLIENT_SECRET'

    def access_token(self, token):
        """Return request for access token value"""
        # Flickr is a bit different - it passes user information along with
        # the access token, so temporarily store it to vie the user_data
        # method easy access later in the flow!
        request = self.oauth_request(token, self.ACCESS_TOKEN_URL)
        response = self.fetch_response(request)
        token = Token.from_string(response)
        params = parse_qs(response)
        print params

        '''
        token.user_nsid = params['user_nsid'][0] if 'user_nsid' in params \
                                                 else None
        token.fullname = params['fullname'][0] if 'fullname' in params \
                                               else None
        token.username = params['username'][0] if 'username' in params \
                                               else None
        '''
        return token

    def user_data(self, access_token):
        """Loads user data from service"""
        return {
            'id': access_token.user_nsid,
            'username': access_token.username,
            'fullname': access_token.fullname,
        }


# Backend definition
BACKENDS = {
    'runkeeper': RunKeeperAuth,
}
