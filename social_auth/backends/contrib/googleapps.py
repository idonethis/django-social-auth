"""
Google Apps OpenID support.
"""
from social_auth.backends.google import GoogleBackend, GoogleAuth
from social_auth.backends.google import GoogleOAuthBackend, GoogleOAuth
from social_auth.backends.exceptions import AuthMissingParameter


GOOGLEAPPS_DOMAIN = 'domain'
GOOGLEAPPS_EMAIL = 'email'
GOOGLEAPPS_OPENID_URL = 'https://www.google.com/accounts/o8/site-xrds?hd=%s'

class GoogleAppsBackend(GoogleBackend):
    """Google Apps OpenID authentication backend"""
    name = 'googleapps'

    def get_user_id(self, details, response):
        """
        Return user unique id provided by service. For google user email
        is unique enought to flag a single user. Email comes from schema:
        http://axschema.org/contact/email
        """
        return details['email']


class GoogleAppsAuth(GoogleAuth):
    """Google Apps OpenID authentication"""
    AUTH_BACKEND = GoogleAppsBackend

    def openid_url(self):
        """Returns Google Apps OpenID authentication URL"""
        if self.data.get(GOOGLEAPPS_DOMAIN):
            domain = self.data.get(GOOGLEAPPS_DOMAIN)
        elif self.data.get(GOOGLEAPPS_EMAIL):
            (user, domain) = self.data.get(GOOGLEAPPS_EMAIL).split('@')
        else:
            raise AuthMissingParameter(self, GOOGLEAPPS_DOMAIN + ' and ' +
                                             GOOGLEAPPS_EMAIL)
        return GOOGLEAPPS_OPENID_URL % domain

# Backend definition
BACKENDS = {
    'googleapps': GoogleAppsAuth,
}
