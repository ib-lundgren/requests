import oauthlib.oauth as oauth
from auth import AuthBase

class OAuth(requests.auth.AuthBase):
    
    AUTH_METHODS = ("HEADER", "URI", "BODY")
     
    def __init__(self,  
        client_key=None,
        client_secret=None,
        request_token=None,
        access_token=None,
        token_secret=None,
        rsa_key=None,
        callback=None,
        signature_method="HMAC-SHA1",
        verifier=None,
        realm=None,
        auth_method="HEADER"):
        """Constructs an :class:`OAuth <OAuth>` hook.
        
        :param client_key: The client identifier, also known as consumer key.
        :param client_secret: The client shared secret, or consumer secret
        :param signature_method: One of HMAC-SHA1, RSA-SHA1 and PLAINTEXT
        :param request_token: The oauth token used to authenticate users
        :param callback: The url an authorized user should be redirected to
        :param verifier: Used in combination with request_token to request 
                        an access_token
        :param access_token: The oauth token used to request resources
        :param token_secret: A secret often used in combination with access_token
        :param rsa_key: The string of a private RSA key
        :param realm: Used to set scope in authorization headers.
        :param auth_method: OAuth.X where X is one of HEADER, URI, BODY. 
        """
        if not auth_method in OAuth.AUTH_METHODS:
            raise oauth.OAuthError("Invalid authentication method")

        self.auth_method = auth_method
        self.realm = realm 
        self.auth = oauth.OAuth(client_key=client_key,
                                client_secret=client_secret,
                                request_token=request_token,
                                access_token=access_token,
                                token_secret=token_secret,
                                rsa_key=rsa_key,
                                callback=callback,
                                signature_method=signature_method,
                                verifier=verifier)

    def __call__(self, r):
        if "HEADER" == self.auth_method:
            h = self.auth.auth_header(r.url, r.data, r.method, self.realm)
            r.headers["Authorization"] = h
            return r

        elif "BODY" == self.auth_method:
            b = self.auth.form_body(r.url, r.data, r.method)
            r.data = b
            return r

        else:
            r.url = self.auth.uri_query(r.url, r.data, r.method)
            return r


if __name__ == "__main__":
    key = "mCA55VGdkg0isw5rVi5Ww"
    secret = "y8h2tzximLpXFTspl7FpMURoGKZYAo2Vq1WeYxVwyg"
    request_url = "https://api.twitter.com/oauth/request_token"
    auth_url = "http://api.twitter.com/oauth/authorize"
    access_url = "https://api.twitter.com/oauth/access_token"

    twitter = OAuth(client_key=key, client_secret=secret)
    r = requests.post(request_url, auth=twitter)
    print r.content

