from flask_oauthlib.client import OAuth

oauth = OAuth()

# from benwaonline we use BENWA to make twitter authenticate the user
# twitter AUTHENTICATES the user (via the user-agent)
# if user grants access, twitter redirects back to the auth-service
#   take response from twitter and generate access token (scope based on whether they exist or not)
# client receives response, login/register as needed
# and asks for a token
# BENWA authenticates the client (using client_id and client_secret)
#   and validates the authorization code
twitter = oauth.remote_app(
    'twitter',
    app_key='TWITTER',
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
)