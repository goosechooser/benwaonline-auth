from authlib.integrations.flask_client import OAuth

oauth = OAuth()

# from benwaonline we use BENWA to make twitter authenticate the user
# twitter AUTHENTICATES the user (via the user-agent)
# if user grants access, twitter redirects back to the auth-service
#   take response from twitter and generate access token (scope based on whether they exist or not)
# client receives response, login/register as needed
# and asks for a token
# BENWA authenticates the client (using client_id and client_secret)
#   and validates the authorization code

twitter = oauth.register("twitter", app_key="TWITTER")
