from flask import request, url_for, session, redirect, make_response
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2 import WebApplicationServer

from benwaonline_auth.database import db
from benwaonline_auth.models import User
from benwaonline_auth.schemas import UserSchema
from benwaonline_auth.oauth import twitter
from benwaonline_auth.bwoauth import auth
from benwaonline_auth.bwoauth.core import BenwaValidator, generate_jwt_token, generate_refresh_token

validator = BenwaValidator()
server = WebApplicationServer(
    validator,
    token_generator=generate_jwt_token,
    refresh_token_generator=generate_refresh_token
)

@auth.errorhandler(errors.FatalClientError)
def handle_invalid_usage(error):
    '''Error handler.'''
    response = error.json
    return response, 500

def extract_params(request):
    '''Extracts pertinent info from a request.'''
    body = request.args if request.method == 'GET' else request.form
    return request.base_url, request.method, body, request.headers

@auth.route('/authorize', methods=['GET'])
def authorize():
    ''' First endpoint used in authentication flow
    Example of request received:
    GET /authorize
    ?response_type=code
    &client_id=CLIENT_ID
    &redirect_uri=given by the client
    &scope=openid%20profile
    &state=OPAQUE_VALUE
    '''
    uri, http_method, body, headers = extract_params(request)
    try:
        scopes, credentials = server.validate_authorization_request(
            uri, http_method, body, headers)

        # Need to examine more carefully and decide what I do/don't need
        session['credentials'] = credentials['request']._params
        session['credentials']['scopes'] = scopes
        # request was valid so now we move them to twitter to authenticate
        return redirect(url_for('auth.authorize_twitter'))

    # Errors that should be shown to the user on the provider website
    except errors.FatalClientError as err:
        raise err

    # Errors embedded in the redirect URI back to the client
    except errors.OAuth2Error as err:
        return redirect(err.in_uri(err.redirect_uri))

@auth.route('/authorize-twitter')
def authorize_twitter():
    '''Directs user to twitter authorization page.'''
    callback_url = url_for('auth.authorize_twitter_callback', next=request.args.get('next'))
    return twitter.authorize(callback=callback_url)

@auth.route('/authorize-twitter/callback')
def authorize_twitter_callback():
    '''Callback after a user completes twitter login (or not)
    {
        'oauth_token': 'value',
        'oauth_token_secret': 'value',
        'screen_name': 'value',
        'user_id': 'value',
        'x_auth_expires': '0'
    }
    '''
    resp = twitter.authorized_response()
    if not resp:
        redirect_uri = session['redirect_uri']
        session.clear()
        return redirect(redirect_uri)

    user = User.query.get(resp['user_id'])
    if not user:
        user = User(user_id=resp['user_id'])
        db.session.add(user)
        db.session.commit()

    # serialize me daddy
    session['credentials']['user'] = UserSchema().dump(user).data
    uri, http_method, body, headers = extract_params(request)

    # now we create our authorization code and response
    try:
        headers, body, status = server.create_authorization_response(
            uri, http_method, body, headers, None, session['credentials'])
        return redirect(headers['Location'])

    except errors.FatalClientError as err:
        raise err

    # Errors embedded in the redirect URI back to the client
    except errors.OAuth2Error as err:
        return redirect(err.in_uri(err.redirect_uri))

@auth.route('/oauth/token', methods=['POST'])
def issue_token():
    '''This route issues new access and refresh tokens.'''
    uri, http_method, body, headers = extract_params(request)
    try:
        headers, body, status = server.create_token_response(uri, http_method, body, headers)
        return make_response(body, status, headers)

    # Errors that should be shown to the user on the provider website
    except errors.FatalClientError as err:
        raise err

    # Errors embedded in the redirect URI back to the client
    except errors.OAuth2Error as err:
        return redirect(err.in_uri(err.redirect_uri))

# @auth.route('/oauth/revoke', methods=['POST'])
# def revoke_token():
#     return server.create_revocation_response()