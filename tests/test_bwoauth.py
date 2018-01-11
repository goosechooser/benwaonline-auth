from urllib.parse import urlencode
import pytest
from flask import url_for

def auth_request_url(query):
    return url_for('auth.authorize') + '?' + urlencode(query)

def test_authorize(client, session, mocker):
    url = auth_request_url({
        'client_id': 'test_id',
        'client_secret': 'test_secret',
        'response_type': 'code',
        'redirect_uri': 'http://test/callback'
    })

    resp = client.get(url)
    assert resp.status_code == 302
    assert 'authorize-twitter' in resp.headers['Location']

def test_no_authorize_twitter_callback(client, session, mocker):
    with client.session_transaction() as sess:
        sess['redirect_uri'] = 'http://test/callback'

    # Test they didn't want to login
    mocker.patch('benwaonline_auth.bwoauth.views.twitter.authorized_response', return_value=None)
    resp = client.get(url_for('auth.authorize_twitter_callback'))
    assert resp.status_code == 302

# Could test for if any of these parameters were missing
def test_authorize_twitter_callback(client, session, mocker):
    # Test if user exists
    with client.session_transaction() as sess:
        sess['credentials'] = {}
        sess['credentials']['redirect_uri'] = 'http://test/callback'
        sess['credentials']['response_type'] = 'code'
        sess['credentials']['scopes'] = 'test scopes'
        sess['credentials']['client_id'] = 'test_id'
        sess['credentials']['client_secret'] = 'test_secret'

    twitter_resp = {
        'oauth_token': 'value',
        'oauth_token_secret': 'value',
        'screen_name': 'value',
        'user_id': '6969',
        'x_auth_expires': '0'
    }
    mocker.patch('benwaonline_auth.bwoauth.views.twitter.authorized_response', return_value=twitter_resp)
    resp = client.get(url_for('auth.authorize_twitter_callback'))
    assert resp.status_code == 302
    assert '?code=' in resp.headers['Location']

    # Test if user doesnt exist
    with client.session_transaction() as sess:
        sess['credentials'] = {}
        sess['credentials']['redirect_uri'] = 'http://test/callback'
        sess['credentials']['response_type'] = 'code'
        sess['credentials']['scopes'] = 'test scopes'
        sess['credentials']['client_id'] = 'test_id'
        sess['credentials']['client_secret'] = 'test_secret'

    twitter_resp = {
        'oauth_token': 'value',
        'oauth_token_secret': 'value',
        'screen_name': 'value',
        'user_id': '696969',
        'x_auth_expires': '0'
    }
    mocker.patch('benwaonline_auth.bwoauth.views.twitter.authorized_response', return_value=twitter_resp)
    resp = client.get(url_for('auth.authorize_twitter_callback'))
    assert resp.status_code == 302
    assert '?code=' in resp.headers['Location']

def test_authorize_twitter_callback_missing_param(client, session, mocker):
    # Test if user exists
    with client.session_transaction() as sess:
        sess['credentials'] = {}
        # sess['credentials']['redirect_uri'] = 'http://test/callback'
        sess['credentials']['response_type'] = 'code'
        sess['credentials']['scopes'] = 'test scopes'
        sess['credentials']['client_id'] = 'test_id'
        sess['credentials']['client_secret'] = 'test_secret'

    twitter_resp = {
        'oauth_token': 'value',
        'oauth_token_secret': 'value',
        'screen_name': 'value',
        'user_id': '6969',
        'x_auth_expires': '0'
    }
    mocker.patch('benwaonline_auth.bwoauth.views.twitter.authorized_response', return_value=twitter_resp)
    resp = client.get(url_for('auth.authorize_twitter_callback'))

    assert resp.status_code == 500
    assert 'invalid_request' in resp.json['error']

def test_issue_token(client, session):
    pass

def test_invalid_client_id(client, session):
    url = auth_request_url({'client_id': 'yes'})
    resp = client.get(url)

    assert 'Invalid client_id' in resp.json['error_description']
    assert resp.status_code == 500

def test_invalid_redirect(client, session):
    url = auth_request_url({
        'client_id': 'test_id',
        'redirect_uri': 'not_valid'
        })
    resp = client.get(url)

    assert 'Invalid redirect' in resp.json['error_description']
    assert resp.status_code == 500

def test_invalid_client_refresh_token(client, session):
    # Didnt include client_id
    params = {
        'refresh_token': 'invalid',
        'grant_type': 'refresh_token'
    }
    resp = client.post(url_for('auth.issue_token'), data=params)

    assert 'invalid_client' in resp.json['error']
    assert resp.status_code == 401

    # Client doesnt exist
    params = {
        'refresh_token': 'invalid',
        'grant_type': 'refresh_token',
        'client_id': 'invalid_af'
    }
    resp = client.post(url_for('auth.issue_token'), data=params)

    assert 'invalid_client' in resp.json['error']
    assert resp.status_code == 401

    # Valid client_id but no client_secret
    params = {
        'refresh_token': 'invalid',
        'grant_type': 'refresh_token',
        'client_id': 'test_id'
    }
    resp = client.post(url_for('auth.issue_token'), data=params)

    assert 'invalid_client' in resp.json['error']
    assert resp.status_code == 401

    # Valid client_id but wrong client_secret
    params = {
        'refresh_token': 'invalid',
        'grant_type': 'refresh_token',
        'client_id': 'test_id',
        'client_secret': 'wrong'
    }
    resp = client.post(url_for('auth.issue_token'), data=params)

    assert 'invalid_client' in resp.json['error']
    assert resp.status_code == 401

def test_invalid_refresh_token(client, session):
    params = {
        # 'refresh_token': 'invalid',
        'grant_type': 'refresh_token',
        'client_id': 'test_id',
        'client_secret': 'test_secret'
    }
    resp = client.post(url_for('auth.issue_token'), data=params)
    assert 'Missing refresh token parameter.' in resp.json['error_description']

    params = {
        'refresh_token': 'invalid_token',
        'grant_type': 'refresh_token',
        'client_id': 'test_id',
        'client_secret': 'test_secret'
    }
    resp = client.post(url_for('auth.issue_token'), data=params)
    assert 'invalid_grant' in resp.json['error']

def test_rotate_refresh_token(client, session):
    params = {
        'refresh_token': 'expired',
        'grant_type': 'refresh_token',
        'client_id': 'test_id',
        'client_secret': 'test_secret'
    }
    resp = client.post(url_for('auth.issue_token'), data=params)

    assert resp.json['refresh_token'] != params['refresh_token']

def test_refresh_token(client, session):
    params = {
        'refresh_token': 'testtoken',
        'grant_type': 'refresh_token',
        'client_id': 'test_id',
        'client_secret': 'test_secret'
    }
    resp = client.post(url_for('auth.issue_token'), data=params)
    assert resp.json['refresh_token'] == params['refresh_token']
