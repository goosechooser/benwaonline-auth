from urllib.parse import urlencode
import pytest
from flask import url_for
from benwaonline_auth.bwoauth import cache

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

class TestAuthorizeTwitterCallback(object):
    def test_user_exists(self, client, session, mocker):
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

    def test_user_dont_exist(self, client, session, mocker):
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

    def test_missing_redirect_uri(self, client, session, mocker):
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

@pytest.mark.usefixtures('session')
class TestIssueToken(object):
    def test_invalid_authorization_code(self, client):
        params = {
            'code': 'a_code',
            'grant_type': 'authorization_code',
            'client_id': 'test_id',
            'client_secret': 'test_secret'
        }
        resp = client.post(url_for('auth.issue_token'), data=params)
        assert resp.status_code == 401

    # Could do a whole series of cache related tests
    def test_mismatching_redirect_uri(self, client):
        code = 'a_code'

        associations = {
            'scopes': 'test scopes',
            'redirect_uri': 'test_redirect',
            'client_id': 'test_id',
            'state': 'test_state',
            'user': 'test_user'
        }

        # this could be a test fixture tbh
        cache.set(code, associations)

        params = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': 'test_id',
            'client_secret': 'test_secret'
        }

        resp = client.post(url_for('auth.issue_token'), data=params)
        assert resp.status_code == 400
        assert 'Mismatching redirect URI.' in resp.json['error_description']

    def test_user_has_no_token(self, client):
        code = 'a_code'

        associations = {
            'scopes': 'test scopes',
            'redirect_uri': 'http://test/callback',
            'client_id': 'test_id',
            'state': 'test_state',
            'user': {'user_id': 666}
        }

        # this could be a test fixture tbh
        cache.set(code, associations)

        params = {
            'code': code,
            'redirect_uri': 'http://test/callback',
            'grant_type': 'authorization_code',
            'client_id': 'test_id',
            'client_secret': 'test_secret'
        }
        resp = client.post(url_for('auth.issue_token'), data=params)
        assert resp.status_code == 200

    def test_registered_client(self, client):
        params = {
            'refresh_token': 'testtoken',
            'grant_type': 'refresh_token',
            'client_id': 'test_id',
            'client_secret': 'test_secret'
        }
        resp = client.post(url_for('auth.issue_token'), data=params)
        assert resp.status_code == 200

    def test_no_client_id(self, client):
        params = {
            'refresh_token': 'invalid',
            'grant_type': 'refresh_token'
        }
        resp = client.post(url_for('auth.issue_token'), data=params)

        assert 'invalid_client' in resp.json['error']
        assert resp.status_code == 401

    def test_unregistered_client(self, client):
        params = {
            'refresh_token': 'invalid',
            'grant_type': 'refresh_token',
            'client_id': 'invalid_af'
        }
        resp = client.post(url_for('auth.issue_token'), data=params)

        assert 'invalid_client' in resp.json['error']
        assert resp.status_code == 401

    def test_no_client_secret(self, client):
        params = {
            'refresh_token': 'invalid',
            'grant_type': 'refresh_token',
            'client_id': 'test_id'
        }
        resp = client.post(url_for('auth.issue_token'), data=params)

        assert 'invalid_client' in resp.json['error']
        assert resp.status_code == 401

    def test_wrong_client_secret(self, client):
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

@pytest.mark.usefixtures('session')
class TestRotateRefreshToken(object):
    def test_rotate_refresh_token(self, client):
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
