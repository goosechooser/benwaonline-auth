import os
from datetime import timedelta
import pytest

from flask.cli import load_dotenv
load_dotenv()

from benwaonline_auth import create_app
from benwaonline_auth.cache import cache as _cache
from benwaonline_auth.database import db as _db
from benwaonline_auth import models


def pytest_addoption(parser):
    parser.addoption(
        "--db", action="store", default="sqlite", help="my option: mysql or sqlite"
    )


@pytest.fixture(scope="session")
def dbopt(request):
    return request.config.getoption("--db")


@pytest.fixture(scope="session")
def app(dbopt):

    app = create_app("testing")

    if dbopt == "sqlite":
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"

    with app.app_context():
        yield app


@pytest.fixture(scope="function")
def cache():
    yield _cache
    _cache.clear()


@pytest.fixture(scope="session")
def db(app):
    _db.app = app
    _db.drop_all()
    _db.create_all()

    init_clients(_db.session)
    init_users(_db.session)
    init_tokens(_db.session)

    yield _db

    _db.drop_all()


@pytest.fixture(scope="function")
def session(db):
    connection = db.engine.connect()
    transaction = connection.begin()

    options = dict(bind=connection, binds={})
    session = db.create_scoped_session(options=options)

    db.session = session
    yield session

    transaction.rollback()
    connection.close()
    session.remove()


def init_clients(session):
    client = models.Client(
        name="test",
        client_id="test_id",
        client_secret="test_secret",
        is_confidential=True,
        blacklisted=False,
        grant_type="authorization_code",
        response_type="code",
        _redirect_uris="http://test/callback",
        allowed_scopes="ham test thanks",
        default_scopes="ham test",
    )
    session.add(client)
    session.commit()

    return


def init_tokens(session):
    token = models.Token(
        code="testtoken",
        expires_in=timedelta(days=14),
        user_id="6969",
        client_id="test_id",
        scopes="ham test",
    )

    expired = models.Token(
        code="expired",
        expires_in=timedelta(microseconds=1),
        is_expired=True,
        user_id="420",
        client_id="test_id",
        scopes="ham test",
    )

    session.add(token)
    session.add(expired)
    session.commit()

    return


def init_users(session):
    user = models.User(user_id="6969")
    session.add(user)

    user = models.User(user_id="420")
    session.add(user)

    user = models.User(user_id="666")
    session.add(user)
    session.commit()

    return
