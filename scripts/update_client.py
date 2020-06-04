import yaml
from sqlalchemy import create_engine
from benwaonline_auth import models
from benwaonline_auth.database import db
from oauthlib.oauth2.rfc6749.utils import list_to_scope
from run import app


def get_url():
    return "mysql+pymysql://{}:{}@{}:{}/".format(
        os.getenv("MYSQL_USER", "root"),
        os.getenv("MYSQL_PASSWORD", "root"),
        os.getenv("MYSQL_HOST", "192.168.10.11"),
        os.getenv("MYSQL_PORT", "3306"),
    )


def permissions_loader(fpath):
    with open(fpath, "r") as f:
        settings = yaml.load(f)

    resources = settings["resources"]

    permissions = []
    for k, v in resources.items():
        permissions.extend([k + ":" + p for p in v["permissions"]])

    return permissions


def update(client, permissions):
    scopes = list_to_scope(permissions)
    client.grant_type = "authorization_code"
    client.response_type = "code"
    client.default_scopes = scopes
    client.allowed_scopes = scopes


if __name__ == "__main__":
    permissions = permissions_loader("benwaonline_auth/scopes.yml")
    with app.app_context():
        client = models.Client.query.first()
        update(client, permissions)
        db.session.commit()
