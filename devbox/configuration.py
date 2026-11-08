# NetBox dev instance used only for netbox-credentials
# plugin development. Values come from /etc/netbox-dev.env (root-owned, on the box).
import os
import sys

ALLOWED_HOSTS = ["*"]
# Debug toolbar refuses to load under the test runner.
DEBUG = "test" not in sys.argv
INTERNAL_IPS = ("127.0.0.1", "::1")
# Needed for makemigrations on plugin models.
DEVELOPER = True

DATABASES = {
    "default": {
        "NAME": "netbox_dev",
        "USER": "netbox_dev",
        "PASSWORD": os.environ["NETBOX_DEV_DB_PASSWORD"],
        "HOST": "localhost",
        "PORT": "",
        "CONN_MAX_AGE": 300,
    }
}

# Production NetBox uses Redis DBs 0 and 1. Keep clear of them.
REDIS = {
    "tasks": {"HOST": "localhost", "PORT": 6379, "DATABASE": 2, "SSL": False},
    "caching": {"HOST": "localhost", "PORT": 6379, "DATABASE": 3, "SSL": False},
}

SECRET_KEY = os.environ["NETBOX_DEV_SECRET_KEY"]
API_TOKEN_PEPPERS = {1: os.environ["NETBOX_DEV_PEPPER"]}

PLUGINS = ["netbox_credentials"]
PLUGINS_CONFIG = {
    "netbox_credentials": {
        "master_keys": [os.environ["NETBOX_CREDENTIALS_MASTER_KEY"]],
    },
}
