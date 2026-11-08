"""
Live smoke test against the running dev server (not the test runner). Run on the box:
  /opt/netbox-dev/venv/bin/python /opt/netbox-credentials/devbox/smoke.py
Creates a throwaway superuser, enrols a software passkey, links a credential to a site,
checks the site page panel, then reveals over the real endpoints.
"""

import importlib.util
import re
import secrets
import subprocess

import requests

# Load the test authenticator by path; importing the package would need NetBox on sys.path.
_spec = importlib.util.spec_from_file_location(
    "authenticator", "/opt/netbox-credentials/netbox_credentials/tests/authenticator.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
SoftAuthenticator = _mod.SoftAuthenticator

BASE = "http://localhost:8002"
PREFIX = "/plugins/credentials"
user, password = "smoke-" + secrets.token_hex(3), secrets.token_urlsafe(16)

subprocess.run(
    [
        "nbdev-manage",
        "shell",
        "-c",
        f"from users.models import User; User.objects.create_superuser('{user}', password='{password}')",
    ],
    check=True,
    capture_output=True,
)

s = requests.Session()
page = s.get(f"{BASE}/login/")
token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page.text).group(1)
r = s.post(
    f"{BASE}/login/",
    data={"csrfmiddlewaretoken": token, "username": user, "password": password},
    headers={"Referer": f"{BASE}/login/"},
    allow_redirects=False,
)
assert r.status_code == 302, r.status_code
csrf = s.cookies["csrftoken"]
H = {"X-CSRFToken": csrf, "Referer": BASE}


def form_post(path, data):
    page = s.get(BASE + path)
    tok = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page.text).group(1)
    return s.post(
        BASE + path, data={"csrfmiddlewaretoken": tok, **data}, headers={"Referer": BASE + path}, allow_redirects=False
    )


auth = SoftAuthenticator(rp_id="localhost", origin=BASE)
begin = s.post(f"{BASE}{PREFIX}/passkeys/register/begin/", json={}, headers=H).json()
r = s.post(
    f"{BASE}{PREFIX}/passkeys/register/finish/",
    headers=H,
    json={"challenge_id": begin["challenge_id"], "credential": auth.create(begin["options"]), "name": "smoke key"},
)
print("enrol:", r.status_code, r.json())

site = form_post("/dcim/sites/add/", {"name": f"Smoke {user}", "slug": user, "status": "active"})
site_url = site.headers["Location"]
site_id = int(re.search(r"/(\d+)/?$", site_url).group(1))
cred = form_post(f"{PREFIX}/credentials/add/", {"name": "Smoke cred", "username": "admin", "secret": "smoke-<pw>&"})
cred_id = int(re.search(r"/(\d+)/?$", cred.headers["Location"]).group(1))
ct = (
    subprocess.run(
        [
            "nbdev-manage",
            "shell",
            "-c",
            "from django.contrib.contenttypes.models import ContentType as C;"
            "print(C.objects.get(app_label='dcim', model='site').pk)",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    .stdout.strip()
    .splitlines()[-1]
)
picker = s.get(f"{BASE}{PREFIX}/assignments/add/", params={"assigned_object_content_type": ct}).text
print("picker searches sites API:", 'data-url="/api/dcim/sites/"' in picker)
a = form_post(
    f"{PREFIX}/assignments/add/?assigned_object_content_type={ct}&assigned_object_object_id={site_id}",
    {"credential": cred_id, "assigned_object_content_type": ct, "assigned_object_object_id": site_id},
)
print("assign:", a.status_code)

page = s.get(BASE + site_url).text
print(
    "site panel shows credential:",
    "Smoke cred" in page,
    "| reveal button:",
    "data-nbc-reveal" in page,
    "| plaintext absent:",
    "smoke-" + "&lt;pw&gt;" not in page and "smoke-<pw>" not in page,
)
cpage = s.get(f"{BASE}{PREFIX}/credentials/{cred_id}/").text
print("credential page plaintext absent:", "smoke-<pw>" not in cpage and "smoke-&lt;pw&gt;" not in cpage)
print("passkey page:", s.get(f"{BASE}{PREFIX}/passkeys/").status_code)

begin = s.post(f"{BASE}{PREFIX}/credentials/{cred_id}/reveal/begin/", headers=H).json()
body = {"challenge_id": begin["challenge_id"], "credential": auth.get(begin["options"])}
r = s.post(f"{BASE}{PREFIX}/credentials/{cred_id}/reveal/finish/", headers=H, json=body)
print(
    "reveal:",
    r.status_code,
    "contains secret:",
    "smoke-&lt;pw&gt;&amp;" in r.json()["html"],
    "| cache:",
    r.headers.get("Cache-Control"),
)
r = s.post(f"{BASE}{PREFIX}/credentials/{cred_id}/reveal/finish/", headers=H, json=body)
print("replay:", r.status_code, "contains secret:", "smoke-" in r.json()["html"])

# Clean up everything this script created.
subprocess.run(
    [
        "nbdev-manage",
        "shell",
        "-c",
        f"from users.models import User; from dcim.models import Site;"
        f"from netbox_credentials.models import Credential;"
        f"Site.objects.filter(slug='{user}').delete(); Credential.objects.filter(pk={cred_id}).delete();"
        f"User.objects.filter(username='{user}').delete()",
    ],
    check=True,
    capture_output=True,
)
print("cleaned up")
