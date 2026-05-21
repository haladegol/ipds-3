import urllib.request
import urllib.parse
from app import create_app
from models.database import User

# First, get a session cookie by logging in via HTTP
import http.cookiejar
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# login
data = urllib.parse.urlencode({'username': 'ADMIN', 'password': 'ADMIN_PASSWORD'}).encode()
try:
    # Actually, we don't know the password.
    # Let's bypass login by hitting a test endpoint that renders the template with a dummy context!
    pass
except:
    pass

