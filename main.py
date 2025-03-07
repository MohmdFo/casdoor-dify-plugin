import os
import urllib.parse

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from casdoor import CasdoorSDK
from dotenv import load_dotenv

app = FastAPI()

# Load environment variables from .env
load_dotenv()

# Retrieve credentials from environment variables
CASDOOR_CERT = os.getenv("CASDOOR_CERT")
CASDOOR_ENDPOINT = os.getenv("CASDOOR_ENDPOINT")
CASDOOR_CLIENT_ID = os.getenv("CASDOOR_CLIENT_ID")
CASDOOR_CLIENT_SECRET = os.getenv("CASDOOR_CLIENT_SECRET")
CASDOOR_ORG_NAME = os.getenv("CASDOOR_ORG_NAME")
CASDOOR_APP_NAME = os.getenv("CASDOOR_APP_NAME")

app = FastAPI()

# Initialize the Casdoor SDK with your environment variables.
casdoor_sdk = CasdoorSDK(
    endpoint=CASDOOR_ENDPOINT,
    client_id=CASDOOR_CLIENT_ID,
    client_secret=CASDOOR_CLIENT_SECRET,
    certificate=CASDOOR_CERT,
    org_name=CASDOOR_ORG_NAME,
    application_name=CASDOOR_APP_NAME
)

def get_casdoor_login_url(redirect_uri: str, state: str = "state"):
    """Builds the Casdoor OAuth login URL manually."""
    base_url = casdoor_sdk.endpoint.rstrip("/")
    params = {
        "client_id": casdoor_sdk.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid",  # Add additional scopes if needed, e.g., "profile email"
        "state": state
    }
    query_string = urllib.parse.urlencode(params)
    return f"{base_url}/login/oauth/authorize?{query_string}"

def get_casdoor_signup_url(redirect_uri: str, state: str = "state"):
    """Builds the Casdoor OAuth signup URL manually."""
    base_url = casdoor_sdk.endpoint.rstrip("/")
    params = {
        "client_id": casdoor_sdk.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid",  # Add additional scopes if needed
        "state": state
    }
    query_string = urllib.parse.urlencode(params)
    # Adjust the URL path if your Casdoor instance uses a different signup endpoint.
    return f"{base_url}/signup/oauth/authorize?{query_string}"

# Endpoint to start the OAuth login process.
@app.get("/login")
def login():
    redirect_uri = "http://localhost:8000/callback"  # Must match your Casdoor app configuration.
    login_url = get_casdoor_login_url(redirect_uri)
    return RedirectResponse(login_url)

# Endpoint to start the OAuth signup process.
@app.get("/signup")
def signup():
    redirect_uri = "http://localhost:8000/callback"  # Ensure this URI is allowed in your Casdoor app.
    signup_url = get_casdoor_signup_url(redirect_uri)
    return RedirectResponse(signup_url)

# Callback endpoint that Casdoor redirects to after authentication.
@app.get("/callback")
def callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")
    
    # Exchange the authorization code for an access token.
    token_info = casdoor_sdk.get_oauth_token(code)
    if not token_info:
        raise HTTPException(status_code=400, detail="Failed to obtain token")
    
    # Parse the id_token using parse_jwt_token (the method provided by your SDK version).
    user_info = casdoor_sdk.parse_jwt_token(token_info.get("id_token"))
    return {"token_info": token_info, "user": user_info}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
