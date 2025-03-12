import os
import urllib.parse
import requests
import jwt
import secrets
import datetime
import logging
import redis
from typing import Mapping

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from werkzeug import Request, Response
from dify_plugin import Endpoint
from dotenv import load_dotenv
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load environment variables from .env
load_dotenv()

# Casdoor certificate
CASDOOR_CERT = os.getenv("CASDOOR_CERT")

# Retrieve credentials from environment variables
CASDOOR_ENDPOINT = os.getenv("CASDOOR_ENDPOINT")
CASDOOR_CLIENT_ID = os.getenv("CASDOOR_CLIENT_ID")
CASDOOR_CLIENT_SECRET = os.getenv("CASDOOR_CLIENT_SECRET")
CASDOOR_ORG_NAME = os.getenv("CASDOOR_ORG_NAME")
CASDOOR_APP_NAME = os.getenv("CASDOOR_APP_NAME")

# Database connection details
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Shared secret for generating Dify tokens
SECRET_KEY = os.getenv("SECRET_KEY")
DOMAIN = os.getenv("DOMAIN")

# Redis configuration
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_DB = int(os.getenv("REDIS_DB"))
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB, decode_responses=True)

class CasdoorDifySSOPlugin(Endpoint):
    def generate_dify_access_token(self, account_id: str, expire_minutes: int = 60, edition: str = "dify") -> str:
        """Generates an access token with Dify-like payload."""
        exp_dt = datetime.datetime.utcnow() + datetime.timedelta(minutes=expire_minutes)
        payload = {
            "user_id": account_id,
            "exp": int(exp_dt.timestamp()),
            "iss": "SELF_HOSTED",
            "sub": "Console API Passport"
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return token

    def generate_dify_refresh_token(self, account_id: str) -> str:
        """Generates a refresh token and stores it in Redis for 30 days."""
        token = secrets.token_hex(64)
        redis_client.setex(f"refresh_token:{token}", 30 * 24 * 3600, account_id)
        redis_client.setex(f"account_refresh_token:{account_id}", 30 * 24 * 3600, token)
        return token

    # --- Casdoor OAuth Functions --- #

    def get_casdoor_login_url(self, redirect_uri: str, state: str = "state") -> str:
        """Builds the Casdoor OAuth login URL."""
        base_url = CASDOOR_ENDPOINT.rstrip("/")
        params = {
            "client_id": CASDOOR_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid profile email",
            "state": state,
        }
        query_string = urllib.parse.urlencode(params)
        login_url = f"{base_url}/login/oauth/authorize?{query_string}"
        logging.info(f"Constructed login URL: {login_url}")
        return login_url

    def get_casdoor_signup_url(self, redirect_uri: str, state: str = "state") -> str:
        """Builds the Casdoor OAuth signup URL."""
        base_url = CASDOOR_ENDPOINT.rstrip("/")
        params = {
            "client_id": CASDOOR_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid profile email",
            "state": state,
        }
        query_string = urllib.parse.urlencode(params)
        signup_url = f"{base_url}/signup/oauth/authorize?{query_string}"
        logging.info(f"Constructed signup URL: {signup_url}")
        return signup_url

    def get_oauth_token(self, code: str) -> dict:
        """Exchanges the authorization code for an access token."""
        url = f"{CASDOOR_ENDPOINT.rstrip('/')}/api/login/oauth/access_token"
        payload = {
            "grant_type": "authorization_code",
            "client_id": CASDOOR_CLIENT_ID,
            "client_secret": CASDOOR_CLIENT_SECRET,
            "code": code,
        }
        logging.info(f"Requesting token with code: {code} from URL: {url}")
        response = requests.post(url, data=payload)
        if response.status_code != 200:
            logging.error("Failed to obtain token, status code: %s", response.status_code)
            return {"error": "Failed to obtain token"}
        logging.info("Token obtained successfully.")
        return response.json()

    def parse_jwt_token(self, token: str) -> dict:
        """Parses and decodes the JWT using the provided certificate."""
        logging.info("Parsing JWT token.")
        certificate = x509.load_pem_x509_certificate(CASDOOR_CERT.encode("utf-8"), default_backend())
        public_key = certificate.public_key()
        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=CASDOOR_CLIENT_ID,
            leeway=60  # Allow 60 seconds of clock skew
        )

    # --- Tenant Creation Helper --- #

    def ensure_tenant(self, account, session, Base):
        """Ensures a tenant exists for the account, creating one if necessary."""
        if "tenants" not in Base.classes.keys() or "tenant_account_joins" not in Base.classes.keys():
            raise Exception("Tenants or tenant_account_joins table not found in database schema.")
        
        Tenant = Base.classes.tenants
        TenantAccountJoin = Base.classes.tenant_account_joins
        
        tenant = session.query(Tenant).join(
            TenantAccountJoin,
            Tenant.id == TenantAccountJoin.tenant_id
        ).filter(TenantAccountJoin.account_id == account.id).first()
        
        if not tenant:
            tenant = Tenant(
                name=f"{account.name}'s Workspace",
                created_at=datetime.datetime.utcnow(),
                updated_at=datetime.datetime.utcnow()
            )
            session.add(tenant)
            session.commit()
            ta = TenantAccountJoin(
                tenant_id=tenant.id,
                account_id=account.id,
                role="owner",
                current=True,
                created_at=datetime.datetime.utcnow(),
                updated_at=datetime.datetime.utcnow()
            )
            session.add(ta)
            session.commit()
            logging.info(f"Created new tenant {tenant.id} for account {account.id}")
        return tenant

    # --- Main Process for Casdoor SSO to Dify --- #

    def process_dify_login(self, user_info: dict, redirect_uri: str) -> Response:
        """Processes login, creates/updates account, ensures tenant, and generates tokens."""
        email = user_info.get("email")
        name = user_info.get("name") or (email.split("@")[0] if email else "User")
        open_id = user_info.get("sub") or user_info.get("id")
        if not email or not open_id:
            logging.error("Insufficient user information from Casdoor.")
            return Response("Insufficient user information from Casdoor.", status=400)

        # Connect to the PostgreSQL database
        engine = create_engine(DATABASE_URL)
        Base = automap_base()
        Base.prepare(engine, reflect=True)
        Session = sessionmaker(bind=engine)
        session = Session()

        if "accounts" not in Base.classes.keys():
            session.close()
            return Response("Accounts table not found in database schema.", status=500)
        Account = Base.classes.accounts

        # Find or create account by email
        account = session.query(Account).filter_by(email=email).first()
        if account:
            logging.info(f"Existing account found for email: {email}")
        else:
            logging.info(f"No account found for email: {email}. Creating a new account.")
            account = Account(
                email=email,
                name=name,
                status="active",
                created_at=datetime.datetime.utcnow(),
                updated_at=datetime.datetime.utcnow(),
                initialized_at=datetime.datetime.utcnow()
            )
            session.add(account)
            session.commit()

        account_id = str(account.id)

        # Link Casdoor identity via account_integrates table
        mapped_tables = [t.lower() for t in Base.classes.keys()]
        if "account_integrates" in mapped_tables:
            actual_table_name = [t for t in Base.classes.keys() if t.lower() == "account_integrates"][0]
            AccountIntegrates = getattr(Base.classes, actual_table_name)
            integrate = session.query(AccountIntegrates).filter_by(account_id=account_id, provider="casdoor").first()
            if integrate:
                integrate.open_id = open_id
                logging.info(f"Updated account_integrates for account {account_id}.")
            else:
                new_integrate = AccountIntegrates(
                    account_id=account_id,
                    provider="casdoor",
                    open_id=open_id,
                    encrypted_token="",  # Satisfy NOT NULL constraint
                    created_at=datetime.datetime.utcnow(),
                    updated_at=datetime.datetime.utcnow()
                )
                session.add(new_integrate)
                logging.info(f"Created new account_integrates for account {account_id}.")
            session.commit()
        else:
            session.close()
            return Response("account_integrates table not found in database.", status=500)

        # Ensure tenant exists
        try:
            self.ensure_tenant(account, session, Base)
        except Exception as e:
            session.close()
            return Response(f"Error ensuring tenant: {str(e)}", status=500)

        # Generate tokens
        console_token = self.generate_dify_access_token(account_id, expire_minutes=60, edition="dify")
        refresh_token = self.generate_dify_refresh_token(account_id)

        # Prepare redirect response
        redirect_url = f"{redirect_uri}?access_token={console_token}&refresh_token={refresh_token}"
        response = Response(status=302)
        response.headers["Location"] = redirect_url

        # Set cookies as a fallback
        response.set_cookie(
            key="console_token",
            value=console_token,
            httponly=True,
            secure=False,  # Set to True if using HTTPS
            max_age=60*60,  # 1 hour
            domain=DOMAIN,
            path="/"
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,  # Set to True if using HTTPS
            max_age=30*24*3600,  # 30 days
            domain=DOMAIN,
            path="/"
        )

        session.close()
        logging.info(f"Redirecting user to {redirect_url} with tokens.")
        return response

    # --- Main Endpoint Logic --- #

    def _invoke(self, r: Request, values: Mapping, settings: Mapping) -> Response:
        """
        Invokes the endpoint based on the action specified in the query parameters.
        Use:
          - ?action=login    for login redirection
          - ?action=signup   for signup redirection
          - ?action=callback to handle the OAuth callback
        """
        action = r.args.get("action", "login")  # Default to login if not provided
        logging.info(f"Received action: {action}")

        # Use a custom redirect URI if provided; otherwise, fall back to Dify main page
        redirect_uri = settings.get("redirect_uri") or r.headers.get("Referer")
        logging.info(f"Using redirect URI: {redirect_uri}")

        if action == "login":
            login_url = self.get_casdoor_login_url(redirect_uri)
            logging.info(f"Redirecting to login URL: {login_url}")
            response = Response(status=302)
            response.headers["Location"] = login_url
            return response

        elif action == "signup":
            signup_url = self.get_casdoor_signup_url(redirect_uri)
            logging.info(f"Redirecting to signup URL: {signup_url}")
            response = Response(status=302)
            response.headers["Location"] = signup_url
            return response

        elif action == "callback":
            code = r.args.get("code")
            if not code:
                logging.error("Callback error: Missing authorization code")
                return Response("Missing authorization code", status=400)

            logging.info(f"Received callback with code: {code}")
            token_info = self.get_oauth_token(code)
            if "error" in token_info:
                logging.error("Callback error: Failed to obtain token")
                return Response("Failed to obtain token", status=400)

            id_token = token_info.get("id_token")
            if not id_token:
                logging.error("Callback error: Token response missing id_token")
                return Response("Token response missing id_token", status=400)

            try:
                user_info = self.parse_jwt_token(id_token)
                logging.info("JWT token parsed successfully.")
            except Exception as e:
                logging.exception("Error parsing token")
                return Response(f"Error parsing token: {str(e)}", status=400)

            return self.process_dify_login(user_info, redirect_uri)

        else:
            logging.error(f"Invalid action received: {action}")
            return Response("Invalid action", status=400)