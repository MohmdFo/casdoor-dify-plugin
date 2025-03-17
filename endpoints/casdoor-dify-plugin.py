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
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    db=REDIS_DB,
    decode_responses=True
)


class CasdoorDifyPluginEndpoint(Endpoint):
    def get_casdoor_login_url(self, redirect_uri: str, state: str = "state") -> str:
        """Builds the Casdoor OAuth login URL (exact same as FastAPI)."""
        base_url = CASDOOR_ENDPOINT.rstrip("/")
        params = {
            "client_id": CASDOOR_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid profile email",
            "state": state,
        }
        query_string = urllib.parse.urlencode(params)
        return f"{base_url}/login/oauth/authorize?{query_string}"

    def get_casdoor_signup_url(self, redirect_uri: str, state: str = "state") -> str:
        """Builds the Casdoor OAuth signup URL (exact same as FastAPI)."""
        base_url = CASDOOR_ENDPOINT.rstrip("/")
        params = {
            "client_id": CASDOOR_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid profile email",
            "state": state,
        }
        query_string = urllib.parse.urlencode(params)
        return f"{base_url}/signup/oauth/authorize?{query_string}"

    def get_oauth_token(self, code: str) -> dict:
        """Exchanges the authorization code for an access token (exact same as FastAPI)."""
        url = f"{CASDOOR_ENDPOINT.rstrip('/')}/api/login/oauth/access_token"
        payload = {
            "grant_type": "authorization_code",
            "client_id": CASDOOR_CLIENT_ID,
            "client_secret": CASDOOR_CLIENT_SECRET,
            "code": code,
        }
        response = requests.post(url, data=payload)
        if response.status_code != 200:
            logging.error(f"Failed to obtain token, status code: {response.status_code}")
            raise Exception("Failed to obtain token")
        return response.json()

    def parse_jwt_token(self, token: str) -> dict:
        """Parses and decodes the JWT using the provided certificate (exact same as FastAPI)."""
        certificate = x509.load_pem_x509_certificate(CASDOOR_CERT.encode("utf-8"), default_backend())
        public_key = certificate.public_key()
        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=CASDOOR_CLIENT_ID,
            leeway=60  # Allow 60 seconds of clock skew
        )

    def generate_dify_access_token(self, account_id: str, expire_minutes: int = 60, edition: str = "dify") -> str:
        """Generates an access token with Dify-like payload (exact same as FastAPI)."""
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
        """Generates a refresh token and stores it in Redis for 30 days (exact same as FastAPI)."""
        token = secrets.token_hex(64)
        redis_client.setex(f"refresh_token:{token}", 30 * 24 * 3600, account_id)
        redis_client.setex(f"account_refresh_token:{account_id}", 30 * 24 * 3600, token)
        return token

    def ensure_tenant(self, account, session, Base):
        """Ensures a tenant exists for the account, creating one if necessary (exact same as FastAPI)."""
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

    def process_dify_login(self, user_info: dict, redirect_uri: str) -> Response:
        """
        Process the login logic (exact same as FastAPI):
          - Connect to the Dify database.
          - Check if an account exists based on the email.
          - If not, create a new account.
          - Link the Casdoor identity to the account.
          - Ensure a tenant exists for the account.
          - Generate an access token and refresh token in a Dify-like format.
          - Redirect the user with these tokens in the URL query string and set cookies.
        """
        email = user_info.get("email")
        name = user_info.get("name") or (email.split("@")[0] if email else "User")
        open_id = user_info.get("sub") or user_info.get("id")
        if not email or not open_id:
            logging.error("Insufficient user information from Casdoor.")
            return Response("Insufficient user information from Casdoor.", status=400)

        # Connect to the PostgreSQL database (exact same as FastAPI)
        engine = create_engine(DATABASE_URL)
        Base = automap_base()
        Base.prepare(engine, reflect=True)
        Session = sessionmaker(bind=engine)
        session = Session()

        if "accounts" not in Base.classes.keys():
            session.close()
            logging.error("Accounts table not found in database schema.")
            return Response("Accounts table not found in database schema.", status=500)
        Account = Base.classes.accounts

        # Find or create account by email (exact same as FastAPI)
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

        # Link Casdoor identity via account_integrates table (exact same as FastAPI)
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
            logging.error("account_integrates table not found in database.")
            return Response("account_integrates table not found in database.", status=500)

        # Ensure tenant exists for the account (exact same as FastAPI)
        self.ensure_tenant(account, session, Base)

        # Generate tokens in a Dify-like format (exact same as FastAPI)
        console_token = self.generate_dify_access_token(account_id, expire_minutes=60, edition="dify")
        refresh_token = self.generate_dify_refresh_token(account_id)

        # Redirect with tokens as query parameters (mimicking Dify's OAuth flow, exact same as FastAPI)
        redirect_url = f"{redirect_uri}?access_token={console_token}&refresh_token={refresh_token}"
        response = Response(status=302)
        response.headers["Location"] = redirect_url

        # Set cookies with exact same attributes as FastAPI
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

    def _invoke(self, r: Request, values: Mapping, settings: Mapping) -> Response:
        """
        Invokes the endpoint based on the query parameter "action".
        Supports:
          - ?action=login to initiate login
          - ?action=signup to initiate signup
          - ?action=callback to handle the OAuth callback
        """
        action = r.args.get("action", "login")
        logging.info(f"Received action: {action}")

        # Use redirect_uri from settings or fallback to the hardcoded value from FastAPI
        redirect_uri = settings.get("redirect_uri", DOMAIN)

        if action == "login":
            url = self.get_casdoor_login_url(redirect_uri)
            logging.info(f"Redirecting to Casdoor login: {url}")
            response = Response(status=302)
            response.headers["Location"] = url
            return response

        elif action == "signup":
            url = self.get_casdoor_signup_url(redirect_uri)
            logging.info(f"Redirecting to Casdoor signup: {url}")
            response = Response(status=302)
            response.headers["Location"] = url
            return response

        elif action == "callback":
            code = r.args.get("code")
            if not code:
                logging.error("Missing authorization code in callback")
                return Response("Missing authorization code", status=400)
            logging.info(f"Received callback with code: {code}")

            try:
                token_info = self.get_oauth_token(code)
                id_token = token_info.get("id_token")
                if not id_token:
                    logging.error("Token response missing id_token")
                    return Response("Token response missing id_token", status=400)

                user_info = self.parse_jwt_token(id_token)
                logging.info("JWT token parsed successfully.")
            except Exception as e:
                logging.exception("Error during token processing")
                return Response(f"Error: {str(e)}", status=400)

            # Redirect to Dify main page with tokens, matching FastAPI
            return self.process_dify_login(user_info, redirect_uri=DOMAIN)

        else:
            logging.error(f"Invalid action: {action}")
            return Response("Invalid action", status=400)
