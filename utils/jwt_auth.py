import jwt
from aiohttp import web
from datetime import datetime, timedelta, timezone
import base64

from .users_db import UsersDB
from .access_control import AccessControl
from .logger import Logger

from ..constants import JWT_TOKEN_ALGORITHM, JWT_RS256_PRIVATE_KEY, JWT_RS256_PUBLIC_KEY, JWT_HS256_SECRET_KEY, TOKEN_EXPIRE_MINUTES, JWT_CLAIM_USER_ID, JWT_CLAIM_USERNAME

class JWTAuth:
    def __init__(
        self,
        users_db: UsersDB,
        access_control: AccessControl,
        logger: Logger,
    ):
        self.users_db = users_db
        self.access_control = access_control
        self.logger = logger

        self.logger.info(f"[JWTAuth] Initializing with algorithm: {JWT_TOKEN_ALGORITHM}")
        self.logger.info(f"[JWTAuth] User ID claim: '{JWT_CLAIM_USER_ID}', Username claim: '{JWT_CLAIM_USERNAME}'")

        if JWT_TOKEN_ALGORITHM == "HS256":
            self.__encode_key = JWT_HS256_SECRET_KEY
            self.__decode_key = JWT_HS256_SECRET_KEY
            key_preview = JWT_HS256_SECRET_KEY[:16] if JWT_HS256_SECRET_KEY else None
            self.logger.info(f"[JWTAuth] HS256 secret key loaded: {'yes' if JWT_HS256_SECRET_KEY else 'NO - KEY IS MISSING'} (preview: {key_preview!r})")
        elif JWT_TOKEN_ALGORITHM == "RS256":
            self.__encode_key = JWT_RS256_PRIVATE_KEY
            self.__decode_key = JWT_RS256_PUBLIC_KEY
            self.logger.info(f"[JWTAuth] RS256 private key loaded: {'yes' if JWT_RS256_PRIVATE_KEY else 'NO - KEY IS MISSING'}")
            self.logger.info(f"[JWTAuth] RS256 public key loaded: {'yes' if JWT_RS256_PUBLIC_KEY else 'NO - KEY IS MISSING'}")
            if JWT_RS256_PUBLIC_KEY:
                # Log the modulus prefix to identify which Keycloak key this is
                try:
                    pem_text = JWT_RS256_PUBLIC_KEY.decode('utf-8')
                    self.logger.info(f"[JWTAuth] RS256 public key PEM starts with: {pem_text[:80]}...")
                except Exception:
                    pass
        else:
            self.logger.warning(f"[JWTAuth] Unknown algorithm '{JWT_TOKEN_ALGORITHM}' - encode/decode keys not set!")

    @staticmethod
    def get_token_from_request(request: web.Request) -> str:
        """Extract token from request headers or cookies."""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[len("Bearer ") :]
        return request.cookies.get("jwt_token")

    def create_access_token(self, data: dict, expire_minutes=None) -> str:
        """Create a JWT access token.

        Accepts internal claim names ("id", "username") and maps them to the
        configured claim names before encoding.
        """
        self.logger.debug(f"[JWTAuth] create_access_token: input data keys={list(data.keys())}")
        to_encode = data.copy()
        if "id" in to_encode and JWT_CLAIM_USER_ID != "id":
            self.logger.debug(f"[JWTAuth] Remapping claim 'id' -> '{JWT_CLAIM_USER_ID}'")
            to_encode[JWT_CLAIM_USER_ID] = to_encode.pop("id")
        if "username" in to_encode and JWT_CLAIM_USERNAME != "username":
            self.logger.debug(f"[JWTAuth] Remapping claim 'username' -> '{JWT_CLAIM_USERNAME}'")
            to_encode[JWT_CLAIM_USERNAME] = to_encode.pop("username")
        if not expire_minutes:
            expire_minutes = TOKEN_EXPIRE_MINUTES
        expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
        to_encode.update({"exp": expire})
        self.logger.debug(f"[JWTAuth] Encoding token with claims={list(to_encode.keys())}, expires={expire}, algorithm={JWT_TOKEN_ALGORITHM}")
        return jwt.encode(to_encode, self.__encode_key, algorithm=JWT_TOKEN_ALGORITHM)

    def decode_access_token(self, token: str) -> dict:
        """Decode a JWT access token.

        Maps configured claim names back to internal names ("id", "username")
        before returning, so the rest of the application is claim-name agnostic.
        """
        # Extract and log the JWT header to identify the signing key
        try:
            header = jwt.get_unverified_header(token)
            self.logger.info(f"[JWTAuth] decode_access_token: token header={header}, algorithm={JWT_TOKEN_ALGORITHM}")
        except Exception as e:
            self.logger.warning(f"[JWTAuth] decode_access_token: could not extract token header: {e}")

        self.logger.info(f"[JWTAuth] decode_access_token: attempting decode with algorithm={JWT_TOKEN_ALGORITHM}")
        print(f"[JWTAuth-DEBUG] About to call jwt.decode(), key type={type(self.__decode_key)}, key len={len(self.__decode_key) if self.__decode_key else 0}")
        try:
            decoded = jwt.decode(token, self.__decode_key, algorithms=[JWT_TOKEN_ALGORITHM])
            print(f"[JWTAuth-DEBUG] jwt.decode() returned successfully")
            self.logger.info(f"[JWTAuth] decode_access_token: successfully decoded, claims={list(decoded.keys())}")
        except jwt.ExpiredSignatureError:
            self.logger.warning(f"[JWTAuth] decode_access_token: token has expired")
            raise
        except jwt.InvalidTokenError as e:
            self.logger.error(f"[JWTAuth] decode_access_token: JWT validation FAILED - {type(e).__name__}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"[JWTAuth] decode_access_token: unexpected error during decode - {type(e).__name__}: {e}")
            raise

        self.logger.info(f"[JWTAuth] decode_access_token: raw decoded claims={list(decoded.keys())}")
        if JWT_CLAIM_USER_ID != "id":
            self.logger.info(f"[JWTAuth] Remapping claim '{JWT_CLAIM_USER_ID}' -> 'id' (present={JWT_CLAIM_USER_ID in decoded})")
            decoded["id"] = decoded.pop(JWT_CLAIM_USER_ID, None)
        if JWT_CLAIM_USERNAME != "username":
            self.logger.info(f"[JWTAuth] Remapping claim '{JWT_CLAIM_USERNAME}' -> 'username' (present={JWT_CLAIM_USERNAME in decoded})")
            decoded["username"] = decoded.pop(JWT_CLAIM_USERNAME, None)
        self.logger.info(f"[JWTAuth] decode_access_token: final claims={list(decoded.keys())}, id={decoded.get('id')}, username={decoded.get('username')}")
        return decoded

    def create_jwt_middleware(
        self,
        public: tuple = (),
        public_prefixes: tuple = (),
        public_suffixes: tuple = (),
    ) -> web.middleware:
        """Create middleware for JWT authentication."""

        @web.middleware
        async def jwt_middleware(request: web.Request, handler) -> web.Response:
            """Middleware to handle JWT authentication."""
            self.logger.info(f"[JWTAuth] {request.method} {request.path}")

            if (
                request.path in public
                or request.path.startswith(public_prefixes)
                or request.path.endswith(public_suffixes)
            ):
                self.logger.info(f"[JWTAuth] Path '{request.path}' is public, skipping auth")
                return await handler(request)

            # Log DB state for debugging
            db_users = self.users_db.users
            self.logger.info(f"[JWTAuth] DB has {len(db_users)} users: {list(db_users.keys())}")

            token = self.get_token_from_request(request)

            if not token:
                auth_header = request.headers.get("Authorization", "")
                self.logger.warning(
                    f"[JWTAuth] No token found for {request.method} {request.path} "
                    f"(Authorization header present: {bool(auth_header)}, "
                    f"jwt_token cookie present: {bool(request.cookies.get('jwt_token'))})"
                )
                return await handle_unauthorized_access(request, "/login")

            token_preview = token[:30] + "..." if len(token) > 30 else token
            self.logger.info(f"[JWTAuth] Token found (length={len(token)}, source={'header' if request.headers.get('Authorization') else 'cookie'}, preview={token_preview})")

            try:
                user = self.decode_access_token(token)
                user_id = user.get("id")
                username = user.get("username")
                self.logger.info(f"[JWTAuth] Token decoded: user_id={user_id}, username={username}")

                db_user = self.users_db.get_user(username)
                self.logger.info(f"[JWTAuth] DB lookup for username='{username}': result id={db_user[0]}, user_data keys={list(db_user[1].keys()) if db_user[1] else 'empty'}")

                if db_user[0] is None:
                    self.logger.error(
                        f"[JWTAuth] User '{username}' NOT FOUND in database! "
                        f"Token claims: id={user_id}, username={username}. "
                        f"Available users: {list(db_users.keys())}"
                    )
                    raise ValueError(
                        f"User with username: {username} is not in the database"
                    )

                if not user_id == db_user[0]:
                    self.logger.error(
                        f"[JWTAuth] User ID mismatch! "
                        f"Token id={user_id}, DB id={db_user[0]} "
                        f"for username={username}"
                    )
                    raise ValueError(
                        f"User with username: {username} is not in the database"
                    )

                request["user_id"] = user_id
                request["user"] = username

                set_fallback = (
                    request.path in ("/api/prompt", "/prompt")
                    or request.path.startswith("/api/assets")
                )
                self.access_control.set_current_user_id(user_id, set_fallback)
                self.logger.info(f"[JWTAuth] Auth success: user_id={user_id}, username={username}, path={request.path}")

            except jwt.ExpiredSignatureError:
                self.logger.warning(f"[JWTAuth] Token expired for {request.method} {request.path}")
                return await handle_unauthorized_access(
                    request, "/logout", message="Token has expired"
                )
            except jwt.InvalidTokenError as e:
                self.logger.error(f"[JWTAuth] Token invalid for {request.method} {request.path}: {type(e).__name__}: {e}")
                return await handle_unauthorized_access(
                    request, "/logout", message="Token is invalid"
                )
            except Exception as e:
                self.logger.error(f"[JWTAuth] Unexpected error during auth for {request.method} {request.path}: {type(e).__name__}: {e}")
                return await handle_unauthorized_access(
                    request, "/logout", message="Unexpected error"
                )

            return await handler(request)

        async def handle_unauthorized_access(
            request: web.Request,
            redirect_path: str,
            message: str = "Authentication required",
        ) -> web.Response:
            """Handle unauthorized access cases."""
            accept_header = request.headers.get("Accept", "")
            if "text/html" in accept_header:
                return web.HTTPFound(redirect_path)
            else:
                return web.json_response({"error": message}, status=401)

        return jwt_middleware
