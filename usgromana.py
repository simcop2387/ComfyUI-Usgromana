import os
import json
import jwt
import uuid
from aiohttp import web
from server import PromptServer
from .utils import *
from .utils import watcher
from .utils import ip_filter as ip_filter_module
from .utils import user_env

# --- Init & Globals ---
instance = PromptServer.instance
app = instance.app
routes = instance.routes

logger = Logger(LOG_FILE, LOG_LEVELS)
sanitizer = Sanitizer()
ip_filter = IPFilter(WHITELIST, BLACKLIST)
timeout = Timeout(ip_filter, BLACKLIST_AFTER_ATTEMPTS)
users_db = UsersDB(USERS_FILE)
access_control = AccessControl(users_db, instance)
jwt_auth = JWTAuth(
    users_db, access_control, logger, SECRET_KEY, TOKEN_EXPIRE_MINUTES, TOKEN_ALGORITHM
)


def _load_json_file(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[Usgromana] Error reading {path}: {e}")
        return default if default is not None else {}

def _save_json_file(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.error(f"[Usgromana] Error saving {path}: {e}")

# --- Default Group Config (external file) ---

DEFAULT_GROUP_CONFIG_PATH = os.path.join(
    os.path.dirname(USERS_FILE),
    "defaults",
    "default_group_config.json"
)

def _load_default_groups():
    cfg = _load_json_file(DEFAULT_GROUP_CONFIG_PATH, None)
    if cfg is None:
        logger.error("[Usgromana] Missing default_group_config.json; using built-in fallback!")
        return {
            "admin": {
                "can_run": True,
                "can_upload": True,
                "can_access_manager": True,
                "can_access_api": True,
                "can_see_restricted_settings": True,
            },
            "power": {
                "can_run": True,
                "can_upload": True,
                "can_access_manager": True,
                "can_access_api": True,
                "can_see_restricted_settings": False,
            },
            "user": {
                "can_run": True,
                "can_upload": True,
                "can_access_manager": False,
                "can_access_api": True,
                "can_see_restricted_settings": False,
            },
            "guest": {
                "can_run": False,
                "can_upload": False,
                "can_access_manager": False,
                "can_access_api": True,
                "can_see_restricted_settings": False,
            },
        }
    return cfg

DEFAULT_GROUP_CONFIG = _load_default_groups()

# Where to store the *live* groups config
GROUPS_CONFIG_FILE = os.path.join(
    os.path.dirname(USERS_FILE),
    "usgromana_groups.json",
)

def _ensure_groups_config():
    default_cfg = _load_default_groups()
    current = _load_json_file(GROUPS_CONFIG_FILE, {})

    changed = False

    # Add missing groups
    for role, perms in default_cfg.items():
        if role not in current:
            current[role] = perms
            changed = True

    # Add missing permission keys for existing groups
    for role, perms in default_cfg.items():
        for key, value in perms.items():
            if key not in current[role]:
                current[role][key] = value
                changed = True

    if changed:
        _save_json_file(GROUPS_CONFIG_FILE, current)

_ensure_groups_config()

def _ensure_guest_user():
    """
    Make sure a 'guest' user exists in the user DB and is assigned to the 'guest' group.
    This is only meant to run when bootstrapping the system (first admin creation).
    """
    try:
        guest_id, guest_rec = users_db.get_user("guest")
    except Exception as e:
        logger.error(f"[Usgromana] Error checking guest user: {e}")
        return

    if guest_id is not None:
        # Guest exists; just make sure group/admin flags are sensible
        _patch_user_group("guest", ["guest"], False)
        return

    # Create a new guest user with a random password (never actually used)
    try:
        random_password = str(uuid.uuid4())
        new_guest_id = str(uuid.uuid4())
        users_db.add_user(new_guest_id, "guest", random_password, False)
        _patch_user_group("guest", ["guest"], False)
        logger.info("[Usgromana] Created default 'guest' user")
    except Exception as e:
        logger.error(f"[Usgromana] Error creating guest user: {e}")

def _patch_user_group(username, group_list, is_admin_bool):
    raw = _load_json_file(USERS_FILE, {})
    users_data = raw.get("users", raw) if isinstance(raw, dict) else raw
    
    # Handle list or dict user db
    target_rec = None
    target_key = None
    
    iterator = users_data.items() if isinstance(users_data, dict) else enumerate(users_data)
    for k, u in iterator:
        if u.get("username") == username or u.get("user") == username:
            target_rec = u
            target_key = k
            break
                
    if target_rec:
        target_rec["groups"] = [g.lower() for g in group_list]
        target_rec["admin"] = is_admin_bool
        
        if isinstance(users_data, list): users_data[target_key] = target_rec
        else: users_data[target_key] = target_rec
        
        if isinstance(raw, dict) and "users" in raw: raw["users"] = users_data
        else: raw = users_data
            
        _save_json_file(USERS_FILE, raw)
        return True
    return False

# --- Routes (API) ---

@routes.get("/usgromana/api/me")
async def api_me(request):
    # Quick dirty check via AccessControl helper if needed, or re-implement simple extraction
    # Since middleware runs before this, we are safe, but we need data for UI
    token = jwt_auth.get_token_from_request(request)
    if not token: return web.json_response({"role": "guest", "is_admin": False})
    
    try:
        payload = jwt_auth.decode_access_token(token)
        username = payload.get("username")
        _, rec = users_db.get_user(username)
        
        groups = [g.lower() for g in rec.get("groups", [])] if rec else ["guest"]
        role = groups[0] if groups else "guest"
        is_admin = "admin" in groups or rec.get("admin") is True
        
        return web.json_response({
            "username": username,
            "role": role,
            "groups": groups,
            "is_admin": is_admin
        })
    except:
        return web.json_response({"role": "guest", "is_admin": False})

@routes.get("/usgromana/api/groups")
async def api_groups(request):
    return web.json_response({"groups": _load_json_file(GROUPS_CONFIG_FILE, DEFAULT_GROUP_CONFIG)})

@routes.put("/usgromana/api/groups")
async def api_update_groups(request):
    # Permission check is handled by middleware but explicit check is good
    token = jwt_auth.get_token_from_request(request)
    # ... verify admin ...
    
    try:
        data = await request.json()
        new_groups = data.get("groups", {})
        current = _load_json_file(GROUPS_CONFIG_FILE, DEFAULT_GROUP_CONFIG)
        
        for g, perms in new_groups.items():
            g_lower = g.lower()
            if g_lower not in current: current[g_lower] = {}
            for k, v in perms.items():
                current[g_lower][k] = bool(v)
                
        _save_json_file(GROUPS_CONFIG_FILE, current)
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)

@routes.get("/usgromana/api/users")
async def api_users(request):
    raw = _load_json_file(USERS_FILE, {})
    users_list = []
    iterable = raw.get("users", raw).values() if isinstance(raw.get("users", raw), dict) else raw.get("users", raw)
    for u in iterable:
        users_list.append({
            "username": u.get("username", "unknown"),
            "groups": [g.lower() for g in u.get("groups", ["user"])],
            "is_admin": u.get("admin", False)
        })
    return web.json_response({"users": users_list})

@routes.put("/usgromana/api/users/{target_user}")
async def api_update_user_route(request):
    target = request.match_info["target_user"]
    data = await request.json()
    groups = [g.lower() for g in data.get("groups", [])]
    is_admin_flag = "admin" in groups
    success = _patch_user_group(target, groups, is_admin_flag)
    if success: return web.json_response({"status": "ok"})
    return web.Response(status=404)

# --- Standard Auth Routes (Login/Register/Logout) remain same as before ---

@routes.get("/register")
async def get_register(request: web.Request) -> web.Response:
    with open(os.path.join(HTML_DIR, "register.html"), "r") as f:
        html_content = f.read()

    if not users_db.load_users():
        # no users yet → first-time bootstrap; frontend shows "admin" mode
        html_content = html_content.replace("{{ X-Admin-User }}", "true")
    else:
        html_content = html_content.replace("{{ X-Admin-User }}", "false")

    return web.Response(body=html_content, content_type="text/html")


@routes.post("/register")
async def post_register(request: web.Request) -> web.Response:
    sanitized_data = request.get("_sanitized_data", {})
    ip = get_ip(request)
    new_user_username = sanitized_data.get("new_user_username")
    new_user_password = sanitized_data.get("new_user_password")
    username = sanitized_data.get("username")
    password = sanitized_data.get("password")

    username_valid, username_invalid_message = validate_username(new_user_username)
    if not username_valid:
        return web.json_response({"error": username_invalid_message}, status=400)

    password_valid, password_invalid_message = validate_password(new_user_password)
    if not password_valid:
        return web.json_response({"error": password_invalid_message}, status=400)

    admin_user = users_db.get_admin_user()
    admin_user_id = None

    if admin_user[0] and (not new_user_username or not new_user_password):
        return web.json_response(
            {"error": "Missing new user registration details"}, status=400
        )

    if admin_user[0]:
        if not username or not password:
            return web.json_response(
                {"error": "Missing admin user authentication details"}, status=400
            )

        admin_user_id = admin_user[0]

        if admin_user_id is not None:
            if not (
                users_db.get_user(username)[0] == admin_user_id
                and users_db.check_username_password(username, password)
            ):
                logger.registration_attempt(
                    ip, username, password, new_user_username, new_user_password
                )
                timeout.add_failed_attempt(ip)
                return web.json_response(
                    {"message": "Invalid username or password"}, status=403
                )

    if None not in users_db.get_user(new_user_username):
        return web.json_response({"error": "Username already exists"}, status=400)

    # True if this is the very first user (bootstrap admin)
    is_first_admin = not bool(admin_user_id)

    users_db.add_user(
        str(uuid.uuid4()),
        new_user_username,
        new_user_password,
        is_first_admin,
    )

    # If we just created the first admin, also make sure 'guest' exists
    if is_first_admin:
        _ensure_groups_config()   # makes sure usgromana_groups.json exists
        _ensure_guest_user()      # creates/patches 'guest' user + group

    logger.registration_success(
        ip, new_user_username, username if admin_user_id is not None else None
    )
    timeout.remove_failed_attempts(ip)
    return web.json_response({"message": "User registered successfully"})


@routes.get("/login")
async def get_login(request: web.Request) -> web.Response:
    if not users_db.load_users():
        return web.HTTPFound("/register")

    token = jwt_auth.get_token_from_request(request)
    if token:
        return web.HTTPFound("/logout")
    return web.FileResponse(os.path.join(HTML_DIR, "login.html"))


@routes.post("/login")
async def post_login(request: web.Request) -> web.Response:
    sanitized_data = request.get("_sanitized_data", {})
    ip = get_ip(request)
    
    # --- NEW: detect guest login flag from the hidden input ---
    guest_login_flag = str(sanitized_data.get("guest_login", "false")).lower() == "true"

    # ===================== GUEST LOGIN PATH ======================
    if guest_login_flag:
        # Make sure guest user exists + is in the guest group
        _ensure_guest_user()

        guest_id, guest_rec = users_db.get_user("guest")
        if guest_id is None or guest_rec is None:
            logger.error("[Usgromana] Guest login requested but 'guest' user not found")
            timeout.add_failed_attempt(ip)
            return web.json_response(
                {"error": "Guest login is not available"}, status=500
            )

        # You *could* check a 'disabled' flag here if your UsersDB supports it

        token = jwt_auth.create_access_token(
            {"id": guest_id, "username": "guest"}
        )

        response = web.json_response(
            {
                "message": "Guest login successful",
                "jwt_token": token,
            }
        )

        secure_flag = request.headers.get("X-Forwarded-Proto", "http") == "https"
        response.set_cookie(
            "jwt_token", token, httponly=True, secure=secure_flag, samesite="Strict"
        )

        logger.login_success(ip, "guest")
        timeout.remove_failed_attempts(ip)
        return response


    username = sanitized_data.get("username")
    password = sanitized_data.get("password")

    if not username or not password:
        return web.json_response(
            {"error": "Missing login credentials (username and password)"}, status=400
        )

    if users_db.check_username_password(username, password):
        timeout.remove_failed_attempts(ip)

        user_id, _ = users_db.get_user(username)
        token = jwt_auth.create_access_token({"id": user_id, "username": username})
        response = web.json_response(
            {
                "message": "Login successful",
                "jwt_token": token,
                # "user_settings_id": next((key for key, value in instance.user_manager.users.items() if value == username), ""),
            }
        )
        secure_flag = request.headers.get("X-Forwarded-Proto", "http") == "https"
        response.set_cookie(
            "jwt_token", token, httponly=True, secure=secure_flag, samesite="Strict"
        )
        logger.login_success(ip, username)
        return response

    logger.login_attempt(ip, username, password)
    timeout.add_failed_attempt(ip)
    return web.json_response({"error": "Invalid username or password"}, status=401)


@routes.get("/generate_token")
async def get_generate_token(request: web.Request) -> web.Response:
    if not users_db.load_users():
        return web.HTTPFound("/register")

    token = jwt_auth.get_token_from_request(request)
    if token:
        return web.HTTPFound("/logout")
    return web.FileResponse(os.path.join(HTML_DIR, "generate_token.html"))


@routes.post("/generate_token")
async def post_generate_token(request: web.Request) -> web.Response:
    sanitized_data = request.get("_sanitized_data", {})
    ip = get_ip(request)
    username = sanitized_data.get("username")
    password = sanitized_data.get("password")

    try:
        expire_hours = int(
            sanitized_data.get("expire_hours", TOKEN_EXPIRE_MINUTES / 60)
        )

    except ValueError:
        return web.json_response(
            {"error": "Expiration hours must be a number"},
            status=400,
        )

    if expire_hours > MAX_TOKEN_EXPIRE_MINUTES / 60:
        return web.json_response(
            {
                "error": f"Expiration hours must be smaller than {MAX_TOKEN_EXPIRE_MINUTES / 60}"
            },
            status=400,
        )

    if not username or not password:
        return web.json_response(
            {"error": "Missing login credentials (username and password)"}, status=400
        )

    if users_db.check_username_password(username, password):
        timeout.remove_failed_attempts(ip)

        user_id, _ = users_db.get_user(username)
        token = jwt_auth.create_access_token(
            {"id": user_id, "username": username}, expire_minutes=(expire_hours * 60)
        )
        response = web.json_response(
            {
                "message": "JWT Token successfully generated",
                "jwt_token": token,
            }
        )
        secure_flag = request.headers.get("X-Forwarded-Proto", "http") == "https"
        response.set_cookie(
            "jwt_token", token, httponly=True, secure=secure_flag, samesite="Strict"
        )

        logger.generate_success(ip, username, expire_hours)

        return response

    logger.generate_attempt(ip, username, password, expire_hours)
    timeout.add_failed_attempt(ip)
    return web.json_response({"error": "Invalid username or password"}, status=401)


@routes.get("/logout")
async def get_logout(request: web.Request) -> web.Response:
    ip = get_ip(request)
    free_memory = request.query.get("free_memory", "false").lower() == "true"
    unload_models = request.query.get("unload_models", "false").lower() == "true"

    token = jwt_auth.get_token_from_request(request)
    if token and FREE_MEMORY_ON_LOGOUT:
        try:
            username = jwt_auth.decode_access_token(token).get("username")
            if free_memory or unload_models:
                if hasattr(instance, "post_free"):
                    json_data = {
                        "unload_models": unload_models,
                        "free_memory": free_memory,
                    }
                    mock_request = web.Request(
                        app=app,
                        method="POST",
                        path="/free",
                        headers={},
                        match_info={},
                        payload=None,
                    )
                    mock_request._post = json_data
                    await instance.post_free(mock_request)
                    logger.memory_free(ip, username, free_memory, unload_models)

            logger.logout(ip, username)
        except jwt.ExpiredSignatureError:
            pass
        except jwt.InvalidTokenError:
            pass
        except Exception as e:
            logger.error(f"Unexpected error during logout: {e}")

    response = web.HTTPFound("/login")
    response.del_cookie("jwt_token", path="/")

    return response

@routes.get("/usgromana/api/ip-lists")
async def api_ip_lists(request: web.Request) -> web.Response:
    """
    Return current whitelist / blacklist as JSON arrays of strings.
    Uses the same list files as IPFilter middleware.
    """
    # Force reload from disk so UI always sees the latest file contents
    whitelist, blacklist = ip_filter.load_filter_list()

    wl = [str(ip) for ip in (whitelist or [])]
    bl = [str(ip) for ip in (blacklist or [])]

    return web.json_response({
        "whitelist": wl,
        "blacklist": bl,
    })


@routes.put("/usgromana/api/ip-lists")
async def api_update_ip_lists(request: web.Request) -> web.Response:
    """
    Overwrite whitelist / blacklist files from JSON arrays.
    Only admins should be allowed to do this.
    """
    token = jwt_auth.get_token_from_request(request)
    if not token:
        return web.json_response({"error": "Not authenticated"}, status=401)

    try:
        payload = jwt_auth.decode_access_token(token)
        username = payload.get("username")
        _, rec = users_db.get_user(username)
        groups = [g.lower() for g in rec.get("groups", [])] if rec else []
        is_admin = "admin" in groups or rec.get("admin") is True
        if not is_admin:
            return web.json_response({"error": "Admin only"}, status=403)
    except Exception:
        return web.json_response({"error": "Invalid token"}, status=401)

    try:
        data = await request.json()
        wl = data.get("whitelist") or []
        bl = data.get("blacklist") or []

        # Normalize to plain strings and strip empties
        wl = [str(x).strip() for x in wl if str(x).strip()]
        bl = [str(x).strip() for x in bl if str(x).strip()]

        # Overwrite files used by IPFilter
        # WHITELIST / BLACKLIST should already exist via your utils config
        with open(WHITELIST, "w", encoding="utf-8") as f:
            if wl:
                f.write("\n".join(wl) + "\n")

        with open(BLACKLIST, "w", encoding="utf-8") as f:
            if bl:
                f.write("\n".join(bl) + "\n")

        # Refresh in-memory lists
        ip_filter.load_filter_list()

        return web.json_response({"status": "ok"})
    except Exception as e:
        logger.error(f"[Usgromana] Error updating IP lists: {e}")
        return web.json_response({"error": str(e)}, status=500)

@routes.post("/usgromana/api/user-env")
async def api_user_env(request: web.Request) -> web.Response:
    """
    Management API for per-user environment folders (user_env.py).

    Expected JSON:
      { "action": "status" | "list" | "purge" | "set_gallery_root",
        "user": "<username>",
        ... }
    """
    token = jwt_auth.get_token_from_request(request)
    if not token:
        return web.json_response({"error": "Not authenticated"}, status=401)

    try:
        payload = jwt_auth.decode_access_token(token)
        current_username = payload.get("username")
        _, rec = users_db.get_user(current_username)
        groups = [g.lower() for g in rec.get("groups", [])] if rec else []
        is_admin = "admin" in groups or rec.get("admin") is True
    except Exception:
        return web.json_response({"error": "Invalid token"}, status=401)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    action = (data.get("action") or "").strip().lower()
    target_user = (data.get("user") or "").strip()

    if not target_user:
        return web.json_response({"error": "Missing 'user' field"}, status=400)

    # ----- STATUS -----
    if action == "status":
        files = user_env.list_user_files(target_user, max_files=200)
        gallery_root_user = user_env.get_gallery_root_user()
        is_gallery_root = (gallery_root_user == target_user)

        return web.json_response({
            "user": target_user,
            "is_gallery_root": is_gallery_root,
            "files": files,
            "message": f"Status for user '{target_user}'. "
                       f"Gallery root: {'yes' if is_gallery_root else 'no'}."
        })

    # Everything below here should be admin-only (destructive / global)
    if not is_admin:
        return web.json_response({"error": "Admin only"}, status=403)

    # ----- LIST FILES -----
    if action == "list":
        files = user_env.list_user_files(target_user, max_files=1000)
        return web.json_response({
            "user": target_user,
            "files": files,
        })

    # ----- PURGE -----
    if action == "purge":
        user_env.purge_user_root(target_user)
        return web.json_response({
            "user": target_user,
            "message": f"Purged environment folders for '{target_user}'."
        })

    # ----- SET GALLERY ROOT -----
    if action == "set_gallery_root":
        enable = bool(data.get("enable"))
        if enable:
            user_env.set_gallery_root_user(target_user)
            msg = f"Gallery root set to user '{target_user}'."
        else:
            # Only clear if this user is currently the root
            if user_env.get_gallery_root_user() == target_user:
                user_env.set_gallery_root_user(None)
                msg = f"Gallery root cleared from '{target_user}'."
            else:
                msg = f"User '{target_user}' was not the gallery root; no change."
        return web.json_response({
            "user": target_user,
            "enable": enable,
            "message": msg,
        })

    return web.json_response({"error": f"Unknown action '{action}'"}, status=400)

# --- Init App ---

app.add_routes([
    web.static("/usgromana/css", CSS_DIR),
    web.static("/usgromana/js", JS_DIR),
    web.static("/usgromana/assets", ASSETS_DIR),
])

if FORCE_HTTPS: app.middlewares.append(create_https_middleware(MATCH_HEADERS))
app.middlewares.append(ip_filter.create_ip_filter_middleware())
app.middlewares.append(sanitizer.create_sanitizer_middleware())
app.middlewares.append(timeout.create_time_out_middleware(limited=("/login", "/register")))
app.middlewares.append(jwt_auth.create_jwt_middleware(public=("/login", "/logout", "/register"), public_prefixes=("/usgromana", "/assets")))

if SEPERATE_USERS:
    app.middlewares.append(access_control.create_folder_access_control_middleware())
    access_control.patch_folder_paths()
    access_control.patch_prompt_queue()

# REGISTER THE NEW UNIFIED MIDDLEWARE
app.middlewares.append(access_control.create_usgromana_middleware())

# NEW: register watcher AFTER access_control so it can see its 403 responses
watcher.register(app)