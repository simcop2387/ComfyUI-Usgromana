# --- START OF FILE routes/user.py ---
from aiohttp import web
from ..globals import routes, jwt_auth, users_db
from ..utils import user_env


# ------------------------------------------------------------------
# /usgromana/api/me  ->  current user info for the UI
# ------------------------------------------------------------------
@routes.get("/usgromana/api/me")
async def api_me(request: web.Request) -> web.Response:
    """
    Return minimal user info for the frontend:

    {
      "username": "jdallen",
      "role": "admin" | "power" | "user" | "guest",
      "groups": ["admin", "something_else"],
      "is_admin": true/false
    }
    """
    token = jwt_auth.get_token_from_request(request)
    if not token:
        # anonymous / no token = guest
        return web.json_response({
            "username": None,
            "role": "guest",
            "groups": ["guest"],
            "is_admin": False,
        })

    try:
        payload = jwt_auth.decode_access_token(token)
        username = payload.get("username")
        if not username:
            raise ValueError("Missing username in token")

        _, rec = users_db.get_user(username)
        if not rec:
            # Known token but no DB entry → treat as guest-ish
            return web.json_response({
                "username": username,
                "role": "guest",
                "groups": ["guest"],
                "is_admin": False,
            })

        groups = [g.lower() for g in rec.get("groups", [])]

        # Determine primary role in priority order
        role = "guest"
        for candidate in ["admin", "power", "user", "guest"]:
            if candidate in groups:
                role = candidate
                break

        is_admin = bool(rec.get("admin") or ("admin" in groups))

        return web.json_response({
            "username": username,
            "role": role,
            "groups": groups,
            "is_admin": is_admin,
        })

    except Exception as e:
        print(f"[usgromana] /usgromana/api/me error: {e}")
        return web.json_response({
            "username": None,
            "role": "guest",
            "groups": ["guest"],
            "is_admin": False,
        })


# ------------------------------------------------------------------
# /usgromana/api/user-env  ->  per-user environment operations
# ------------------------------------------------------------------
@routes.post("/usgromana/api/user-env")
async def api_user_env(request: web.Request) -> web.Response:
    """
    Handle per-user environment actions used by the admin panel:

    POST body:
      { "action": "status" | "list" | "purge" | "set_gallery_root",
        "user": "<username>",
        "enable": true/false   # only for set_gallery_root
      }
    """
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    action = data.get("action")
    target_user = (data.get("user") or "").strip()

    if not target_user:
        return web.json_response({"error": "Missing 'user'"}, status=400)

    # ---- STATUS ---------------------------------------------------
    if action == "status":
        files = user_env.list_user_files(target_user, max_files=200)
        gallery_root_user = user_env.get_gallery_root_user()
        is_root = gallery_root_user == target_user

        msg = f"User '{target_user}' has {len(files)} files under their environment folder."
        if is_root:
            msg += " This user is currently configured as the Gallery root."

        return web.json_response({
            "user": target_user,
            "files": files,
            "is_gallery_root": is_root,
            "message": msg,
        })

    # ---- LIST FILES ----------------------------------------------
    if action == "list":
        files = user_env.list_user_files(target_user, max_files=2000)
        return web.json_response({
            "user": target_user,
            "files": files,
        })

    # ---- PURGE USER ENV ROOT -------------------------------------
    if action == "purge":
        user_env.purge_user_root(target_user)
        msg = f"Purged environment folders for user '{target_user}'."
        return web.json_response({
            "user": target_user,
            "message": msg,
        })

    # ---- SET / CLEAR GALLERY ROOT --------------------------------
    if action == "set_gallery_root":
        enable = bool(data.get("enable"))

        if enable:
            user_env.set_gallery_root_user(target_user)
            msg = f"Gallery root set to user '{target_user}'."
            is_root = True
        else:
            # Clear the gallery root entirely
            user_env.set_gallery_root_user(None)
            msg = "Gallery root cleared."
            is_root = False

        return web.json_response({
            "user": target_user,
            "message": msg,
            "is_gallery_root": is_root,
        })

    # ---- UNKNOWN ACTION ------------------------------------------
    return web.json_response(
        {"error": f"Unknown action '{action}'"},
        status=400,
    )
