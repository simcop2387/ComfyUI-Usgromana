# utils/reactor_sfw_intercept.py
#
# Safe, optional hook for Reactor's SFW filter.
# - If Reactor is installed and reactor_sfw is importable, we monkey-patch nsfw_image.
# - If not, we just log and do nothing (extension still loads).

import importlib

from ..globals import users_db, current_username_var


def _try_import_reactor_module():
    """
    Try several likely import paths for Reactor's reactor_sfw module.
    Return the module object or None if not found.
    """
    module = None

    # 1) Preferred: comfyui_reactor.scripts.reactor_sfw
    try:
        module = importlib.import_module("comfyui_reactor.scripts.reactor_sfw")
        return module
    except ModuleNotFoundError:
        pass
    except Exception as e:
        print(f"[Usgromana] Error importing comfyui_reactor.scripts.reactor_sfw: {e}")

    # 2) Fallback: reactor_sfw directly (some setups add scripts/ to sys.path)
    try:
        module = importlib.import_module("reactor_sfw")
        return module
    except ModuleNotFoundError:
        pass
    except Exception as e:
        print(f"[Usgromana] Error importing reactor_sfw: {e}")

    # If we get here, Reactor isn't importable in this environment
    return None


def _apply_patch():
    reactor_sfw_mod = _try_import_reactor_module()
    if reactor_sfw_mod is None:
        print("[Usgromana] Reactor not found; SFW intercept is disabled.")
        return

    # Make sure the attribute exists
    if not hasattr(reactor_sfw_mod, "nsfw_image"):
        print("[Usgromana] reactor_sfw.nsfw_image not found; cannot patch.")
        return

    original_nsfw_image = reactor_sfw_mod.nsfw_image

    def nsfw_image_patched(img_data, model_path: str):
        """
        Wrapper around Reactor's nsfw_image().
        If the current user has sfw_check == False, we bypass detection
        and always return False ("not NSFW").
        Otherwise, call the original implementation.
        """
        username = None
        try:
            username = current_username_var.get(None)
        except LookupError:
            username = None

        if username:
            _, rec = users_db.get_user(username)
            if rec and rec.get("sfw_check", True) is False:
                # SFW disabled for this user → pretend everything is safe
                return False

        # Default behavior: let Reactor do its thing
        return original_nsfw_image(img_data, model_path)

    reactor_sfw_mod.nsfw_image = nsfw_image_patched
    print("[Usgromana] Reactor SFW intercept installed successfully.")


# Run the patch at import time, but never crash the extension if it fails.
try:
    _apply_patch()
except Exception as e:
    print(f"[Usgromana] Unexpected error while applying Reactor SFW intercept: {e}")
