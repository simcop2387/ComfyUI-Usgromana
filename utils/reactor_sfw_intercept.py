# utils/reactor_sfw_intercept.py
#
# Per-user Reactor SFW bypass:
# - Dynamically loads comfyui-reactor/scripts/reactor_sfw.py from disk
# - Monkey-patches nsfw_image()
# - Reads sfw_check from users_db using current_username_var
# - Never crashes the extension if Reactor is missing

import importlib.util
import os

from ..globals import users_db, current_username_var  # <-- you were missing this


def _load_reactor_module():
    try:
        # This file: .../custom_nodes/ComfyUI-Usgromana/utils/reactor_sfw_intercept.py
        # base -> .../custom_nodes/ComfyUI-Usgromana
        base = os.path.dirname(os.path.dirname(__file__))

        # One level up -> .../custom_nodes
        # then comfyui-reactor/scripts/reactor_sfw.py
        reactor_path = os.path.join(
            base, "..", "comfyui-reactor", "scripts", "reactor_sfw.py"
        )
        reactor_path = os.path.abspath(reactor_path)

        if not os.path.exists(reactor_path):
            print("[Usgromana] Reactor SFW script not found at:", reactor_path)
            return None

        spec = importlib.util.spec_from_file_location("reactor_sfw", reactor_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    except Exception as e:
        print("[Usgromana] Failed to load reactor_sfw:", e)
        return None


def _apply_patch():
    reactor_sfw_mod = _load_reactor_module()
    if reactor_sfw_mod is None:
        print("[Usgromana] Reactor not found; SFW intercept is disabled.")
        return

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
