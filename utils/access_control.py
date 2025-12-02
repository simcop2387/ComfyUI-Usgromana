import os
import heapq
import copy
import contextvars
from aiohttp import web

import folder_paths
from server import PromptServer
from execution import PromptQueue, MAXIMUM_HISTORY_SIZE

from .users_db import UsersDB


class AccessControl:
    def __init__(self, users_db: UsersDB, server: PromptServer):
        self.users_db = users_db
        self.server = server

        self._current_user = contextvars.ContextVar("user_id", default=None)
        self.__current_user_id = None

        self.__get_output_directory = folder_paths.get_output_directory
        self.__get_temp_directory = folder_paths.get_temp_directory
        self.__get_input_directory = folder_paths.get_input_directory

        self.__prompt_queue = self.server.prompt_queue
        self.__prompt_queue_put = self.__prompt_queue.put

    # ---------------------------------------------------------
    # USER CONTEXT
    # ---------------------------------------------------------

    def set_current_user_id(self, user_id: str, set_fallback=False):
        self._current_user.set(user_id)
        if set_fallback:
            self.__current_user_id = user_id

    def get_current_user_id(self):
        return self._current_user.get() or self.__current_user_id

    # ---------------------------------------------------------
    # USER FOLDERS
    # ---------------------------------------------------------

    def get_user_output_directory(self):
        return os.path.join(self.__get_output_directory(), self.get_current_user_id() or "public")

    def get_user_temp_directory(self):
        return os.path.join(self.__get_temp_directory(), self.get_current_user_id() or "public")

    def get_user_input_directory(self):
        directory = os.path.join(self.__get_input_directory(), self.get_current_user_id() or "public")
        os.makedirs(directory, exist_ok=True)
        return directory

    def add_user_specific_folder_paths(self, json_data):
        user_id = self.get_current_user_id() or "public"

        if isinstance(json_data, dict):
            for k, v in json_data.items():
                if k == "filename_prefix":
                    json_data[k] = f"{user_id}/{v}"
                else:
                    self.add_user_specific_folder_paths(v)

        elif isinstance(json_data, list):
            for item in json_data:
                self.add_user_specific_folder_paths(item)

        return json_data

    def patch_folder_paths(self):
        folder_paths.get_temp_directory = self.get_user_temp_directory
        folder_paths.get_input_directory = self.get_user_input_directory

        self.server.add_on_prompt_handler(self.add_user_specific_folder_paths)

    # ---------------------------------------------------------
    # FOLDER ACCESS CONTROL
    # ---------------------------------------------------------

    def create_folder_access_control_middleware(self, folder_paths=()):
        folder_paths = folder_paths or (
            self.__get_output_directory(),
            self.__get_temp_directory(),
            self.__get_input_directory(),
        )

        @web.middleware
        async def folder_access_control_middleware(request: web.Request, handler):
            if not request.path.startswith(folder_paths):
                return await handler(request)

            user_id = request.get("user_id")
            user_id, user = self.users_db.get_user(user_id)

            try:
                parts = request.path.strip("/").split("/")
                folder_user = parts[1]
            except:
                return web.HTTPNotFound()

            if folder_user == "public":
                return await handler(request)

            if not user_id or not user or (folder_user != user_id and not user.get("admin")):
                return web.HTTPForbidden(reason="Access denied.")

            return await handler(request)

        return folder_access_control_middleware

    # ---------------------------------------------------------
    # QUEUE PATCHING (CRITICAL SECTION)
    # ---------------------------------------------------------

    def user_queue_put(self, item):
        """
        Preserve ComfyUI queue tuple structure.
        Attach user_id safely without mutating expected format.
        """
        if isinstance(item, tuple):
            new_item = (*item, {"user_id": self.get_current_user_id()})
        else:
            new_item = (item, {"user_id": self.get_current_user_id()})

        self.__prompt_queue_put(new_item)

    def user_queue_get(self, timeout=None):
        with self.__prompt_queue.not_empty:
            while not self.__prompt_queue.queue:
                self.__prompt_queue.not_empty.wait(timeout=timeout)
                if timeout and not self.__prompt_queue.queue:
                    return None

            entry = heapq.heappop(self.__prompt_queue.queue)

            task_id = self.__prompt_queue.task_counter
            self.__prompt_queue.currently_running[task_id] = entry
            self.__prompt_queue.task_counter += 1

            self.server.queue_updated()
            return (entry, task_id)

    def user_queue_task_done(self, item_id, history_result, **kwargs):
        with self.__prompt_queue.mutex:
            item = self.__prompt_queue.currently_running.pop(item_id)

            while len(self.__prompt_queue.history) > MAXIMUM_HISTORY_SIZE:
                self.__prompt_queue.history.pop(next(iter(self.__prompt_queue.history)))

            prompt_tuple = item[:-1] if isinstance(item[-1], dict) else item
            meta = item[-1] if isinstance(item[-1], dict) else {}

            self.__prompt_queue.history[prompt_tuple[1]] = {
                "prompt": prompt_tuple,
                "outputs": {},
                "status": {
                    "completed": kwargs.get("completed"),
                    "messages": kwargs.get("messages"),
                },
                "user_id": meta.get("user_id"),
            }

            if history_result:
                self.__prompt_queue.history[prompt_tuple[1]].update(history_result)

            self.server.queue_updated()

    def user_queue_get_current_queue(self):
        """
        Provide queue format exactly as ComfyUI expects:
        - list of tuples
        - no dict slicing
        - strip Sentinel metadata before returning
        """

        def unwrap(entry):
            if isinstance(entry, tuple) and isinstance(entry[-1], dict):
                return entry[:-1]
            return entry

        current_user = self.get_current_user_id()

        with self.__prompt_queue.mutex:
            running = []
            pending = []

            for item in self.__prompt_queue.currently_running.values():
                meta = item[-1] if isinstance(item[-1], dict) else None
                if not meta or meta.get("user_id") != current_user:
                    continue
                running.append(unwrap(item))

            for item in self.__prompt_queue.queue:
                meta = item[-1] if isinstance(item[-1], dict) else None
                if not meta or meta.get("user_id") != current_user:
                    continue
                pending.append(unwrap(item))

            return (running, copy.deepcopy(pending))

    def user_queue_wipe_queue(self):
        with self.__prompt_queue.mutex:
            current_user = self.get_current_user_id()
            self.__prompt_queue.queue = [
                i for i in self.__prompt_queue.queue
                if not (isinstance(i[-1], dict) and i[-1].get("user_id") == current_user)
            ]
            self.server.queue_updated()

    def user_queue_delete_queue_item(self, func):
        with self.__prompt_queue.mutex:
            for i, item in enumerate(self.__prompt_queue.queue):
                meta = item[-1] if isinstance(item[-1], dict) else None
                if meta and meta.get("user_id") == self.get_current_user_id() and func(unwrap(item)):
                    self.__prompt_queue.queue.pop(i)
                    heapq.heapify(self.__prompt_queue.queue)
                    self.server.queue_updated()
                    return True
        return False

    def user_queue_get_history(self, prompt_id=None, max_items=None, offset=-1):
        with self.__prompt_queue.mutex:
            user = self.get_current_user_id()

            filtered = {k: v for k, v in self.__prompt_queue.history.items() if v.get("user_id") == user}

            if prompt_id:
                return {prompt_id: filtered.get(prompt_id)} if prompt_id in filtered else {}

            keys = list(filtered.keys())
            if offset < 0:
                offset = max(0, len(keys) - max_items) if max_items else 0

            result = {}
            for k in keys[offset:]:
                result[k] = filtered[k]
                if max_items and len(result) >= max_items:
                    break

            return result

    def user_queue_wipe_history(self):
        with self.__prompt_queue.mutex:
            u = self.get_current_user_id()
            self.__prompt_queue.history = {k: v for k, v in self.__prompt_queue.history.items() if v.get("user_id") != u}

    # ---------------------------------------------------------
    # APPLY PATCHES
    # ---------------------------------------------------------

    def patch_prompt_queue(self):
        self.__prompt_queue.put = self.user_queue_put
        self.__prompt_queue.get = self.user_queue_get
        self.__prompt_queue.task_done = self.user_queue_task_done
        self.__prompt_queue.get_current_queue = self.user_queue_get_current_queue
        self.__prompt_queue.wipe_queue = self.user_queue_wipe_queue
        self.__prompt_queue.delete_queue_item = self.user_queue_delete_queue_item
        self.__prompt_queue.get_history = self.user_queue_get_history
        self.__prompt_queue.wipe_history = self.user_queue_wipe_history

    # ---------------------------------------------------------
    # MANAGER ACCESS CONTROL
    # ---------------------------------------------------------

    def create_manager_access_control_middleware(self, manager_directory="/extensions/comfyui-manager", manager_routes=()):
        @web.middleware
        async def middleware(request: web.Request, handler):
            user_id = request.get("user_id")

            if self.users_db.get_admin_user()[0] == user_id:
                return await handler(request)

            if not request.path.lower().startswith(manager_directory):
                return await handler(request)

            return web.HTTPForbidden(reason="Access denied to ComfyUI Manager")

        return middleware