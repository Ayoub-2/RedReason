import json
import os
from core.types import ADUser, ADComputer
from core.logger import log

class SessionManager:
    def __init__(self, target):
        self.target = target
        self.filename = f"session_{target}.json"

    def save_state(self, collected_users, collected_computers):
        data = {
            "users": [u.to_dict() for u in collected_users],
            "computers": [c.to_dict() for c in collected_computers]
        }
        try:
            with open(self.filename, 'w') as f:
                json.dump(data, f, indent=4)
            log.success(f"Session state saved to {self.filename}")
        except Exception as e:
            log.fail(f"Failed to save session state: {e}")

    def load_state(self):
        if not os.path.exists(self.filename):
            log.info(f"No existing session found for {self.target}")
            return None, None
        
        try:
            with open(self.filename, 'r') as f:
                data = json.load(f)
            
            users = [ADUser.from_dict(u) for u in data.get("users", [])]
            computers = [ADComputer.from_dict(c) for c in data.get("computers", [])]
            log.success(f"Loaded session state: {len(users)} users, {len(computers)} computers.")
            return users, computers
        except Exception as e:
            log.fail(f"Failed to load session state: {e}")
            return None, None
