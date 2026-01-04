import json
import os
from core.logger import log
from core.types import ADUser, ADComputer

class BloodHoundGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir

    def save_json(self, data, filename):
        path = os.path.join(self.output_dir, filename)
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            log.success(f"Generated BloodHound file: {path}")
        except Exception as e:
            log.fail(f"Failed to generate {filename}: {e}")

    def generate_users(self, domain, users_list):
        # basic structure for BH 4
        bh_data = {
            "data": [],
            "meta": {
                "methods": 0,
                "type": "users",
                "count": 0,
                "version": 4
            }
        }
        
        for user in users_list:
            # user is now an ADUser object
            u_obj = {
                "Properties": {
                    "domain": domain,
                    "name": f"{user.name}@{domain}",
                    "distinguishedname": user.dn,
                    "description": user.description,
                    "admincount": user.admin_count,
                    "enabled": not bool(user.uac_flags & 0x2), # ACCOUNTDISABLE = 0x2
                    "passwordlastset": user.password_last_set
                },
                "ObjectIdentifier": user.sid or f"{user.name}@{domain}", 
                "Aces": [],
                "SPNTargets": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
                "IsAdmin": False,
                "IsService": False
            }
            bh_data["data"].append(u_obj)
        
        bh_data["meta"]["count"] = len(bh_data["data"])
        self.save_json(bh_data, "users.json")

    def generate_computers(self, domain, computers_list):
        bh_data = {
            "data": [],
            "meta": {
                "methods": 0,
                "type": "computers",
                "count": 0,
                "version": 4
            }
        }
        
        for comp in computers_list:
            c_name = comp.name
            c_obj = {
                "Properties": {
                    "domain": domain,
                    "name": f"{c_name}.{domain}",
                    "distinguishedname": comp.dn,
                    "haslaps": comp.has_laps,
                    "enabled": True
                },
                "ObjectIdentifier": f"{c_name}.{domain}",
                "Aces": [],
                "IncomingRules": [],
                "OutgoingRules": [],
                "IsDeleted": False,
                "Status": None
            }
            bh_data["data"].append(c_obj)

        bh_data["meta"]["count"] = len(bh_data["data"])
        self.save_json(bh_data, "computers.json")
