import unittest
import os
import sqlite3
from core.module import RedReasonModule
from core.session import SessionManager
from core.types import ADUser, ADComputer, ADGPO

class DummyTestModule(RedReasonModule):
    """Concrete subclass of RedReasonModule to verify execution lifecycle stages."""
    def __init__(self):
        super().__init__()
        self.name = "DummyTestModule"
        self.description = "Unit Test Verification Module"
        self.tracker = []

    def stage_l0_presence(self):
        self.tracker.append("L0")

    def stage_l1_misconfig(self):
        self.tracker.append("L1")

    def stage_l2_validation(self):
        self.tracker.append("L2")

    def stage_l3_execution(self):
        self.tracker.append("L3")

    def run(self, args):
        self.execute_maturity_flow()


class TestRedReasonCoreUpgrades(unittest.TestCase):
    """Unit tests verifying database schema integrity, data mapping, and engine execution rules."""
    
    def setUp(self):
        self.target = "127.0.0.1"
        self.db_name = f"session_127.0.0.1.db"
        # Ensure clean environment
        if os.path.exists(self.db_name):
            try:
                os.remove(self.db_name)
            except OSError:
                pass
        self.sm = SessionManager(self.target)

    def tearDown(self):
        if os.path.exists(self.db_name):
            try:
                os.remove(self.db_name)
            except OSError:
                pass

    def test_database_initialization(self):
        """Verify SQLite database is successfully initialized with expected tables and indexes."""
        self.assertTrue(os.path.exists(self.db_name))
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Verify tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        self.assertIn("users", tables)
        self.assertIn("computers", tables)
        self.assertIn("group_members", tables)
        self.assertIn("trusts", tables)
        self.assertIn("gpos", tables)
        
        conn.close()

    def test_parameterized_crud_operations(self):
        """Verify data mapping and safe parameterized insertions in SessionManager."""
        user = ADUser(
            name="test_user",
            dn="CN=test_user,CN=Users,DC=domain,DC=local",
            sid="S-1-5-21-12345",
            description="Built-in Administrator",
            admin_count=True,
            password_last_set=1600000000,
            is_roastable_asrep=True,
            is_roastable_kerb=False,
            uac_flags=0x00040000,
            spn="host/service"
        )
        
        computer = ADComputer(
            name="test_comp",
            dn="CN=test_comp,OU=Computers,DC=domain,DC=local",
            sid="S-1-5-21-67890",
            os="Windows Server 2022",
            is_dc=True,
            has_laps=True,
            unconstrained_delegation=True
        )
        
        # Save state
        self.sm.save_state(
            collected_users=[user],
            collected_computers=[computer],
            collected_groups={"Domain Admins": ["CN=test_user,CN=Users,DC=domain,DC=local"]},
            collected_trusts=[{"name": "external.local", "direction": "Bidirectional"}],
            collected_gpos=[ADGPO(name="Default Domain Policy", display_name="Default Domain Policy", gpc_file_sys_path="\\\\sysvol\\Policies\\{GUID}")]
        )
        
        # Load state and verify mappings
        users, computers = self.sm.load_state()
        
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].name, "test_user")
        self.assertEqual(users[0].sid, "S-1-5-21-12345")
        self.assertTrue(users[0].admin_count)
        self.assertTrue(users[0].is_roastable_asrep)
        
        self.assertEqual(len(computers), 1)
        self.assertEqual(computers[0].name, "test_comp")
        self.assertTrue(computers[0].is_dc)
        self.assertTrue(computers[0].has_laps)
        
        # Custom query path verification
        high_risk_paths = self.sm.find_high_risk_relation_paths()
        self.assertEqual(len(high_risk_paths), 1)
        self.assertEqual(high_risk_paths[0]['user_name'], "test_user")
        self.assertEqual(high_risk_paths[0]['administrative_group'], "Domain Admins")

    def test_maturity_flow_engine_ceiling(self):
        """Verify MaturityFlowEngine execution boundaries and max_level ceilings."""
        mod = DummyTestModule()
        
        # Scenario 1: max_level = 3 (Full execution)
        mod.max_level = 3
        mod.execute_maturity_flow()
        self.assertEqual(mod.tracker, ["L0", "L1", "L2", "L3"])
        
        # Scenario 2: max_level = 1 (Stealth enforcement ceiling)
        mod.tracker = []
        mod.max_level = 1
        mod.execute_maturity_flow()
        self.assertEqual(mod.tracker, ["L0", "L1"])
        
        # Scenario 3: max_level = 0 (Presence query only)
        mod.tracker = []
        mod.max_level = 0
        mod.execute_maturity_flow()
        self.assertEqual(mod.tracker, ["L0"])

if __name__ == '__main__':
    unittest.main()
