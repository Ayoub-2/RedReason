import sqlite3
import os
from core.types import ADUser, ADComputer
from core.logger import log

class SessionManager:
    """
    Manages session context state sharing using a local transactional SQLite database.
    Provides parameterized queries, schema validation, and graph relation pathfinding.
    """
    def __init__(self, target):
        self.target = target
        # Sanitize target domain or IP filename characters to prevent path injection
        sanitized_target = "".join([c for c in target if c.isalnum() or c in ".-_"])
        self.db_name = f"session_{sanitized_target}.db"
        self.conn = None
        self._initialize_database()

    def _get_connection(self):
        """Returns a connection to the SQLite database. Configures thread safety."""
        try:
            conn = sqlite3.connect(self.db_name, timeout=10.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            log.fail(f"SQLite Connection Failure: {e}")
            raise

    def _initialize_database(self):
        """Creates the relational database schema representing Active Directory graph structure."""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # 1. Users Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    sam_name TEXT PRIMARY KEY,
                    dn TEXT,
                    sid TEXT,
                    description TEXT,
                    admin_count INTEGER,
                    pwd_last_set INTEGER,
                    is_roastable_asrep INTEGER,
                    is_roastable_kerb INTEGER,
                    uac_flags INTEGER,
                    spn TEXT
                )
            """)
            
            # 2. Computers Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS computers (
                    name TEXT PRIMARY KEY,
                    dn TEXT,
                    sid TEXT,
                    os TEXT,
                    is_dc INTEGER,
                    has_laps INTEGER,
                    unconstrained_delegation INTEGER
                )
            """)
            
            # 3. Group Memberships Table (M2M Relationship representing Graph Edges)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS group_members (
                    group_name TEXT,
                    member_dn TEXT,
                    PRIMARY KEY (group_name, member_dn)
                )
            """)
            
            # 4. Trusts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS trusts (
                    name TEXT PRIMARY KEY,
                    direction TEXT
                )
            """)
            
            # 5. GPOs Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS gpos (
                    name TEXT PRIMARY KEY,
                    file_sys_path TEXT
                )
            """)
            
            # Create indexes to optimize relationship traversals and prevent lock contention
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_group_members_dn ON group_members(member_dn)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_sid ON users(sid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_computers_dc ON computers(is_dc)")
            
            conn.commit()
            log.debug("SQLite database initialized successfully.")
        except sqlite3.Error as e:
            log.fail(f"Failed to initialize SQLite Database schema: {e}")
        finally:
            if conn:
                conn.close()

    def save_state(self, collected_users, collected_computers, collected_groups=None, collected_trusts=None, collected_gpos=None):
        """
        Saves all collected AD entities within a single, ACID-compliant database transaction.
        Enforces fully parameterized queries to protect against input injection (Rule 15, 16).
        """
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Use REPLACE INTO for clean state updating or insertion
            if collected_users:
                log.debug(f"Inserting/updating {len(collected_users)} user records into cache...")
                for u in collected_users:
                    # Input normalization and validation
                    sam_name = str(u.name) if u.name else ""
                    if not sam_name:
                        continue
                    
                    cursor.execute("""
                        INSERT OR REPLACE INTO users (
                            sam_name, dn, sid, description, admin_count, 
                            pwd_last_set, is_roastable_asrep, is_roastable_kerb, uac_flags, spn
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        sam_name,
                        str(u.dn) if u.dn else None,
                        str(u.sid) if u.sid else None,
                        str(u.description) if u.description else None,
                        1 if u.admin_count else 0,
                        int(u.password_last_set) if u.password_last_set else 0,
                        1 if u.is_roastable_asrep else 0,
                        1 if u.is_roastable_kerb else 0,
                        int(u.uac_flags) if u.uac_flags else 0,
                        str(u.spn) if u.spn else None
                    ))

            if collected_computers:
                log.debug(f"Inserting/updating {len(collected_computers)} computer records into cache...")
                for c in collected_computers:
                    name = str(c.name) if c.name else ""
                    if not name:
                        continue
                    
                    cursor.execute("""
                        INSERT OR REPLACE INTO computers (
                            name, dn, sid, os, is_dc, has_laps, unconstrained_delegation
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        name,
                        str(c.dn) if c.dn else None,
                        str(c.sid) if c.sid else None,
                        str(c.os) if c.os else None,
                        1 if c.is_dc else 0,
                        1 if c.has_laps else 0,
                        1 if c.unconstrained_delegation else 0
                    ))

            if collected_groups:
                log.debug(f"Inserting/updating group member relations...")
                for g_name, members in collected_groups.items():
                    group_name = str(g_name)
                    for m_dn in members:
                        cursor.execute("""
                            INSERT OR REPLACE INTO group_members (group_name, member_dn)
                            VALUES (?, ?)
                        """, (group_name, str(m_dn)))

            if collected_trusts:
                for t in collected_trusts:
                    t_name = str(t.get('name')) if isinstance(t, dict) else str(t)
                    t_dir = str(t.get('direction', 'Bidirectional')) if isinstance(t, dict) else 'Unknown'
                    cursor.execute("""
                        INSERT OR REPLACE INTO trusts (name, direction)
                        VALUES (?, ?)
                    """, (t_name, t_dir))

            if collected_gpos:
                for gpo in collected_gpos:
                    g_name = str(gpo.display_name) if gpo.display_name else str(gpo.name)
                    g_path = str(gpo.gpc_file_sys_path) if gpo.gpc_file_sys_path else ""
                    cursor.execute("""
                        INSERT OR REPLACE INTO gpos (name, file_sys_path)
                        VALUES (?, ?)
                    """, (g_name, g_path))

            conn.commit()
            log.success(f"Session state updated successfully in SQLite database: {self.db_name}")
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            log.fail(f"Failed to commit AD session state to SQLite: {e}")
        finally:
            if conn:
                conn.close()

    def load_state(self):
        """
        Loads cached users and computers from the SQLite database.
        Returns a tuple of (users_list, computers_list) to maintain backwards compatibility.
        """
        if not os.path.exists(self.db_name):
            log.debug(f"No existing SQLite session database found for {self.target}.")
            return None, None
            
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Load users
            cursor.execute("SELECT * FROM users")
            users_rows = cursor.fetchall()
            users = []
            for r in users_rows:
                u = ADUser(
                    name=r['sam_name'],
                    dn=r['dn'],
                    sid=r['sid'],
                    description=r['description'],
                    admin_count=bool(r['admin_count']),
                    password_last_set=r['pwd_last_set'],
                    is_roastable_asrep=bool(r['is_roastable_asrep']),
                    is_roastable_kerb=bool(r['is_roastable_kerb']),
                    uac_flags=r['uac_flags'],
                    spn=r['spn']
                )
                users.append(u)
                
            # Load computers
            cursor.execute("SELECT * FROM computers")
            comp_rows = cursor.fetchall()
            computers = []
            for r in comp_rows:
                c = ADComputer(
                    name=r['name'],
                    dn=r['dn'],
                    sid=r['sid'],
                    os=r['os'],
                    is_dc=bool(r['is_dc']),
                    has_laps=bool(r['has_laps']),
                    unconstrained_delegation=bool(r['unconstrained_delegation'])
                )
                computers.append(c)
                
            log.success(f"Loaded cached state: {len(users)} users, {len(computers)} computers.")
            return users, computers
        except sqlite3.Error as e:
            log.fail(f"Failed to read session state from database: {e}")
            return None, None
        finally:
            if conn:
                conn.close()

    def execute_custom_query(self, query, params=()):
        """
        Executes a custom parameterized query on the database cache.
        Returns all matched rows as lists of dicts.
        """
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error as e:
            log.fail(f"Failed custom SQLite query: {e} (Query: {query})")
            return []
        finally:
            if conn:
                conn.close()

    def find_high_risk_relation_paths(self):
        """
        Natively traverse active directory nodes inside the SQLite database cache.
        Returns a list of high-risk user-to-group administrative linkages (Graph analysis).
        """
        query = """
            SELECT u.sam_name as user_name, u.dn as user_dn, gm.group_name as administrative_group
            FROM users u
            JOIN group_members gm ON u.dn = gm.member_dn
            WHERE gm.group_name IN ('Domain Admins', 'Enterprise Admins', 'Administrators')
            OR u.admin_count = 1
        """
        return self.execute_custom_query(query)
