from dataclasses import dataclass, field
from typing import List, Optional 

@dataclass
class RedReasonObject:
    """Base class for all enumerated objects."""
    name: str
    dn: Optional[str] = None
    sid: Optional[str] = None
    properties: dict = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "name": self.name,
            "dn": self.dn,
            "sid": self.sid,
            "properties": self.properties
        }

@dataclass
class ADUser(RedReasonObject):
    description: Optional[str] = None
    admin_count: bool = False
    password_last_set: Optional[int] = None # Timestamp
    is_roastable_asrep: bool = False
    is_roastable_kerb: bool = False
    uac_flags: int = 0
    spn: Optional[str] = None

@dataclass
class ADComputer(RedReasonObject):
    os: Optional[str] = None
    is_dc: bool = False
    has_laps: bool = False
    unconstrained_delegation: bool = False
    
@dataclass
class ADGroup(RedReasonObject):
    members: List[str] = field(default_factory=list)
