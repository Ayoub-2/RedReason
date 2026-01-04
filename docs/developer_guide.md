# RedReason Developer Guide

This guide explains how to extend RedReason by creating new modules using the standardized architecture.

## 1. Architecture Overview
RedReason uses a modular architecture where each functional component (Enumeration, Attack, etc.) is a self-contained module inheriting from `RedReasonModule`. Data is shared between modules using typed objects defined in `core/types.py`.

## 2. Data Model (`core/types.py`)
Instead of passing unstructured dictionaries, we use strict Dataclasses.
*   **`ADUser`**: Represents a user account.
*   **`ADComputer`**: Represents a computer/server.
*   **`ADGroup`**: Represents a group.

**Example**:
```python
from core.types import ADUser
user = ADUser(name="jsmith", dn="CN=jsmith,DC=corp", is_roastable_asrep=True)
```

## 3. Creating a New Module
All modules must inherit from `RedReasonModule` and implement the `run` method.

**Template**:
```python
from core.module import RedReasonModule
from core.logger import log

class MyCustomModule(RedReasonModule):
    def __init__(self, target):
        super().__init__()
        self.name = "MyCustomModule"
        self.description = "Performs specific custom checks."
        self.target = target

    def run(self, args=None):
        self.log_start()
        # Implementation Logic
        log.info(f"Checking {self.target}...")
        self.log_end()
```

## 4. State Sharing
Modules can accept `enumeration_data` in their `__init__` to access data collected by previous modules.

```python
class ExploitModule(RedReasonModule):
    def __init__(self, target, enumeration_data=None):
        self.enumeration_data = enumeration_data

    def run(self, args=None):
        if self.enumeration_data:
            # Use cached users
            for user in self.enumeration_data.collected_users:
                if user.is_roastable_asrep:
                    self.attack(user)
```
