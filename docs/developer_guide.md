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

        self.log_start()
        # Implementation Logic
        if self.connect():
             self.execute_maturity_flow()
        self.log_end()

    # Implement Stages
    def stage_l0_presence(self):
        log.info("L0: Checking feature presence...")

    def stage_l1_misconfig(self):
        log.info("L1: Checking misconfigurations...")
```

## 3a. Module Maturity Model (L0-L4)
All new modules should follow the **Maturity Model** by implementing the following methods:

1.  **`stage_l0_presence()`**: Is the service/feature present? (Enumeration)
2.  **`stage_l1_misconfig()`**: Is it misconfigured? (Detection)
3.  **`stage_l2_validation()`**: Is it exploitable *for us*? (Validation)
4.  **`stage_l3_execution()`**: Execute attack (Requires explicit approval/flag).
5.  **`stage_l4_suggestions()`**: Remediation advice (Reasoning).

The base `RedReasonModule` class provides the `execute_maturity_flow()` helper to run these in order.

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
