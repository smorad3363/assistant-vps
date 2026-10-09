"""Stable PM2 CLI return/error codes."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PM2Error(Exception):
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return {
            "E_VALIDATION": 2,
            "E_PERMISSION": 3,
            "E_DEPENDENCY": 4,
            "E_CONFLICT": 5,
            "E_APPLY": 6,
            "E_ROLLBACK": 7,
            "E_UNSUPPORTED": 8,
            "E_LOCKED": 9,
        }.get(self.code, 6)
