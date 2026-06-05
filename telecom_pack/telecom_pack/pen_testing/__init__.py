"""Telecom pen testing — social engineering + account takeover simulation.

Provides:
- TelecomPenTestRunner: parameterized attack simulator for telecom scenarios
- SocialEngineeringDetector: detects social engineering in customer interactions
- Pattern catalogs: YAML-based, tagged to compliance frameworks
"""

from telecom_pack.pen_testing.runner import TelecomPenTestResult, TelecomPenTestRunner
from telecom_pack.pen_testing.social_engineering import (
    SocialEngineeringDetector,
    SocialEngineeringMatch,
)

__all__ = [
    "SocialEngineeringDetector",
    "SocialEngineeringMatch",
    "TelecomPenTestResult",
    "TelecomPenTestRunner",
]
