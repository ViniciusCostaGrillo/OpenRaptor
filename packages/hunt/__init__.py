"""OpenRaptor Bug Bounty & Ethical Hacking orchestration package."""

from .classifier import TargetClassification, TargetKind, classify_target
from .scope import ScopeConfig, ScopeViolationError, assert_in_scope

__all__ = [
    "ScopeConfig",
    "ScopeViolationError",
    "TargetClassification",
    "TargetKind",
    "assert_in_scope",
    "classify_target",
]
