"""Explicit, small built-in rule set. No plugin discovery or network lookups."""
from aire.security.rules.api_calls import UnboundedCopyRule, DangerousApiRule

__all__ = ['UnboundedCopyRule', 'DangerousApiRule']
