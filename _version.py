"""Tool identity and version. Single source of truth for the version string."""

TOOL_NAME = "NullGrant"

TOOL_VERSION = "1.0.0"

USER_AGENT = f"{TOOL_NAME}/{TOOL_VERSION} (standards-compliance audit)"

#: PEP 440 version, kept identical to TOOL_VERSION.
__version__ = TOOL_VERSION
