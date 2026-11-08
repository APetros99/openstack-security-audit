"""Project-specific exceptions."""


class SecurityAuditError(Exception):
    """Base error raised by the security audit service."""


class ConfigurationError(SecurityAuditError):
    """Raised when configuration is missing or invalid."""


class CollectionError(SecurityAuditError):
    """Raised when an OpenStack collection cycle cannot complete."""

