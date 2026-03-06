"""
Centralized logging and audit trail for AZSploitMapper.

All security-relevant events (logins, scan triggers, API access)
are logged with timestamps, user identity, source IP, and action.
This provides an audit trail for compliance and incident response.
"""

import logging
import os
import sys
from pathlib import Path


def setup_logging() -> logging.Logger:
    """
    Configure application-wide logging with both console and file output.

    Returns the root 'azsploitmapper' logger that all modules should use.
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logger = logging.getLogger("azsploitmapper")
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Prevent duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    # Log format includes timestamp, level, module, and message
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    # Console handler -- always enabled
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler -- write to logs/ directory if possible
    try:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "azsploitmapper.log")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        logger.warning("Could not create log file, using console only")

    return logger


# Dedicated audit logger for security events
def get_audit_logger() -> logging.Logger:
    """
    Return a logger specifically for security audit events.

    Audit events include: login, logout, scan trigger, API key usage,
    failed authentication, and configuration changes.
    """
    return logging.getLogger("azsploitmapper.audit")
