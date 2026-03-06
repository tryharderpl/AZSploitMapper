"""
API Key authentication for AZSploitMapper.

Inspired by Prowler's API key approach:
- Keys are generated via CLI command and shown once
- Keys are stored as salted SHA-256 hashes (never plaintext)
- Each key has a name, prefix (for identification), and expiration date
- Keys are passed via the Authorization header: "Api-Key <key>"

This provides secure, non-interactive authentication suitable for:
- Local development (no Azure AD required)
- CI/CD pipelines
- Docker deployments
- API integrations
"""

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path

from azsploitmapper.logging_config import get_audit_logger

audit = get_audit_logger()

# API keys are stored in this file as hashed entries
DEFAULT_KEYS_FILE = "data/api_keys.json"


def _hash_key(key: str, salt: str) -> str:
    """
    Hash an API key with a salt using SHA-256.

    We never store the raw key -- only the salted hash.
    This means if the keys file is compromised, the actual
    keys cannot be recovered.
    """
    return hashlib.sha256(f"{salt}:{key}".encode()).hexdigest()


def generate_api_key(name: str, expires_days: int = 90) -> dict:
    """
    Generate a new API key and store its hash.

    Args:
        name: A descriptive label for this key (e.g. "admin", "ci-pipeline")
        expires_days: Number of days until the key expires (default: 90)

    Returns:
        A dict with the full key (shown only once), prefix, name, and expiration.
    """
    # Generate a cryptographically secure random key
    # Format: azm_<32 random bytes as URL-safe base64>
    raw_token = secrets.token_urlsafe(32)
    full_key = f"azm_{raw_token}"

    # The prefix is shown in management UIs for identification
    prefix = full_key[:12]

    # Generate a unique salt for this key
    salt = secrets.token_hex(16)

    # Hash the key for storage
    key_hash = _hash_key(full_key, salt)

    # Calculate expiration date
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=expires_days)

    # Build the key record (stored on disk)
    key_record = {
        "name": name,
        "prefix": prefix,
        "salt": salt,
        "key_hash": key_hash,
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "revoked": False,
        "last_used": None,
    }

    # Save to keys file
    _save_key_record(key_record)

    audit.info(
        "API key created: name=%s prefix=%s expires=%s",
        name, prefix, expires_at.isoformat(),
    )

    # Return the full key to the user (shown only once)
    return {
        "key": full_key,
        "prefix": prefix,
        "name": name,
        "expires_at": expires_at.isoformat(),
    }


def validate_api_key(key: str) -> dict | None:
    """
    Validate an API key against stored hashes.

    Args:
        key: The full API key string (e.g. "azm_abc123...")

    Returns:
        The key record dict if valid, or None if invalid/expired/revoked.
    """
    records = _load_key_records()

    for record in records:
        # Check if the key matches this record's hash
        key_hash = _hash_key(key, record["salt"])
        if key_hash != record["key_hash"]:
            continue

        # Key matches -- now check if it's still valid
        if record.get("revoked", False):
            audit.warning(
                "Revoked API key used: prefix=%s name=%s",
                record["prefix"], record["name"],
            )
            return None

        # Check expiration
        expires_at = datetime.fromisoformat(record["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            audit.warning(
                "Expired API key used: prefix=%s name=%s expired=%s",
                record["prefix"], record["name"], record["expires_at"],
            )
            return None

        # Update last_used timestamp
        record["last_used"] = datetime.now(timezone.utc).isoformat()
        _save_all_records(records)

        return record

    return None


def validate_env_api_key(key: str) -> bool:
    """
    Validate an API key against the AZSPLOITMAPPER_API_KEY environment variable.

    This is the simplest auth mode -- a single key set in the environment.
    For multi-key management, use the file-based key store instead.
    """
    env_key = os.getenv("AZSPLOITMAPPER_API_KEY", "")
    if not env_key:
        return False
    # Use constant-time comparison to prevent timing attacks
    return secrets.compare_digest(key, env_key)


def list_api_keys() -> list[dict]:
    """
    List all API keys (without the hash/salt -- just metadata).

    Returns a list of key summaries for display in management UI.
    """
    records = _load_key_records()
    summaries = []
    for record in records:
        summaries.append({
            "name": record["name"],
            "prefix": record["prefix"],
            "created_at": record["created_at"],
            "expires_at": record["expires_at"],
            "revoked": record.get("revoked", False),
            "last_used": record.get("last_used"),
        })
    return summaries


def revoke_api_key(prefix: str) -> bool:
    """
    Revoke an API key by its prefix.

    Revoked keys remain in the store for audit purposes
    but can no longer authenticate.
    """
    records = _load_key_records()
    for record in records:
        if record["prefix"] == prefix:
            record["revoked"] = True
            _save_all_records(records)
            audit.info("API key revoked: prefix=%s name=%s", prefix, record["name"])
            return True
    return False


def _load_key_records() -> list[dict]:
    """Load all key records from the keys file."""
    keys_path = Path(DEFAULT_KEYS_FILE)
    if not keys_path.exists():
        return []
    try:
        data = json.loads(keys_path.read_text())
        return data.get("keys", [])
    except (json.JSONDecodeError, OSError):
        return []


def _save_key_record(record: dict):
    """Append a new key record to the keys file."""
    records = _load_key_records()
    records.append(record)
    _save_all_records(records)


def _save_all_records(records: list[dict]):
    """Write all key records to the keys file."""
    keys_path = Path(DEFAULT_KEYS_FILE)
    keys_path.parent.mkdir(parents=True, exist_ok=True)
    keys_path.write_text(json.dumps({"keys": records}, indent=2))
    # Restrict file permissions (owner read/write only)
    try:
        keys_path.chmod(0o600)
    except OSError:
        pass
