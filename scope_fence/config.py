"""Config for scope-fence plugin.

Config is populated at plugin registration via ``ctx.get_config()`` and stored
in ``_RUNTIME_CONFIG``. ``load_config()`` merges it over ``DEFAULTS``.
"""
import logging

log = logging.getLogger(__name__)

DEFAULTS = {
    "deny_paths": ["~/.ssh", "~/.env", "~/.aws", "~/.gnupg", "~/.config",
                   "~/.bashrc", "~/.zshrc", "~/.profile", "~/.hermes"],
    "replace_default_deny": False,
    "block_unparseable_destructive": True,
    "allow_reads_outside_scope": True,
    "allow_skill_writes": False,
    "max_scope_paths": 8,
    "auto_scope": True,
    "deny_by_default": False,
    "strict_mode": False,
    "extra_write_paths": ["/tmp", "$TMPDIR", "~/.cache"],
    "replace_default_extra_write_paths": False,
    "mode": "enforce",
}

CONFIG_SCHEMA = {
    "deny_paths": list,
    "replace_default_deny": bool,
    "block_unparseable_destructive": bool,
    "allow_reads_outside_scope": bool,
    "allow_skill_writes": bool,
    "max_scope_paths": int,
    "auto_scope": bool,
    "deny_by_default": bool,
    "strict_mode": bool,
    "extra_write_paths": list,
    "replace_default_extra_write_paths": bool,
    "mode": str,
}

MODE_ENFORCE = "enforce"
MODE_WARN = "warn"
_VALID_MODES = (MODE_ENFORCE, MODE_WARN)

# Populated by register(ctx) via ctx.get_config(); empty until then.
_RUNTIME_CONFIG: dict = {}


def set_runtime_config(cfg: dict):
    """Store config read from ctx.get_config() at registration time."""
    global _RUNTIME_CONFIG
    _RUNTIME_CONFIG = dict(cfg) if isinstance(cfg, dict) else {}


def validate_config(cfg: dict) -> dict:
    """Validate config against schema, return cleaned config with defaults."""
    result = dict(DEFAULTS)
    if not isinstance(cfg, dict):
        return result
    unknown = set(cfg.keys()) - set(CONFIG_SCHEMA.keys())
    if unknown:
        log.warning("scope-fence: unknown config keys ignored: %s", ", ".join(sorted(unknown)))
    for key, typ in CONFIG_SCHEMA.items():
        if key in cfg:
            val = cfg[key]
            # Reject bool for int (bool is subclass of int)
            if typ is int and isinstance(val, bool):
                log.warning("scope-fence: config %s must be int, got bool; using default", key)
                continue
            if typ is bool and not isinstance(val, bool):
                log.warning("scope-fence: config %s must be bool, got %r; using default", key, type(val).__name__)
                continue
            if isinstance(val, typ):
                if typ is int and val <= 0:
                    log.warning("scope-fence: config %s must be > 0; using default", key)
                    continue
                if key == "deny_paths" and isinstance(val, list):
                    cleaned = [str(p) for p in val if isinstance(p, str) and p.strip()]
                    if cleaned:
                        if cfg.get("replace_default_deny", False):
                            result[key] = cleaned
                        else:
                            # Additive: defaults stay, user entries extend
                            merged = list(DEFAULTS["deny_paths"])
                            for p in cleaned:
                                if p not in merged:
                                    merged.append(p)
                            result[key] = merged
                    continue
                if key == "mode":
                    if val not in _VALID_MODES:
                        log.warning("scope-fence: config mode must be one of %s, got %r; using default",
                                    ", ".join(_VALID_MODES), val)
                        continue
                    result[key] = val
                    continue
                if key == "extra_write_paths" and isinstance(val, list):
                    cleaned = [str(p) for p in val if isinstance(p, str) and p.strip()]
                    if cleaned:
                        if cfg.get("replace_default_extra_write_paths", False):
                            result[key] = cleaned
                        else:
                            # Additive: defaults stay, user entries extend
                            merged = list(DEFAULTS["extra_write_paths"])
                            for p in cleaned:
                                if p not in merged:
                                    merged.append(p)
                            result[key] = merged
                    continue
                result[key] = val
    return result


def extra_write_roots() -> list:
    """Resolved extra write paths (scratch dirs). Filesystem roots and $HOME are rejected."""
    import os
    from .paths import resolve, is_filesystem_root
    cfg = load_config()
    out = []
    home = os.path.realpath(os.path.expanduser("~"))
    for raw in cfg.get("extra_write_paths", []):
        if not isinstance(raw, str):
            continue
        p = os.path.expanduser(os.path.expandvars(raw)).strip()
        if not p:
            continue
        try:
            rp = resolve(p)
        except Exception:
            continue
        if is_filesystem_root(rp) or str(rp) == home:
            log.warning("scope-fence: extra_write_paths entry rejected (filesystem root or $HOME): %s", raw)
            continue
        if rp not in out:
            out.append(rp)
    return out


def mode() -> str:
    """Effective mode: 'enforce' (default) or 'warn'."""
    return load_config().get("mode", MODE_ENFORCE)


def load_config() -> dict:
    """Return validated config: runtime config (from ctx.get_config) over defaults."""
    return validate_config(_RUNTIME_CONFIG)
