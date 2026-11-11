"""Scope Fence plugin for Hermes Agent."""
import logging

log = logging.getLogger(__name__)

try:
    from .scope_fence.hooks import (
        on_pre_tool_call, on_post_tool_call, on_session_finalize,
        on_session_reset, on_post_compaction, _bump as _bump_stat,
    )
    from .scope_fence.commands import handle_scope
except ImportError:
    from scope_fence.hooks import (
        on_pre_tool_call, on_post_tool_call, on_session_finalize,
        on_session_reset, on_post_compaction, _bump as _bump_stat,
    )
    from scope_fence.commands import handle_scope

CONFIG_KEYS = (
    "deny_paths", "replace_default_deny", "block_unparseable_destructive",
    "allow_reads_outside_scope", "allow_skill_writes", "max_scope_paths",
    "auto_scope", "deny_by_default", "strict_mode",
    "extra_write_paths", "replace_default_extra_write_paths", "mode",
)


def _import_config_module():
    """Import config module in both hermes_plugins.* and standalone namespaces."""
    try:
        from .scope_fence import config as cfg_mod
        return cfg_mod
    except ImportError:
        import scope_fence.config as cfg_mod
        return cfg_mod


def register(ctx):
    # Read plugin settings via the official API: plugins.entries.scope-fence.settings.*
    try:
        cfg_mod = _import_config_module()
        cfg = {}
        for key in CONFIG_KEYS:
            try:
                val = ctx.get_config(key, None)
            except Exception:
                val = None
            if val is not None:
                cfg[key] = val
        cfg_mod.set_runtime_config(cfg)
    except Exception as e:
        log.warning("scope-fence: could not read plugin config via ctx.get_config: %s", e)

    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("on_session_finalize", on_session_finalize)
    ctx.register_hook("on_session_reset", on_session_reset)
    try:
        ctx.register_hook("post_compaction", on_post_compaction)
    except Exception as e:
        log.warning("scope-fence: post_compaction hook unavailable: %s", e)

    def scope_handler(raw_args: str, session_id: str = "", **kwargs) -> str:
        return handle_scope(raw_args, session_id=session_id)

    ctx.register_command("scope", scope_handler, description="Manage write scope fence", args_hint="add|list|remove|check <dir>")

    # System prompt section (verified available in hermes_cli.plugins_context)
    def section_fn(session_info=None):
        sid = ""
        from collections.abc import Mapping
        if isinstance(session_info, Mapping):
            sid = session_info.get("session_id", "")
        try:
            _bump_stat("section_render")
        except Exception:
            pass
        try:
            cfg_mod = _import_config_module()
            from .scope_fence.store import get_scope as _get_scope
        except ImportError:
            from scope_fence.store import get_scope as _get_scope
        try:
            cfg = cfg_mod.load_config()
            scope = _get_scope(sid)
            deny = ", ".join(cfg.get("deny_paths", []))
            if scope["roots"]:
                roots = ", ".join(str(p) for p in scope["roots"])
                return (f"Scope Fence is ACTIVE. You may only write to: {roots}. "
                        f"Deny-list (never writable): {deny}. "
                        f"Writes outside scope will be blocked.")
            return ("Scope Fence is installed. No scope is declared yet; it will auto-scope "
                    "to the project's git root on your first write, or the user can run "
                    "/scope add <dir>. Writes outside the scope are blocked.")
        except Exception as e:
            log.warning("scope-fence: system prompt section failed: %s", e)
            return ("Scope Fence is installed. No scope is declared yet; it will auto-scope "
                    "to the project's git root on your first write, or the user can run "
                    "/scope add <dir>. Writes outside the scope are blocked.")

    try:
        # Bound is 1..4000 (MAX_SYSTEM_PROMPT_SECTION_CHARS); the section is ~200 chars.
        ctx.register_system_prompt_section("scope-fence", section_fn, max_chars=1000)
    except TypeError:
        # Older Hermes without the max_chars keyword.
        try:
            ctx.register_system_prompt_section("scope-fence", section_fn)
        except Exception as e:
            log.warning("scope-fence: could not register system prompt section: %s", e)
    except Exception as e:
        log.warning("scope-fence: could not register system prompt section: %s", e)
