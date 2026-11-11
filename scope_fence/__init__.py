"""scope_fence package."""
from .config import load_config
from .paths import resolve, check_path, is_inside
from .terminal import classify_terminal
from .store import get_scope, add_scope, remove_scope, record_cwd, record_block, prune_session, invalidate_cache, get_audit
from .hooks import on_pre_tool_call, on_post_tool_call, on_session_finalize, on_session_reset, on_post_compaction
from .commands import handle_scope

__all__ = [
    "load_config", "resolve", "check_path", "is_inside",
    "classify_terminal", "get_scope", "add_scope", "remove_scope",
    "record_cwd", "record_block", "prune_session", "invalidate_cache",
    "get_audit", "on_pre_tool_call", "on_post_tool_call", "on_session_finalize",
    "on_session_reset", "on_post_compaction", "handle_scope",
]
