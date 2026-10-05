from pathlib import Path
from typing import Any, Dict

try:
    from application_profiler import ApplicationProfiler, profile_application as rich_profile
except ImportError:
    from orchestrator.application_profiler import ApplicationProfiler, profile_application as rich_profile


def profile_application(app_path) -> Dict[str, Any]:
    """
    Profile the application using the full generic ApplicationProfiler engine
    while maintaining 100% backward compatibility with legacy schema.
    """
    return rich_profile(app_path)