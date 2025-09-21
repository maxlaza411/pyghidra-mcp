from typing import TYPE_CHECKING, Any

from .context import ProgramInfo, PyGhidraContext
from .tools import GhidraTools

__version__ = "0.1.9"
__author__ = "clearbluejar"


def main() -> None:
    """Main entry point for the package."""
    from . import server as server_module

    server_module.main()


def __getattr__(name: str) -> Any:
    if name == "server":
        from . import server as server_module

        return server_module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if TYPE_CHECKING:
    from . import server as server_module

    server = server_module


# Optionally expose other important items at package level
__all__ = ["GhidraTools", "ProgramInfo", "PyGhidraContext", "main", "server"]
