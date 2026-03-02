# Server
# ---------------------------------------------------------------------------------
import json
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import click
import pyghidra
from click_option_group import optgroup
from mcp.server import Server
from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse

from pyghidra_mcp import mcp_tools
from pyghidra_mcp.__init__ import __version__
from pyghidra_mcp.context import PyGhidraContext

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,  # Critical for STDIO transport
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

_T = TypeVar("_T")


# Init Pyghidra
# ---------------------------------------------------------------------------------
@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[PyGhidraContext]:
    """Manage server startup and shutdown lifecycle."""
    try:
        yield server._pyghidra_context  # type: ignore
    finally:
        pyghidra_context = getattr(server, "_pyghidra_context", None)
        if pyghidra_context is not None:
            close_method = getattr(pyghidra_context, "close", None)
            if callable(close_method):
                try:
                    close_method()
                except Exception:  # pragma: no cover - defensive cleanup
                    logger.exception("Error closing PyGhidraContext during shutdown")


mcp = FastMCP("pyghidra-mcp", lifespan=server_lifespan)  # type: ignore


# Register tools from mcp_tools module
# ---------------------------------------------------------------------------------

# ── Existing tools ────────────────────────────────────────────────────────────
mcp.tool()(mcp_tools.decompile_function)
mcp.tool()(mcp_tools.get_function_disassembly)
mcp.tool()(mcp_tools.get_function_pcode)
mcp.tool()(mcp_tools.get_function_analysis_report)
mcp.tool()(mcp_tools.search_symbols_by_name)
mcp.tool()(mcp_tools.search_code)
mcp.tool()(mcp_tools.list_project_binaries)
mcp.tool()(mcp_tools.list_project_binary_metadata)
mcp.tool()(mcp_tools.delete_project_binary)
mcp.tool()(mcp_tools.list_exports)
mcp.tool()(mcp_tools.list_imports)
mcp.tool()(mcp_tools.list_cross_references)
mcp.tool()(mcp_tools.search_strings)
mcp.tool()(mcp_tools.read_bytes)
mcp.tool()(mcp_tools.gen_callgraph)
mcp.tool()(mcp_tools.import_binary)
mcp.tool()(mcp_tools.analyze_now)
mcp.tool()(mcp_tools.project_open)
mcp.tool()(mcp_tools.select_program)

# ── Annotation / mutation tools ───────────────────────────────────────────────
mcp.tool()(mcp_tools.rename_function)
mcp.tool()(mcp_tools.rename_variable)
mcp.tool()(mcp_tools.set_comment)
mcp.tool()(mcp_tools.set_function_signature)
mcp.tool()(mcp_tools.create_label)

# ── Navigation tools ──────────────────────────────────────────────────────────
mcp.tool()(mcp_tools.list_functions)
mcp.tool()(mcp_tools.list_namespaces)
mcp.tool()(mcp_tools.get_function_containing)
mcp.tool()(mcp_tools.list_basic_blocks)
mcp.tool()(mcp_tools.get_entry_points)

# ── Memory tools ──────────────────────────────────────────────────────────────
mcp.tool()(mcp_tools.list_memory_segments)
mcp.tool()(mcp_tools.find_byte_pattern)
mcp.tool()(mcp_tools.list_all_strings)

# ── Data type tools ───────────────────────────────────────────────────────────
mcp.tool()(mcp_tools.list_data_types)
mcp.tool()(mcp_tools.get_data_type)
mcp.tool()(mcp_tools.create_struct)
mcp.tool()(mcp_tools.apply_data_type)
mcp.tool()(mcp_tools.get_data_at)
mcp.tool()(mcp_tools.get_stack_frame)

# ── Composite / context tools ─────────────────────────────────────────────────
mcp.tool()(mcp_tools.get_function_context)
mcp.tool()(mcp_tools.get_binary_summary)
mcp.tool()(mcp_tools.decompile_functions_batch)

# ── Script execution ──────────────────────────────────────────────────────────
mcp.tool()(mcp_tools.run_python_script)


def init_pyghidra_context(
    mcp: FastMCP,
    *,
    input_paths: list[Path],
    project_name: str,
    project_directory: str,
    pyghidra_mcp_dir: Path,
    force_analysis: bool,
    verbose_analysis: bool,
    no_symbols: bool,
    gdts: list[str],
    program_options_path: str | None,
    gzfs_path: str | None,
    threaded: bool,
    max_workers: int,
    wait_for_analysis: bool,
    list_project_binaries: bool,
    delete_project_binary: str | None,
    symbols_path: str | None,
    sym_file_path: str | None,
) -> FastMCP:
    bin_paths: list[str | Path] = [Path(p) for p in input_paths]
    logger.info(f"Project: {project_name}")
    logger.info(f"Project: Location {project_directory}")

    program_options: dict | None = None
    if program_options_path:
        with open(program_options_path) as f:
            program_options = json.load(f)

    # init pyghidra
    pyghidra.start(False)  # setting Verbose output

    # init PyGhidraContext / import + analyze binaries
    logger.info("Server initializing...")
    try:
        pyghidra_context = PyGhidraContext(
            project_name=project_name,
            project_path=project_directory,
            pyghidra_mcp_dir=pyghidra_mcp_dir,
            force_analysis=force_analysis,
            verbose_analysis=verbose_analysis,
            no_symbols=no_symbols,
            gdts=gdts,
            program_options=program_options,
            gzfs_path=gzfs_path,
            threaded=threaded,
            max_workers=max_workers,
            auto_open=False,
            wait_for_analysis=wait_for_analysis,
            symbols_path=symbols_path,
            sym_file_path=sym_file_path,
        )
        pyghidra_context.open_project(Path(project_directory), project_name)

        if list_project_binaries:
            binaries = pyghidra_context.list_binaries()
            if binaries:
                click.echo("Ghidra Project Binaries:")
                for binary_name in binaries:
                    click.echo(f"- {binary_name}")
            else:
                click.echo("No binaries found in the project.")
            sys.exit(0)

        if delete_project_binary:
            try:
                if pyghidra_context.delete_program(delete_project_binary):
                    click.echo(f"Successfully deleted binary: {delete_project_binary}")
                else:
                    click.echo(f"Failed to delete binary: {delete_project_binary}", err=True)
            except ValueError as e:
                click.echo(f"Error: {e}", err=True)
            sys.exit(0)

        if len(bin_paths) > 0:
            logger.info(f"Adding new bins: {', '.join(map(str, bin_paths))}")
            logger.info(f"Importing binaries to {project_directory}")
            pyghidra_context.import_binaries(bin_paths)

        logger.info(f"Analyzing project: {pyghidra_context.project}")
        pyghidra_context.analyze_project()

        if len(pyghidra_context.list_binaries()) == 0:
            logger.warning("No binaries were imported and none exist in the project.")

        mcp._pyghidra_context = pyghidra_context  # type: ignore[attr-defined]
        mcp._pyghidra_context_error = None  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover - defensive programming
        logger.exception("Failed to initialize PyGhidra context: %s", exc)
        mcp._pyghidra_context = None  # type: ignore[attr-defined]
        mcp._pyghidra_context_error = {"message": str(exc)}  # type: ignore[attr-defined]
        raise
    logger.info("Server initialized")

    return mcp


# MCP Server Entry Point
# ---------------------------------------------------------------------------------


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(
    __version__,
    "-v",
    "--version",
    help="Show version and exit.",
)
# --- Server Options ---
@optgroup.group("Server Options")
@optgroup.option(
    "-t",
    "--transport",
    type=click.Choice(["stdio", "streamable-http", "sse", "http"], case_sensitive=False),
    default="stdio",
    envvar="MCP_TRANSPORT",
    show_default=True,
    help="Transport protocol to use.",
)
@optgroup.option(
    "-p",
    "--port",
    type=int,
    default=8000,
    envvar="MCP_PORT",
    show_default=True,
    help="Port to listen on for HTTP-based transports.",
)
@optgroup.option(
    "-o",
    "--host",
    type=str,
    default="127.0.0.1",
    envvar="MCP_HOST",
    show_default=True,
    help="Host to listen on for HTTP-based transports.",
)
@optgroup.option(
    "--project-path",
    type=click.Path(path_type=Path),
    default=Path("pyghidra_mcp_projects"),
    show_default=True,
    help="Directory path to create new pyghidra-mcp project or an existing Ghidra .gpr file.",
)
@optgroup.option(
    "--project-name",
    type=str,
    default="my_project",
    show_default=True,
    help="Name for the project (used for Ghidra project files). Ignored when using .gpr files.",
)
@optgroup.option(
    "--threaded/--no-threaded",
    default=True,
    show_default=True,
    help="Allow threaded analysis. Disable for debug.",
)
@optgroup.option(
    "--max-workers",
    type=int,
    default=0,  # 0 means multiprocessing.cpu_count()
    show_default=True,
    help="Number of workers for threaded analysis. Defaults to CPU count.",
)
@optgroup.option(
    "--wait-for-analysis/--no-wait-for-analysis",
    default=False,
    show_default=True,
    help="Wait for initial project analysis to complete before starting the server.",
)
# --- Project Options ---
@optgroup.group("Project Management")
@optgroup.option(
    "--list-project-binaries",
    is_flag=True,
    help="List all ingested binaries in the project.",
)
@optgroup.option(
    "--delete-project-binary",
    type=str,
    help="Delete a specific binary (program) from the project by name.",
)
# --- Analysis Options ---
@optgroup.group("Analysis Options")
@optgroup.option(
    "--force-analysis/--no-force-analysis",
    default=False,
    show_default=True,
    help="Force a new binary analysis each run.",
)
@optgroup.option(
    "--verbose-analysis/--no-verbose-analysis",
    default=False,
    show_default=True,
    help="Verbose logging for analysis step.",
)
@optgroup.option(
    "--no-symbols/--with-symbols",
    default=False,
    show_default=True,
    help="Turn off symbols for analysis.",
)
@optgroup.option(
    "--sym-file-path",
    type=click.Path(exists=True),
    default=None,
    help="Specify single pdb symbol file for bin (default: None)",
)
@optgroup.option(
    "-s",
    "--symbols-path",
    type=click.Path(),
    default=None,
    help="Path for local symbols directory (default: symbols)",
)
@optgroup.option(
    "--gdt",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to GDT files (can be specified multiple times).",
)
@optgroup.option(
    "--program-options",
    type=click.Path(exists=True),
    help="Path to a JSON file containing program options.",
)
@optgroup.option(
    "--gzfs-path",
    type=click.Path(),
    help="Location to store GZFs of analyzed binaries.",
)
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1)
def main(
    transport: str,
    input_paths: list[Path],
    project_path: Path,
    project_name: str,
    port: int,
    host: str,
    threaded: bool,
    force_analysis: bool,
    verbose_analysis: bool,
    no_symbols: bool,
    gdt: tuple[str, ...],
    program_options: str | None,
    gzfs_path: str | None,
    max_workers: int,
    wait_for_analysis: bool,
    list_project_binaries: bool,
    delete_project_binary: str | None,
    sym_file_path: str | None,
    symbols_path: str | None,
) -> None:
    """PyGhidra Command-Line MCP server

    - input_paths: Path to one or more binaries to import, analyze, and expose with pyghidra-mcp\n
    - transport: Supports stdio, streamable-http, and sse transports.\n
    For stdio, it will read from stdin and write to stdout.
    For streamable-http and sse, it will start an HTTP server on the specified port (default 8000).

    """
    # Handle both .gpr files and directory paths
    if project_path.suffix.lower() == ".gpr":
        # Check constraint: cannot use --project-name with .gpr files
        if project_name != "my_project":  # project_name was explicitly provided (not default)
            raise click.BadParameter("Cannot use --project-name when specifying a .gpr file")

        # Direct .gpr opening - create pyghidra-mcp alongside existing project
        project_directory = str(project_path.parent)
        project_name = project_path.stem
        pyghidra_mcp_dir = project_path.parent / f"{project_name}-pyghidra-mcp"
    else:
        # Directory-based opening - create self-contained project
        # Use provided project_name (defaults to my_project)
        # This creates the structure:
        # project_path/project_name.gpr, project_path/project_name-pyghidra-mcp/, etc.
        project_directory = str(project_path)
        pyghidra_mcp_dir = project_path / f"{project_name}-pyghidra-mcp"
    mcp.settings.port = port
    mcp.settings.host = host

    init_pyghidra_context(
        mcp=mcp,
        input_paths=input_paths,
        project_name=project_name,
        project_directory=project_directory,
        force_analysis=force_analysis,
        verbose_analysis=verbose_analysis,
        no_symbols=no_symbols,
        gdts=list(gdt),
        program_options_path=program_options,
        gzfs_path=gzfs_path,
        threaded=threaded,
        max_workers=max_workers,
        wait_for_analysis=wait_for_analysis,
        list_project_binaries=list_project_binaries,
        delete_project_binary=delete_project_binary,
        pyghidra_mcp_dir=pyghidra_mcp_dir,
        sym_file_path=sym_file_path,
        symbols_path=symbols_path,
    )

    @mcp.custom_route("/health", ["GET"])
    async def health(_request) -> JSONResponse:
        """Report readiness information for HTTP-based transports."""

        error_info = getattr(mcp, "_pyghidra_context_error", None)
        pyghidra_context = getattr(mcp, "_pyghidra_context", None)

        if error_info is not None:
            detail = (
                error_info.get("message", "PyGhidra context initialization failed.")
                if isinstance(error_info, dict)
                else str(error_info)
            )
            payload = {"status": "error", "detail": detail}
            if isinstance(error_info, dict):
                payload.update(error_info)
            return JSONResponse(payload, status_code=503)

        if pyghidra_context is None:
            return JSONResponse(
                {
                    "status": "error",
                    "detail": "PyGhidra context is not available.",
                },
                status_code=503,
            )

        program_count = len(pyghidra_context.programs)
        analyzed_programs = sum(
            1 for program in pyghidra_context.programs.values() if program.analysis_complete
        )

        payload = {
            "status": "ready",
            "project_name": pyghidra_context.project_name,
            "project_path": str(pyghidra_context.project_path),
            "program_count": program_count,
            "analyzed_programs": analyzed_programs,
        }
        return JSONResponse(payload, status_code=200)

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        elif transport in ["streamable-http", "http"]:
            mcp.run(transport="streamable-http")
        elif transport == "sse":
            mcp.run(transport="sse")
        else:
            raise ValueError(f"Invalid transport: {transport}")
    finally:
        pyghidra_context = getattr(mcp, "_pyghidra_context", None)
        if pyghidra_context is not None:
            pyghidra_context.close()


if __name__ == "__main__":
    main()
