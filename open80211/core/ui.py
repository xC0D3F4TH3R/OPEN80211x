"""
UI helpers built on `rich`.
Provides the visual language of the whole suite: banners, menus,
tables, prompts, log levels, and live views.
"""
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()
err_console = Console(stderr=True)

from open80211 import __version__


# --------------------------------------------------------------------------
# Banner & section headers
# --------------------------------------------------------------------------

def banner() -> None:
    """Print the suite banner."""
    title = Text()
    title.append("   ___                 ______ ____  ____ _  ___   ____  \n", style="cyan")
    title.append("  / _ \\___  ____  __  / __/ // / _ )/ __ ) |/ ( ) / / /__\n", style="cyan")
    title.append(" / // / _ \\/ __/ |/_/ _\\ \\/ _  / _  | / _ /    /| / / _ \\\n", style="cyan")
    title.append("/____/\\___/\\__/  _>_</___/_/ /_/ ____/_/ \\_/___ |_/_//_/\n", style="cyan")
    title.append("                          |___/  WIRELESS PENTEST SUITE\n", style="bright_yellow")
    panel = Panel(
        Group(
            title,
            Text(f"  Advanced Wireless Penetration Testing Suite  v{__version__}\n"
                 "  Recon  |  Capture  |  Attacks  |  MITM  |  Evil AP  |  Analysis",
                 style="dim"),
        ),
        box=box.ROUNDED,
        border_style="bright_blue",
        padding=(1, 2),
    )
    console.print(panel)


def section(title: str, sub: str = "") -> None:
    """Print a section header rule."""
    label = f" [bold cyan]{title}[/bold cyan]"
    if sub:
        label += f" [dim]- {sub}[/dim]"
    console.print(Rule(label, style="bright_blue", align="left"))


def disclaimer(force: bool = False) -> None:
    """Show the ethical use disclaimer. Returns immediately; main handles the prompt."""
    console.print(Panel(
        "[yellow]AUTHORIZED USE ONLY[/yellow]\n"
        "This suite is for security research and penetration testing on networks\n"
        "that you OWN or have EXPLICIT written permission to test.\n"
        "Unauthorized use may violate local and international laws.",
        box=box.DOUBLE,
        border_style="yellow",
        title="[bold red]DISCLAIMER[/bold red]",
    ))


# --------------------------------------------------------------------------
# Log levels
# --------------------------------------------------------------------------

def info(msg: Any) -> None:
    console.print(f"[bold cyan][*][/bold cyan] {msg}")


def ok(msg: Any) -> None:
    console.print(f"[bold green][+][/bold green] {msg}")


def warn(msg: Any) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def error(msg: Any) -> None:
    err_console.print(f"[bold red][x][/bold red] {msg}")


def debug(msg: Any) -> None:
    if "--debug" in sys.argv:
        console.print(f"[dim][~][/dim] {msg}")


# --------------------------------------------------------------------------
# Prompts
# --------------------------------------------------------------------------

def ask(prompt: str, default: str = "", password: bool = False) -> str:
    return Prompt.ask(prompt, default=default, password=password)


def ask_int(prompt: str, default: Optional[int] = None) -> int:
    return IntPrompt.ask(prompt, default=default)


def confirm(prompt: str, default: bool = True) -> bool:
    return Confirm.ask(prompt, default=default)


def press_enter(msg: str = "Press Enter to continue...") -> None:
    console.input(f"[dim]{msg}[/dim]")


def menu(title: str, options: List[str], footer: str = "q) Quit / back") -> int:
    """
    Interactive selection menu. Returns the 1-based index of the choice
    or 0 for Quit/back. Rendering happens before the prompt.
    """
    table = Table(title=f"[bold]{title}[/bold]", box=box.SIMPLE_HEAD,
                  border_style="cyan", show_header=False, pad_edge=False)
    for i, opt in enumerate(options, 1):
        table.add_row(f"[cyan]{i:>2}[/cyan]", f"{opt}")
    table.add_row(f"[dim]{'  '}[/dim]", f"[dim]{footer}[/dim]")
    console.print(table)
    while True:
        raw = Prompt.ask("  > ").strip().lower()
        if raw in ("q", "quit", "back", "exit", "0", ""):
            return 0
        if raw.isdigit():
            n = int(raw)
            if 1 <= n <= len(options):
                return n
        console.print("[red]Invalid choice.[/red]")


# --------------------------------------------------------------------------
# Tables
# --------------------------------------------------------------------------

def show_table(title: str, columns: List[str], rows: List[list],
               highlight_first: bool = False) -> None:
    t = Table(title=title, box=box.ROUNDED, border_style="bright_blue",
              header_style="bold cyan")
    for c in columns:
        t.add_column(c)
    for row in rows:
        t.add_row(*[str(x) for x in row])
    console.print(t)


# --------------------------------------------------------------------------
# Live / progress helpers
# --------------------------------------------------------------------------

class LiveStatus:
    """Context-managed rich.Live wrapper to show updating panels from a thread."""

    def __init__(self, render: Callable[[], Any], refresh: float = 0.25):
        self._render = render
        self._live = Live(self._render(), console=console, refresh_per_second=1 / refresh,
                          transient=False)

    def __enter__(self) -> "LiveStatus":
        self._live.__enter__()
        return self

    def update(self) -> None:
        self._live.update(self._render())

    def __exit__(self, *args) -> None:
        self._live.__exit__(*args)


def spinner(msg: str, work: Callable[[], Any], success: str = "") -> Any:
    """Run `work()` while showing an indeterminate spinner."""
    from rich.progress import Progress, SpinnerColumn, TextColumn
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as prog:
        task = prog.add_task(msg, total=None)
        try:
            result = work()
        finally:
            prog.update(task, completed=1)
    if success:
        ok(success)
    return result


# --------------------------------------------------------------------------
# Professional workflow helpers
# --------------------------------------------------------------------------

def clipboard(text: str, label: str = "value") -> None:
    """Copy text to the OS clipboard; works on Linux + Windows."""
    try:
        import subprocess
        if sys.platform.startswith("linux"):
            for tool in ("xclip", "xsel", "wl-copy"):
                try:
                    subprocess.run([tool, "-i"] if tool == "wl-copy" else [tool],
                                   input=text.encode(), timeout=3,
                                   capture_output=True)
                    ok(f"{label} copied to clipboard")
                    return
                except Exception:
                    continue
            warn("Clipboard tool not found (install xclip/xsel/wl-copy).")
        else:
            subprocess.run(["clip"], input=text.encode(), check=True, timeout=3)
            ok(f"{label} copied to clipboard")
    except Exception:
        warn("Clipboard copy failed.")


def confirm_note_default(default: str, prompt: str = "Note to self") -> str:
    """Quick note-taking with sensible default."""
    return ask(prompt, default=default)


def header_line(text: str) -> None:
    console.print(f"[bold bright_blue]▸[/bold bright_blue] {text}", highlight=False)


def live_hud(panels: List[Any], refresh: float = 0.5) -> "LiveStatus":
    """Open a multi-panel live HUD. Returns LiveStatus; caller updates."""
    from rich.console import Group
    return LiveStatus(lambda: Group(*panels), refresh)


def pick_from_list(title: str, items: List[str], prompt: str = "Select") -> int:
    """
    Numbered picker that returns 1-based index (0 = cancel). Render-first.
    """
    table = Table(title=f"[bold]{title}[/bold]", box=box.SIMPLE_HEAD,
                  border_style="cyan", show_header=False, pad_edge=False)
    for i, item in enumerate(items, 1):
        table.add_row(f"[cyan]{i:>2}[/cyan]", str(item))
    table.add_row(f"[dim]{'  '}[/dim]", "[dim]0) Cancel[/dim]")
    console.print(table)
    while True:
        raw = Prompt.ask(f"  {prompt} ").strip().lower()
        if raw in ("0", "q", ""):
            return 0
        if raw.isdigit() and 1 <= int(raw) <= len(items):
            return int(raw)
        console.print("[red]Invalid choice.[/red]")