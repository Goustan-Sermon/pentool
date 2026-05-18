"""Console Rich partagée et helpers de logging."""

from rich.console import Console
from rich.theme import Theme

_theme = Theme(
    {
        "info":     "bold cyan",
        "success":  "bold green",
        "warning":  "bold yellow",
        "danger":   "bold red",
        "muted":    "dim white",
        "section":  "bold white",
        "critical": "bold white on red",
        "high":     "bold red",
        "medium":   "bold yellow",
        "low":      "bold green",
    }
)

console = Console(theme=_theme, highlight=False)


def section(title: str) -> None:
    console.rule(f"[section]{title}[/section]", style="cyan")


def info(msg: str) -> None:
    console.print(f"[info]ℹ[/info]  {msg}")


def success(msg: str) -> None:
    console.print(f"[success]✔[/success]  {msg}")


def warning(msg: str) -> None:
    console.print(f"[warning]⚠[/warning]  {msg}")


def error(msg: str) -> None:
    console.print(f"[danger]✘[/danger]  {msg}")