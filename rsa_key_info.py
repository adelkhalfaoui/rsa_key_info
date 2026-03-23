#!/usr/bin/env python3
# rsa_key_info.py — RSA Public Key Analyzer
# Author: adelKhalfaoui (2024) / Redsigned by CodeClaude (2026)
# Usage: python rsa_key_info.py -k <key.pub> [-l] [-m] [-f] [-p] [-a]
# Requires: pip install pyfiglet pycryptodome rich
#This script was inspired by the [Breaking RSA](https://tryhackme.com/room/breakrsa) box from TryHackMe.

import sys, os, argparse, time
from math import isqrt

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import pyfiglet
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import import_key
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.prompt import Prompt, Confirm
from rich import box
from rich.syntax import Syntax
from rich.live import Live
from rich.spinner import Spinner

console = Console(legacy_windows=False)


def print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    for font in ["slant", "big", "standard"]:
        try:
            art = pyfiglet.figlet_format("RSA Key Info", font=font); break
        except Exception:
            art = "RSA Key Info\n"
    console.print(Text(art, style="bold cyan"))
    grid = Table.grid(padding=(0, 2))
    grid.add_column(); grid.add_column()
    grid.add_row(Text("by adelKhalfaoui", style="bold green"),
                 Text("RSA Public Key Analyzer v2.0", style="dim white"))
    console.print(grid)
    console.print(Rule(style="cyan"))
    console.print()


def load_key(path):
    try:
        with open(path) as f:
            return import_key(f.read())
    except FileNotFoundError:
        console.print(Panel(f"[red]File not found:[/red] {path}", title="[red]Error[/red]", border_style="red"))
        sys.exit(1)
    except Exception as e:
        console.print(Panel(f"[red]Failed to parse key:[/red] {e}", title="[red]Error[/red]", border_style="red"))
        sys.exit(1)


def factorize(n, max_iter=1_000_000):
    # Fermat's method — only fast when p and q are close
    if n % 2 == 0:
        return (n // 2, 2, n // 2 - 2)
    a = isqrt(n)
    if a * a == n:
        return (a, a, 0)
    for _ in range(max_iter):
        a += 1
        b_sq = a * a - n
        b = isqrt(b_sq)
        if b * b == b_sq:
            return (a + b, a - b, 2 * b)
    return None


def factorize_with_spinner(n):
    with Live(Spinner("dots", text=Text(" Factorizing...", style="yellow")), console=console, refresh_per_second=12):
        start = time.time()
        result = factorize(n)
        elapsed = time.time() - start
    console.print(f"  [dim]{'Completed' if result else 'Failed (limit reached)'} in {elapsed:.3f}s[/dim]")
    return result


def generate_private_key(p, q, e):
    d = pow(e, -1, (p - 1) * (q - 1))
    return RSA.construct((p * q, e, d, p, q))


def _trunc(v, limit=80):
    s = str(v)
    return s if len(s) <= limit else s[:limit] + f"… [dim]({len(s)} digits)[/dim]"


def show_overview(path, n, e, bits):
    t = Table(title="[bold cyan]RSA Key Overview[/bold cyan]", box=box.ROUNDED,
              border_style="cyan", header_style="bold magenta")
    t.add_column("Property", style="bold yellow", no_wrap=True)
    t.add_column("Value", style="white")
    t.add_row("Key File",       f"[green]{path}[/green]")
    t.add_row("Key Size",       f"[bold]{bits}[/bold] bits")
    t.add_row("Public Exp (e)", str(e))
    t.add_row("Modulus (n)",    _trunc(n))
    console.print(t); console.print()


def show_length(bits):
    c = "green" if bits >= 2048 else "red"
    s = "Strong" if bits >= 2048 else "Weak / Vulnerable"
    console.print(Panel(f"[{c}][bold]{bits} bits[/bold][/{c}]  —  [{c}]{s}[/{c}]",
                        title="[bold cyan]Key Length[/bold cyan]", border_style="cyan", expand=False))
    console.print()


def show_modulus(n):
    s = str(n)
    console.print(Panel(f"[yellow]{s}[/yellow]\n\n[dim]{len(s)} digits  |  {n.bit_length()} bits[/dim]",
                        title="[bold cyan]Modulus (n)[/bold cyan]", border_style="cyan"))
    console.print()


def show_factors(p, q, diff):
    t = Table(title="[bold cyan]Prime Factors[/bold cyan]", box=box.ROUNDED,
              border_style="cyan", header_style="bold magenta")
    t.add_column("Factor", style="bold yellow", no_wrap=True)
    t.add_column("Value",  style="white")
    t.add_column("Digits", style="dim")
    t.add_row("p",    _trunc(p),    str(len(str(p))))
    t.add_row("q",    _trunc(q),    str(len(str(q))))
    t.add_row("diff", _trunc(diff), str(len(str(diff))))
    console.print(t); console.print()


def show_private_key(key_pem):
    console.print(Panel(Syntax(key_pem, "text", theme="monokai", word_wrap=True),
                        title="[bold cyan]Generated Private Key[/bold cyan]", border_style="green"))
    console.print()
    if Confirm.ask("[bold yellow]Save to file?[/bold yellow]"):
        filename = Prompt.ask("[bold green]Filename[/bold green]")
        with open(filename, 'w') as f:
            f.write(key_pem)
        try:
            os.chmod(filename, 0o600)
        except NotImplementedError:
            pass
        console.print(Panel(f"[green]Saved:[/green] [bold]{filename}[/bold]  [dim](600)[/dim]",
                            border_style="green", expand=False))
    console.print()


def main():
    print_banner()

    ap = argparse.ArgumentParser(description="RSA public key analyzer.")
    ap.add_argument("-k", "--key",       required=True,       help="RSA public key file")
    ap.add_argument("-l", "--length",    action="store_true", help="Key length")
    ap.add_argument("-m", "--modulus",   action="store_true", help="Modulus (n)")
    ap.add_argument("-f", "--factorize", action="store_true", help="Factorize n (Fermat)")
    ap.add_argument("-p", "--private",   action="store_true", help="Generate private key")
    ap.add_argument("-a", "--all",       action="store_true", help="Run all")
    args = ap.parse_args()

    if args.all:
        args.length = args.modulus = args.factorize = args.private = True

    key = load_key(args.key)
    n, e, bits = key.n, key.e, key.size_in_bits()
    show_overview(args.key, n, e, bits)

    if args.length:   show_length(bits)
    if args.modulus:  show_modulus(n)

    if args.factorize or args.private:
        result = factorize_with_spinner(n)
        if result is None:
            console.print(Panel("[red]Factorization failed:[/red] p and q are not close enough for Fermat's method.",
                                title="[red]Error[/red]", border_style="red"))
            sys.exit(1)
        p, q, diff = result
        if args.factorize: show_factors(p, q, diff)
        if args.private:   show_private_key(generate_private_key(p, q, e).export_key().decode())

    console.print(Rule("[dim]adelKhalfaoui — RSA Key Info[/dim]", style="dim cyan"))
    console.print()


if __name__ == "__main__":
    main()
