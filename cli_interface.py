import os
import shutil
import sys
import threading
import time
from collections import deque
from pathlib import Path


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    WHITE = "\033[37m"


class ClientCli:
    OPTIONS = (
        ("1", "Dergo mesazh te enkriptuar"),
        ("2", "Dergo mesazh te paenkriptuar"),
        ("3", "Shfaq public key"),
        ("4", "Testo lidhjen me serverin"),
        ("5", "Dil nga aplikacioni"),
    )

    LEVELS = {
        "inactive": ("inactive", Colors.YELLOW),
        "pending": ("pending", Colors.YELLOW),
        "info": ("info", Colors.CYAN),
        "success": ("success", Colors.GREEN),
        "warning": ("warning", Colors.YELLOW),
        "error": ("error", Colors.RED),
    }

    def __init__(self):
        os.system("")
        self.interactive = sys.stdout.isatty()
        self.width = max(64, min(120, shutil.get_terminal_size((100, 20)).columns))
        self.banner = load_ascii_art("ascii_client.txt")
        self.events = deque(maxlen=10)
        self.status = "Duke u lidhur..."
        self.status_level = "pending"
        self.panel_title = None
        self.panel_body = None
        self.colors_enabled = self.interactive and "NO_COLOR" not in os.environ
        self.render()

    def set_status(self, message, level="info"):
        self.status = message
        self.status_level = level
        self.render()

    def update(self, status, status_level, event, event_level="info"):
        self.status = status
        self.status_level = status_level
        self.events.append((event_level, event))
        self.panel_title = None
        self.panel_body = None
        self.render()

    def log(self, message, level="info"):
        self.events.append((level, message))
        self.panel_title = None
        self.panel_body = None
        self.render()

    def divider(self, title):
        self.events.append(("divider", title))
        self.panel_title = None
        self.panel_body = None
        self.render()

    def show_panel(self, title, body):
        self.panel_title = title
        self.panel_body = body
        self.render()

    def prompt(self, message, timeout=None):
        if timeout is not None and self.interactive and os.name == "nt":
            return self.windows_prompt(message, timeout)

        return input(self.paint(f"\n{message}: ", Colors.BOLD)).strip()

    def render(self):
        self.clear()
        print(self.paint(self.banner, Colors.BOLD + self.banner_color()))
        self.section("Status")
        print(f"  {self.badge(self.status_level)} {self.status}")
        print()

        self.section("Commands")
        for key, label in self.OPTIONS:
            print(f"  {self.paint(key + '.', Colors.BOLD + Colors.CYAN)} {label}")
        print()

        self.section("Aktiviteti")

        if self.events:
            for level, message in self.events:
                if level == "divider":
                    self.activity_divider(message)
                    continue

                print(f"  {self.badge(level)} {message}")
        else:
            print(self.paint("  Nuk ka aktivitet ende.", Colors.DIM))

        if self.panel_body:
            print()
            self.section(self.panel_title)
            print(self.panel_body)

    def clear(self):
        if not self.interactive:
            return

        if os.name == "nt":
            os.system("cls")
            return

        print("\033[2J\033[H", end="")

    def section(self, title):
        label = f" {title} "
        side = max(2, (self.width - len(label)) // 2)
        right = max(2, self.width - side - len(label))
        print(self.paint("-" * side + label + "-" * right, Colors.DIM))

    def badge(self, level):
        label, color = self.level(level)
        return self.paint(f"[{label:<7}]", color)

    def activity_divider(self, title):
        print(self.paint(f"  {'-' * 18} {title} {'-' * 18}", Colors.DIM))

    def level_color(self, level):
        return self.level(level)[1]

    def level(self, level):
        return self.LEVELS.get(level, ("info", Colors.WHITE))

    def banner_color(self):
        if self.status_level == "inactive":
            return Colors.YELLOW

        return Colors.CYAN

    def paint(self, text, color):
        if not self.colors_enabled:
            return text

        return f"{color}{text}{Colors.RESET}"

    def windows_prompt(self, message, timeout):
        import msvcrt

        text = []
        deadline = time.monotonic() + timeout
        print(self.paint(f"\n{message}: ", Colors.BOLD), end="", flush=True)

        while time.monotonic() < deadline:
            if not msvcrt.kbhit():
                time.sleep(0.05)
                continue

            char = msvcrt.getwch()

            if char in ("\x00", "\xe0"):
                msvcrt.getwch()
                continue

            if char == "\r":
                print()
                return "".join(text).strip()

            if char == "\003":
                raise KeyboardInterrupt

            if char == "\b":
                if text:
                    text.pop()
                    print("\b \b", end="", flush=True)
                continue

            text.append(char)
            print(char, end="", flush=True)

        print()
        return None