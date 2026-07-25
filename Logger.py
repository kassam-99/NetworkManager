"""
Logger module for the NetworkManager toolkit.

Provides the :class:`Logs` helper used throughout the project to print
coloured messages to the terminal while simultaneously writing a plain-text
(ANSI-stripped) copy to a rotating log file.

Public API (kept intentionally small, this is what the rest of the code uses):

    logs = Logs()
    logs.LogEngine("NetworkManager_Logs", "Wifi_Manager")
    logs.print_and_log("[+] hello")
    logs.print_and_log("[!] something went wrong", message_type="ERROR")
"""

import logging
import os
import re

# Matches ANSI colour / style escape sequences so they can be stripped
# before writing to the log file (the terminal keeps the colours).
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


class Logs:
    """Small console + file logger used across the toolkit."""

    def __init__(self):
        self.logger = None
        self.log_name = "NetworkManager_Logs"
        self.component = "Main"

    def LogEngine(self, log_name="NetworkManager_Logs", component="Main", log_dir="logs"):
        """
        Initialise (or reuse) a logger that writes to ``log_dir/<log_name>.log``.

        Args:
            log_name: Base name of the log file.
            component: Sub-component name, included in each log record.
            log_dir: Directory to store log files (created if missing).

        Returns:
            The configured :class:`logging.Logger` instance.
        """
        self.log_name = log_name
        self.component = component

        try:
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, f"{log_name}.log")
        except OSError:
            # Fall back to the current directory if log_dir is not writable.
            log_path = f"{log_name}.log"

        self.logger = logging.getLogger(f"{log_name}.{component}")
        self.logger.setLevel(logging.DEBUG)

        # Avoid attaching duplicate handlers if LogEngine is called twice.
        if not self.logger.handlers:
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )
            try:
                file_handler = logging.FileHandler(log_path, encoding="utf-8")
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except OSError:
                # If we cannot open the file, logging to console still works.
                pass

        return self.logger

    def print_and_log(self, message, message_type="INFO"):
        """
        Print ``message`` to stdout (with any ANSI colours intact) and record a
        cleaned copy in the log file.

        Args:
            message: The message to display and log.
            message_type: One of INFO, WARNING, ERROR (case-insensitive).
                          Unknown values default to INFO.
        """
        print(message)

        if self.logger is None:
            # Lazily initialise so the class is usable even without LogEngine.
            self.LogEngine(self.log_name, self.component)

        clean_message = _ANSI_ESCAPE.sub("", str(message))
        level = getattr(logging, str(message_type).upper(), logging.INFO)
        if not isinstance(level, int):
            level = logging.INFO
        self.logger.log(level, clean_message)
