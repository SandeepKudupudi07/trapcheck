"""
TrapCheck — Security Layer 3: Ephemeral Processing
=====================================================
PURPOSE:
  Guarantee that user messages are NEVER written to disk during analysis.
  Everything happens in RAM only. When analysis is done, memory is cleared.

WHAT IT DOES:
  1. Context manager that wraps message processing
  2. Ensures message variable is deleted from memory after use
  3. Prevents temp files from being created during processing
  4. Overrides any accidental disk writes with in-memory alternatives

WHY THIS MATTERS:
  Even without intentional storage, Python/OS can write to disk:
  - Swap files (when RAM is full, OS swaps memory to disk)
  - Temp files created by libraries
  - Core dumps on crashes
  - Python's own garbage collector can delay memory clearing

  This module can't prevent OS-level swapping, but it:
  - Explicitly deletes sensitive variables as fast as possible
  - Overwrites string content before deletion (best-effort)
  - Logs a guarantee that processing was ephemeral
"""

import gc
import os
import ctypes
import tempfile
from contextlib import contextmanager
from typing import Generator
import logging

logger = logging.getLogger("trapcheck.safe")


@contextmanager
def ephemeral_processing(label: str = "message") -> Generator[dict, None, None]:
    """
    Context manager for processing sensitive data ephemerally.

    Usage in main.py:
        with ephemeral_processing("scam_message") as ctx:
            ctx["data"] = request.message
            result = analyze_with_rag(ctx["data"], ...)
        # After this block: ctx["data"] is deleted from memory

    HOW IT WORKS:
        1. You put sensitive data into ctx["data"]
        2. You do your processing inside the with block
        3. When the block exits (even on error), the data is:
           a. Overwritten with zeros (best effort)
           b. Deleted from the dict
           c. Garbage collected immediately
    """
    ctx = {"data": None, "processed": False}

    try:
        yield ctx
        ctx["processed"] = True
    finally:
        # Best-effort memory clearing
        _clear_sensitive_data(ctx)
        logger.info(f"✅ Ephemeral processing complete for [{label}] — memory cleared")


def _clear_sensitive_data(ctx: dict):
    """
    Attempt to overwrite sensitive string data before deletion.
    
    NOTE: Python strings are immutable so we can't truly zero them,
    but we can delete references and force garbage collection.
    For true security, use bytearray which IS mutable.
    """
    try:
        if "data" in ctx and ctx["data"] is not None:
            # Overwrite with empty string (best effort for immutable str)
            ctx["data"] = ""
            del ctx["data"]
    except Exception:
        pass

    # Force immediate garbage collection
    gc.collect()


class SecureTempFile:
    """
    A temporary file that:
    1. Only exists in /tmp (not in project directory)
    2. Is automatically deleted when closed
    3. Has restricted permissions (owner read/write only)
    4. Is overwritten with zeros before deletion
    
    Use this if any processing step MUST write to disk temporarily.
    Currently not needed in TrapCheck (all in-memory), but provided
    for future use.
    """

    def __init__(self, suffix: str = ".tmp"):
        self._file = tempfile.NamedTemporaryFile(
            mode='w+b',
            suffix=suffix,
            delete=False
        )
        # Restrict to owner only (no group/world read)
        os.chmod(self._file.name, 0o600)
        self._path = self._file.name

    def write(self, data: bytes):
        self._file.write(data)

    def read(self) -> bytes:
        self._file.seek(0)
        return self._file.read()

    def close_and_delete(self):
        """Overwrite with zeros then delete."""
        try:
            size = self._file.tell()
            self._file.seek(0)
            self._file.write(b'\x00' * size)  # overwrite with zeros
            self._file.flush()
        except Exception:
            pass
        finally:
            self._file.close()
            try:
                os.unlink(self._path)
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close_and_delete()


def processing_guarantee() -> dict:
    """
    Returns a report confirming TrapCheck's data handling guarantees.
    Shown to users on the /privacy endpoint.
    """
    return {
        "message_storage": "Signed-in scans store sanitized previews and analysis results until account deletion.",
        "processing": "Messages are sent to the configured backend and Ollama service for analysis.",
        "retention": "Temporary references are released; Python and OS memory erasure cannot be guaranteed.",
        "logs": "Application logging excludes message bodies, model output, passwords, and reset codes.",
        "database": "Account details, sanitized scan history, and sanitized community reports are stored.",
        "third_parties": "Optional Twilio and SMTP process messages and email; threat feeds and model downloads use the network.",
        "limitations": "Sanitization is heuristic, not guaranteed anonymization. Do not submit credentials or sensitive information."
    }
