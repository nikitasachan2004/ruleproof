"""Base engine interface for execution against EVTX forensic artifacts."""

from abc import ABC, abstractmethod
from pathlib import Path


class EngineError(Exception):
    """Raised when an engine subprocess command fails or returns malformed output."""

    def __init__(self, message: str, returncode: int | None = None, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class BaseEngine(ABC):
    """Abstract interface for detection hunting engines."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the detection engine."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Version of the detection engine."""
        ...

    @abstractmethod
    def hunt(
        self,
        sample_path: Path,
        rules_path: Path,
    ) -> list[str]:
        """Execute rules against a sample and return a list of fired rule IDs.

        Security reasoning: Implementations must execute engines via subprocess argument
        lists without shell=True to prevent shell command injection.
        """
        ...

    @abstractmethod
    def get_sample_telemetry(self, sample_path: Path) -> dict[str, set[int]]:
        """Extract present Windows event channels and their associated Event IDs.

        Returns a dictionary mapping channel names to sets of present EventIDs.
        """
        ...
