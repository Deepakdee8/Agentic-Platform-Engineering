"""
Base interface for deterministic GCP remediation tools.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple


class BaseRemediationTool(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the tool."""
        pass

    @abstractmethod
    def execute(self, parameters: Dict[str, Any], simulate: bool = True) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Executes the remediation.
        Returns: (success: bool, message: str, execution_metadata: dict)
        """
        pass

    @abstractmethod
    def rollback(self, snapshot_state: Dict[str, Any], simulate: bool = True) -> Tuple[bool, str]:
        """
        Rolls back the change using the preserved state snapshot.
        Returns: (success: bool, message: str)
        """
        pass

    @abstractmethod
    def validate_compliance(self, resource_id: str, current_state: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Verifies if the resource is compliant after execution.
        Returns: (is_compliant: bool, evidence_details: str)
        """
        pass
