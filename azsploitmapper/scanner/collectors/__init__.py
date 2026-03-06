"""Resource collectors for Azure resource discovery."""

from azsploitmapper.scanner.collectors.base import BaseCollector
from azsploitmapper.scanner.collectors.compute import ComputeCollector
from azsploitmapper.scanner.collectors.identity import IdentityCollector
from azsploitmapper.scanner.collectors.keyvault import KeyVaultCollector
from azsploitmapper.scanner.collectors.network import NetworkCollector
from azsploitmapper.scanner.collectors.storage import StorageCollector

__all__ = [
    "BaseCollector",
    "ComputeCollector",
    "IdentityCollector",
    "KeyVaultCollector",
    "NetworkCollector",
    "StorageCollector",
]
