"""Ecosystem strategy registry. Import to trigger sub-module registration.

Concrete strategies register via @register("name") decorator on their class.
Selection is `for_ecosystem(name)` which raises UnknownEcosystem on miss —
no default, no fallback. Provision fails loud on unregistered ecosystems
rather than proceeding with silent gaps in attestation.
"""
from __future__ import annotations

from typing import Type

from .base import EcosystemStrategy, UnknownEcosystem, EcosystemScopeExceeded


_REGISTRY: dict[str, Type[EcosystemStrategy]] = {}


def register(name: str):
    """Decorator: bind a strategy class to an ecosystem name (case-folded)."""
    def _wrap(cls: Type[EcosystemStrategy]) -> Type[EcosystemStrategy]:
        key = name.strip().lower()
        if not key:
            raise ValueError("ecosystem name must be non-empty")
        if key in _REGISTRY and _REGISTRY[key] is not cls:
            raise ValueError(f"ecosystem {key!r} already registered to "
                             f"{_REGISTRY[key].__name__}, cannot re-register "
                             f"to {cls.__name__}")
        cls.name = key
        _REGISTRY[key] = cls
        return cls
    return _wrap


def for_ecosystem(name: str) -> EcosystemStrategy:
    """Return a strategy instance for the given ecosystem name (case-insensitive).
    Raises UnknownEcosystem if not registered — caller MUST fail loud."""
    key = (name or "").strip().lower()
    cls = _REGISTRY.get(key)
    if cls is None:
        raise UnknownEcosystem(
            f"no strategy registered for ecosystem {name!r}. "
            f"registered: {sorted(_REGISTRY.keys())}. "
            f"Add patchwing/ecosystems/{key}.py to support this target.")
    return cls()


def registered_names() -> list[str]:
    """List all registered ecosystem names. For diagnostics."""
    return sorted(_REGISTRY.keys())


# Trigger sub-module registration on package import.
# Each concrete strategy module (npm.py, pypi.py, ...) uses @register on its
# class; importing the module runs that decorator.
try:
    from . import npm  # noqa: F401 — side-effect import registers NpmStrategy
except Exception:
    # Missing/broken strategy modules must not break the package import.
    # for_ecosystem() will raise UnknownEcosystem cleanly if npm is needed.
    pass


__all__ = ["EcosystemStrategy", "UnknownEcosystem", "EcosystemScopeExceeded",
           "register", "for_ecosystem", "registered_names"]
