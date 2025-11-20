"""
PQ-FSR: Post-Quantum Forward-Secret Ratchet
============================================

This is the Python interface to the PQ-FSR Rust implementation.
The Rust core provides all cryptographic operations for maximum performance.

IMPORTANT: This module uses the Rust implementation (pqfsr_core) as the primary backend.
No fallback - Rust is required.
"""

try:
    # Import Rust implementation (required)
    from .rust_wrapper import RatchetSession, RatchetMode
    try:
        from pqfsr_core import NuclearReactor, DilithiumSignatures
    except ImportError:
        NuclearReactor = None
        DilithiumSignatures = None
    
    # Re-export for compatibility
    __all__ = [
        "RatchetSession",
        "RatchetMode",
    ]
    if NuclearReactor is not None:
        __all__.append("NuclearReactor")
    if DilithiumSignatures is not None:
        __all__.append("DilithiumSignatures")
    
    _RUST_AVAILABLE = True
except ImportError as e:
    raise ImportError(
        f"Rust implementation (pqfsr_core) not available: {e}. "
        "Please install: cd pqfsr_core && maturin develop"
    ) from e

