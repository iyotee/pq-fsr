"""
RUST WRAPPER: Python Compatibility Layer for Rust Implementation
================================================================

This module provides a Python-compatible API that wraps the Rust implementation.
It ensures backward compatibility with existing code while using the high-performance Rust core.

NOTE: This wrapper now uses Rust for ALL operations. No fallback to _legacy.
"""

from typing import Dict, Any, Optional

try:
    from pqfsr_core import (
        RatchetSessionPy,
        RatchetModePy,
        PacketPy,
        HandshakeRequestPy,
        HandshakeResponsePy,
        DilithiumSignatures,
    )
    _RUST_AVAILABLE = True
except ImportError:
    _RUST_AVAILABLE = False
    RatchetSessionPy = None
    RatchetModePy = None
    PacketPy = None
    HandshakeRequestPy = None
    HandshakeResponsePy = None
    DilithiumSignatures = None


# Removed _python_dict_to_pyany - PyO3 from_dict can handle Python dicts directly


class RatchetSession:
    """
    Python-compatible wrapper for Rust RatchetSessionPy.

    This class provides the same API as the legacy Python implementation
    but uses the Rust core for all operations.
    """

    def __init__(
        self,
        *,
        is_initiator: bool,
        semantic_hint: bytes,
        max_skip: int = 50,
        random_bytes=None,  # Ignored in Rust implementation
        kem=None,  # Ignored in Rust implementation
        cipher=None,  # Ignored in Rust implementation
        strategy=None,  # Ignored in Rust implementation
    ):
        if not _RUST_AVAILABLE:
            raise ImportError(
                "Rust implementation not available. "
                "Please install: cd pqfsr_core && maturin develop"
            )

        self._rust_session = RatchetSessionPy(
            is_initiator,
            list(semantic_hint),
            max_skip if max_skip != 50 else None
        )
        self.is_initiator = is_initiator
        self._semantic_hint = semantic_hint

    @classmethod
    def create_initiator(cls, **kwargs):
        return cls(is_initiator=True, **kwargs)

    @classmethod
    def create_responder(cls, **kwargs):
        return cls(is_initiator=False, **kwargs)

    def create_handshake_request(self) -> Dict[str, Any]:
        """
        Create a handshake request (initiator only).
        
        Returns:
            Dict containing handshake request fields (version, min_version, max_version,
            handshake_id, kem_public, ratchet_public, semantic_digest, signature, signature_public_key)
        
        Raises:
            ValueError: If session is not an initiator
            RuntimeError: If Rust session creation fails
        """
        if not self.is_initiator:
            raise ValueError("Only initiators can create handshake requests")
        
        try:
            req = self._rust_session.create_handshake_request()
        except Exception as e:
            raise RuntimeError(f"Failed to create handshake request: {e}") from e
        
        # Use to_dict_auto which handles GIL internally
        try:
            req_dict_obj = req.to_dict_auto()
        except Exception as e:
            raise RuntimeError(f"Failed to convert handshake request to dict: {e}") from e
        
        # Convert PyObject to Python dict with proper error handling
        if not hasattr(req_dict_obj, '__iter__'):
            raise RuntimeError("Handshake request dict conversion failed: not iterable")
        
        req_dict = dict(req_dict_obj)
        
        # Convert list values to bytes where appropriate with validation
        result = {}
        for k, v in req_dict.items():
            if isinstance(v, (list, tuple)):
                # Validate all elements are integers in byte range
                try:
                    if all(isinstance(x, int) and 0 <= x <= 255 for x in v):
                        result[k] = bytes(v)
                    else:
                        result[k] = list(v)
                except (TypeError, ValueError):
                    result[k] = list(v)
            else:
                result[k] = v
        
        # Validate required fields
        required_fields = ['version', 'min_version', 'max_version', 'handshake_id', 
                         'kem_public', 'ratchet_public', 'semantic_digest']
        for field in required_fields:
            if field not in result:
                raise RuntimeError(f"Handshake request missing required field: {field}")
        
        return result

    def accept_handshake(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Accept a handshake request (responder only).
        
        Args:
            request: Dict containing handshake request fields
        
        Returns:
            Dict containing handshake response fields (version, handshake_id, kem_ciphertext,
            ratchet_public, semantic_digest, signature, signature_public_key)
        
        Raises:
            ValueError: If session is not a responder or request is invalid
            RuntimeError: If handshake acceptance fails
        """
        if self.is_initiator:
            raise ValueError("Only responders can accept handshake requests")
        
        if not isinstance(request, dict):
            raise ValueError(f"Request must be a dict, got {type(request)}")
        
        # Validate required fields
        required_fields = ['version', 'min_version', 'max_version', 'handshake_id',
                         'kem_public', 'ratchet_public', 'semantic_digest']
        for field in required_fields:
            if field not in request:
                raise ValueError(f"Handshake request missing required field: {field}")
        
        # Convert Python dict to HandshakeRequestPy using from_dict
        try:
            req_py = HandshakeRequestPy.from_dict(request)
        except Exception as e:
            raise ValueError(f"Invalid handshake request format: {e}") from e
        
        try:
            resp = self._rust_session.accept_handshake(req_py)
        except Exception as e:
            raise RuntimeError(f"Failed to accept handshake: {e}") from e

        # Convert response to Python dict using to_dict_auto
        try:
            resp_dict_obj = resp.to_dict_auto()
        except Exception as e:
            raise RuntimeError(f"Failed to convert handshake response to dict: {e}") from e
        
        if not hasattr(resp_dict_obj, '__iter__'):
            raise RuntimeError("Handshake response dict conversion failed: not iterable")
        
        resp_dict = dict(resp_dict_obj)
        
        # Convert list values to bytes with validation
        result = {}
        for k, v in resp_dict.items():
            if isinstance(v, (list, tuple)):
                try:
                    if all(isinstance(x, int) and 0 <= x <= 255 for x in v):
                        result[k] = bytes(v)
                    else:
                        result[k] = list(v)
                except (TypeError, ValueError):
                    result[k] = list(v)
            else:
                result[k] = v
        
        # Validate required response fields
        required_response_fields = ['version', 'handshake_id', 'kem_ciphertext',
                                   'ratchet_public', 'semantic_digest']
        for field in required_response_fields:
            if field not in result:
                raise RuntimeError(f"Handshake response missing required field: {field}")
        
        return result

    def finalize_handshake(self, response: Dict[str, Any]) -> None:
        """
        Finalize handshake (initiator only).
        
        Args:
            response: Dict containing handshake response fields
        
        Raises:
            ValueError: If session is not an initiator or response is invalid
            RuntimeError: If handshake finalization fails
        """
        if not self.is_initiator:
            raise ValueError("Only initiators can finalize handshake")
        
        if not isinstance(response, dict):
            raise ValueError(f"Response must be a dict, got {type(response)}")
        
        # Validate required fields
        required_fields = ['version', 'handshake_id', 'kem_ciphertext',
                          'ratchet_public', 'semantic_digest']
        for field in required_fields:
            if field not in response:
                raise ValueError(f"Handshake response missing required field: {field}")
        
        # Convert Python dict to HandshakeResponsePy using from_dict
        try:
            resp_py = HandshakeResponsePy.from_dict(response)
        except Exception as e:
            raise ValueError(f"Invalid handshake response format: {e}") from e
        
        try:
            self._rust_session.finalize_handshake(resp_py)
        except Exception as e:
            raise RuntimeError(f"Failed to finalize handshake: {e}") from e

    @property
    def is_ready(self) -> bool:
        """Check if session is ready for messaging."""
        return self._rust_session.is_ready()
    
    def get_combined_digest(self, remote_digest: bytes) -> bytes:
        """Get combined digest (for testing)."""
        return bytes(self._rust_session.get_combined_digest(list(remote_digest)))

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> Dict[str, Any]:
        """
        Encrypt a message.
        
        Args:
            plaintext: Message to encrypt (bytes)
            associated_data: Optional associated data (bytes, default: empty)
        
        Returns:
            Dict containing encrypted packet with 'header' and 'ciphertext' fields
        
        Raises:
            ValueError: If session is not ready or plaintext is invalid
            RuntimeError: If encryption fails
        """
        if not self.is_ready:
            raise ValueError("Session not ready for encryption. Complete handshake first.")
        
        if not isinstance(plaintext, bytes):
            raise ValueError(f"Plaintext must be bytes, got {type(plaintext)}")
        
        if not isinstance(associated_data, bytes):
            raise ValueError(f"Associated data must be bytes, got {type(associated_data)}")
        
        try:
            packet = self._rust_session.encrypt(
                list(plaintext),
                list(associated_data) if associated_data else None
            )
        except Exception as e:
            raise RuntimeError(f"Encryption failed: {e}") from e
        
        # Use to_dict_auto which handles GIL internally
        try:
            packet_dict_obj = packet.to_dict_auto()
        except Exception as e:
            raise RuntimeError(f"Failed to convert packet to dict: {e}") from e
        
        if not hasattr(packet_dict_obj, '__iter__'):
            raise RuntimeError("Packet dict conversion failed: not iterable")
        
        packet_dict = dict(packet_dict_obj)
        
        # Convert to Python dict and handle bytes with validation
        result = {}
        for k, v in packet_dict.items():
            if k == "header" and isinstance(v, dict):
                header = {}
                for hk, hv in v.items():
                    if isinstance(hv, (list, tuple)):
                        try:
                            if all(isinstance(x, int) and 0 <= x <= 255 for x in hv):
                                header[hk] = bytes(hv)
                            else:
                                header[hk] = hv
                        except (TypeError, ValueError):
                            header[hk] = hv
                    else:
                        header[hk] = hv
                result[k] = header
            elif isinstance(v, (list, tuple)):
                try:
                    if all(isinstance(x, int) and 0 <= x <= 255 for x in v):
                        result[k] = bytes(v)
                    else:
                        result[k] = list(v)
                except (TypeError, ValueError):
                    result[k] = list(v)
            else:
                result[k] = v
        
        # Validate packet structure
        if 'header' not in result or 'ciphertext' not in result:
            raise RuntimeError("Invalid packet structure: missing header or ciphertext")
        
        return result

    def decrypt(self, packet: Dict[str, Any], associated_data: bytes = b"") -> bytes:
        """
        Decrypt a message.
        
        Args:
            packet: Dict containing encrypted packet with 'header' and 'ciphertext' fields
            associated_data: Optional associated data (bytes, default: empty)
        
        Returns:
            Decrypted plaintext as bytes
        
        Raises:
            ValueError: If session is not ready, packet is invalid, or decryption fails
            RuntimeError: If decryption operation fails
        """
        if not self.is_ready:
            raise ValueError("Session not ready for decryption. Complete handshake first.")
        
        if not isinstance(packet, dict):
            raise ValueError(f"Packet must be a dict, got {type(packet)}")
        
        if 'header' not in packet or 'ciphertext' not in packet:
            raise ValueError("Invalid packet structure: missing 'header' or 'ciphertext' field")
        
        if not isinstance(associated_data, bytes):
            raise ValueError(f"Associated data must be bytes, got {type(associated_data)}")
        
        # Convert Python dict to PacketPy using from_dict
        try:
            packet_py = PacketPy.from_dict(packet)
        except Exception as e:
            raise ValueError(f"Invalid packet format: {e}") from e
        
        try:
            plaintext = self._rust_session.decrypt(
                packet_py,
                list(associated_data) if associated_data else None
            )
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}") from e
        
        return bytes(plaintext)

    def pack_packet(self, packet: Dict[str, Any]) -> bytes:
        """
        Pack a packet into binary format.
        
        Args:
            packet: Dict containing packet with 'header' and 'ciphertext' fields
        
        Returns:
            Packed packet as bytes
        
        Raises:
            ValueError: If packet is invalid
            RuntimeError: If packing fails
        """
        if not isinstance(packet, dict):
            raise ValueError(f"Packet must be a dict, got {type(packet)}")
        
        if 'header' not in packet or 'ciphertext' not in packet:
            raise ValueError("Invalid packet structure: missing 'header' or 'ciphertext' field")
        
        try:
            packet_py = PacketPy.from_dict(packet)
        except Exception as e:
            raise ValueError(f"Invalid packet format: {e}") from e
        
        try:
            return bytes(packet_py.pack())
        except Exception as e:
            raise RuntimeError(f"Packing failed: {e}") from e

    def unpack_packet(self, data: bytes) -> Dict[str, Any]:
        """
        Unpack a binary packet.
        
        Args:
            data: Packed packet as bytes
        
        Returns:
            Dict containing unpacked packet with 'header' and 'ciphertext' fields
        
        Raises:
            ValueError: If data is invalid or unpacking fails
            RuntimeError: If unpacking operation fails
        """
        if not isinstance(data, bytes):
            raise ValueError(f"Data must be bytes, got {type(data)}")
        
        if len(data) == 0:
            raise ValueError("Cannot unpack empty data")
        
        try:
            packet_py = PacketPy.unpack(list(data))
        except Exception as e:
            raise ValueError(f"Unpacking failed: {e}") from e

        # Convert to Python dict using to_dict_auto
        try:
            packet_dict_obj = packet_py.to_dict_auto()
        except Exception as e:
            raise RuntimeError(f"Failed to convert unpacked packet to dict: {e}") from e
        
        if not hasattr(packet_dict_obj, '__iter__'):
            raise RuntimeError("Unpacked packet dict conversion failed: not iterable")
        
        packet_dict = dict(packet_dict_obj)
        
        # Convert PyDict to Python dict with validation
        result = {}
        for k, v in packet_dict.items():
            if isinstance(v, dict):
                result[k] = v
            elif isinstance(v, (list, tuple)):
                # Convert list of ints back to bytes if applicable
                try:
                    if all(isinstance(x, int) and 0 <= x <= 255 for x in v):
                        result[k] = bytes(v)
                    else:
                        result[k] = list(v)
                except (TypeError, ValueError):
                    result[k] = list(v)
            else:
                result[k] = v
        
        # Validate unpacked packet structure
        if 'header' not in result or 'ciphertext' not in result:
            raise RuntimeError("Invalid unpacked packet structure: missing header or ciphertext")
        
        return result

    def export_state(self, use_cbor: bool = True) -> bytes:
        """
        Export session state.
        
        Args:
            use_cbor: If True (default), use CBOR format (production, more compact).
                     If False, use JSON format (debug/backward compatibility).
        
        Returns:
            Serialized state as bytes (CBOR or JSON format)
        """
        state_bytes = self._rust_session.export_state(use_cbor)
        return bytes(state_bytes)
    
    def _get_state_dict(self):
        """Get state as dict for testing purposes."""
        import json
        
        # Always use JSON for _get_state_dict to maintain compatibility with tests
        # Tests that need state dict should use JSON format
        state_bytes = self.export_state(use_cbor=False)
        
        # JSON format
        return json.loads(state_bytes.decode('utf-8'))
    
    @property
    def _state(self):
        """Access internal state for testing (compatibility)."""
        class StateProxy:
            def __init__(self, wrapper):
                self._wrapper = wrapper
                self._data = None
            
            def _load(self):
                if self._data is None:
                    self._data = self._wrapper._get_state_dict()['data']
            
            @property
            def skipped_message_keys(self):
                self._load()
                # Convert from [(idx, key_hex, nonce_hex), ...] to dict
                result = {}
                for item in self._data.get('skipped_keys', []):
                    idx = item[0] if isinstance(item[0], int) else int(item[0], 16)
                    key = bytes.fromhex(item[1])
                    nonce = bytes.fromhex(item[2])
                    result[idx] = (key, nonce)
                return result
            
            @property
            def root_key(self):
                self._load()
                return bytes.fromhex(self._data['root_key'])
            
            @property
            def send_chain_key(self):
                self._load()
                return bytes.fromhex(self._data['send_chain_key'])
            
            @property
            def recv_chain_key(self):
                self._load()
                return bytes.fromhex(self._data['recv_chain_key'])
            
            @property
            def send_count(self):
                self._load()
                return self._data['send_count']
            
            @property
            def recv_count(self):
                self._load()
                return self._data['recv_count']
            
            @property
            def combined_digest(self):
                self._load()
                return bytes.fromhex(self._data['combined_digest'])
            
            @property
            def local_ratchet_public(self):
                self._load()
                return bytes.fromhex(self._data['local_ratchet_public'])
            
            @property
            def remote_ratchet_public(self):
                self._load()
                rp = self._data.get('remote_ratchet_public')
                return bytes.fromhex(rp) if rp else None
            
            @property
            def local_digest(self):
                self._load()
                return bytes.fromhex(self._data['local_digest'])
            
            @property
            def remote_digest(self):
                self._load()
                rd = self._data.get('remote_digest')
                return bytes.fromhex(rd) if rd else None
            
            @property
            def max_skip(self):
                self._load()
                return self._data['max_skip']
        
        return StateProxy(self)

    @classmethod
    def from_serialized(cls, blob: bytes, **kwargs):
        """
        Load session from serialized state.
        
        Args:
            blob: Serialized state as bytes (CBOR or JSON format)
            **kwargs: Additional arguments (ignored for compatibility)
        
        Returns:
            RatchetSession instance restored from serialized state
        
        Raises:
            ValueError: If blob is invalid or deserialization fails
            RuntimeError: If session restoration fails
        """
        if not isinstance(blob, bytes):
            raise ValueError(f"Blob must be bytes, got {type(blob)}")
        
        if len(blob) == 0:
            raise ValueError("Cannot deserialize empty blob")
        
        try:
            session = RatchetSessionPy.from_serialized(list(blob))
        except Exception as e:
            raise ValueError(f"Deserialization failed: {e}") from e
        
        wrapper = cls.__new__(cls)
        wrapper._rust_session = session
        
        # Use PyO3 methods instead of accessing inner
        try:
            wrapper.is_initiator = session.is_initiator()
            wrapper._semantic_hint = bytes(session.semantic_hint())
        except Exception as e:
            raise RuntimeError(f"Failed to restore session properties: {e}") from e
        
        return wrapper


# Re-export RatchetMode for compatibility
class RatchetMode:
    """Python-compatible RatchetMode enum."""
    MAXIMUM_SECURITY = "MAXIMUM_SECURITY"
    BALANCED_FLOW = "BALANCED_FLOW"
    MINIMAL_OVERHEAD = "MINIMAL_OVERHEAD"

    @staticmethod
    def from_string(mode_str: str):
        """Create RatchetMode from string."""
        if _RUST_AVAILABLE:
            return RatchetModePy.new(mode_str)
        else:
            return mode_str

