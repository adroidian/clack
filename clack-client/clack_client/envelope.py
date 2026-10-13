"""Opaque transport validation for Clack E2EE envelopes.

The relay imports this module only to enforce exact shape/version/size. Crypto
and private keys remain owner-side in :mod:`clack_client.e2ee`.

Provenance (candidate-679-py-federation-v1): this file is the byte-verified
``clack-client/clack_client/envelope.py`` from custody tree 171f96 (v1+v2
native envelope validation), extended ONLY with ``validate_message_context``
copied verbatim from custody tree 3998354 (canonical topic/reply semantics).
No other bytes changed.
"""
import re
import uuid

from .e2ee import (
    ENC_ALG,
    ENC_ALG_V2,
    ENC_VERSION,
    ENC_VERSION_V2,
    serialize_envelope,
    validate_envelope,
)

_V1_FIELDS = {"v", "alg", "eph", "nonce", "kid", "ct"}
_V2_FIELDS = {"v", "alg", "eph", "nonce", "kid", "skid", "ctx", "ct", "sig"}
_SUPPORTED = {
    ENC_VERSION: (ENC_ALG, _V1_FIELDS),
    ENC_VERSION_V2: (ENC_ALG_V2, _V2_FIELDS),
}

_TOPIC_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")


def native_payload(enc, enc_v=None):
    """Return canonical JSON after exact version/shape/size validation.

    ``enc_v`` may be omitted only when the exact integer version is present in
    the envelope. A marker/envelope mismatch is always rejected; a future
    version can never fall through to plaintext handling.
    """
    if type(enc) is not dict:
        raise ValueError("native envelope object required")
    # Exact built-in keys are a boundary condition, not merely a shape
    # preference: hostile str subclasses can otherwise run equality hooks in
    # the version/algorithm lookups below.
    if any(type(field) is not str for field in enc):
        raise ValueError("native envelope field set/algorithm invalid")
    version = enc.get("v")
    if type(version) is not int or version not in _SUPPORTED:
        raise ValueError("unsupported native envelope version")
    if enc_v is None:
        enc_v = version
    if type(enc_v) is not int or enc_v != version:
        raise ValueError("native envelope/version mismatch")
    expected_alg, expected_fields = _SUPPORTED[version]
    algorithm = enc.get("alg")
    if (
        set(enc) != expected_fields
        or type(algorithm) is not str
        or algorithm != expected_alg
    ):
        raise ValueError("native envelope field set/algorithm invalid")
    error = validate_envelope(enc)
    if error:
        raise ValueError(error)
    raw = serialize_envelope(enc)
    if len(raw.encode("utf-8")) > 65536:
        raise ValueError("native envelope exceeds transport limit")
    return raw


def validate_message_context(topic=None, in_reply_to=None):
    """Return canonical optional correlation fields or reject them.

    Verbatim from custody tree 3998354. This is shared by the SDK, relay,
    and federation adapter. Exact built-in string checks happen before
    regex/UUID parsing so subclasses cannot invoke caller-defined equality,
    conversion, or regex callbacks.
    """
    if topic is not None:
        if type(topic) is not str or _TOPIC_RE.fullmatch(topic) is None:
            raise ValueError("bad_topic")
    if in_reply_to is not None:
        if type(in_reply_to) is not str:
            raise ValueError("bad_in_reply_to")
        try:
            parsed = uuid.UUID(in_reply_to)
        except (ValueError, AttributeError, TypeError):
            raise ValueError("bad_in_reply_to") from None
        if str(parsed) != in_reply_to:
            raise ValueError("bad_in_reply_to")
    return topic, in_reply_to
