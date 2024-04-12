#    Copyright 2024 Seznam.cz, a.s.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

from __future__ import annotations

import base64
import contextlib
import time
from dataclasses import dataclass, field
from typing import Annotated, Any, Final, Protocol, Type, TypeVar, TYPE_CHECKING

import dacite
import nkeys
from Crypto.Hash import SHA512
from dataclasses_json import config, dataclass_json
from nkeys import ErrInvalidSignature

from nats_jwt.nkeys_ext import keypair_from_pubkey
from nats_jwt.v2.version import LIB_VERSION
from nats_jwt.v2.header import AlgorithmNkey, AlgorithmNkeyOld, Header, TokenTypeJwt
from nats_jwt.v2.validation import ValidationResults

if TYPE_CHECKING:
    from Crypto.Hash.SHA512 import SHA512Hash

ClaimType = Annotated[str, "ClaimType is used to indicate the type of JWT being stored in a Claim"]

# OperatorClaim is the type of an operator JWT
OperatorClaim: Final[ClaimType] = "operator"
# AccountClaim is the type of an Account JWT
AccountClaim: Final[ClaimType] = "account"
# UserClaim is the type of an user JWT
UserClaim: Final[ClaimType] = "user"
# [not supported] ActivationClaim is the type of an activation JWT
# ActivationClaim: Final[ClaimType] = "activation"
# [not supported] AuthorizationRequestClaim is the type of an auth request claim JWT
# AuthorizationRequestClaim: Final[ClaimType] = "authorization_request"
# [not supported] AuthorizationResponseClaim is the response for an auth request
# AuthorizationResponseClaim: Final[ClaimType] = "authorization_response"
# GenericClaim is a type that doesn't match Operator/Account/User/ActionClaim
GenericClaim: Final[ClaimType] = "generic"


# this dict is used for dacite, so we can omit not used fields from json.
# in go, it's done by `omitempty` in json tag, but in python it's not possible.
_claim_data_config: dict[str, dict] = config(exclude=lambda x: not x)

T = TypeVar("T")


def safe_url_base64_decode(data: bytes) -> bytes:
    """ Safe url base64 decode

    Method append padding to data if it's not multiple of 4.
    It's needed as python's base64 decoding can't handle non-padded data.
    """
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def extract_payload_sig_from_jwt(token: str) -> tuple[bytes, bytes]:
    """ Extracts payload and its signature from JWT.

    Payload - is header and data, joined by dot (in base64 encoding).
    Signature - is base64 encoded bytes;

    Args:
         token: JWT token as string

    Returns:
        tuple of payload and signature
    """

    chunks = token.split(".", 3)
    if len(chunks) != 3:
        raise ValueError("expected 3 chunks")

    payload: str = chunks[0] + "." + chunks[1]
    sig: bytes = safe_url_base64_decode(chunks[2].encode())

    return payload.encode(), sig


PrefixByte: type = Annotated[bytes, "max len is 1, just one byte"]


class Claims(Protocol):
    """ Claims is a JWT claims
    """

    def claims(self) -> "ClaimsData": ...

    def encode(self, kp: nkeys.KeyPair, *args, **kwargs) -> str: ...

    def expected_prefixes(self) -> list[PrefixByte]: ...

    def payload(self) -> Any: ...

    def validate(self, vr: "ValidationResults") -> None: ...

    def claim_type(self) -> ClaimType: ...

    def __str__(self) -> str: ...

    def verify(self, payload: bytes, sig: bytes, pub_key: str = "") -> bool: ...

    # should be protected
    def update_version(self) -> None: ...


@dataclass_json
@dataclass
class GenericFields:
    tags: list[str] = field(default_factory=list, metadata=_claim_data_config)
    type: ClaimType = field(default_factory=str, metadata=_claim_data_config)
    version: int = LIB_VERSION


def serialize(v: dataclass) -> bytes:
    """ Converts dataclass to json and encodes it to bytes

    Note:
        Dataclass should be compatible with a datice library

    Args:
        v: dataclass to serialize
    """
    return v.to_json().encode()


AnyClaims = TypeVar("AnyClaims", bound=Claims)


@dataclass_json
@dataclass
class ClaimsData(Claims):
    """ ClaimsData is the base struct for all claims

    Attributes:
        aud: Audience
        exp: Expires
        jti: ID
        iat: IssuedAt
        iss: Issuer
        name: Name
        nbf: NotBefore
        sub: Subject
    """
    sub: str   # Subject
    name: str  # Name

    aud: str = field(default_factory=str, metadata=_claim_data_config)
    exp: int = field(default_factory=int, metadata=_claim_data_config)  # Expires
    jti: str = field(default_factory=str, metadata=_claim_data_config)  # ID
    iat: int = field(default_factory=int, metadata=_claim_data_config)  # IssuedAt
    iss: str = field(default_factory=str, metadata=_claim_data_config)  # Issuer

    nbf: int = field(default_factory=int, metadata=_claim_data_config)  # NotBefore
    tags: list[str] = field(default_factory=list, metadata=_claim_data_config)

    nats: GenericFields = field(default=None, metadata=_claim_data_config)

    def do_encode(self, header: Header, kp: nkeys.KeyPair, claim: Claims) -> str:
        """ Creates an encoded JWT token for this instance of claims.

        Note:
            This method is doing some checks and may raise Exception.

        Note:
            Claims are not checked in runtime to

        Note:
            This method depends on time, so it's not deterministic.
            And JWT tokens created at different times will be different.

        Note:
            That method calls `update_version` method of `claim` argument.

        Raises:
            ValueError
        """
        if header is None or not isinstance(header, Header):
            raise ValueError("header is required")

        if kp is None or not isinstance(kp, nkeys.KeyPair):
            raise ValueError("keypair is required")

        if claim is None:
            raise ValueError("claim is required")

        if self.sub == "":
            raise ValueError("subject is not set")

        h: bytes = serialize(header)

        issuer_bytes: bytes = kp.public_key

        self.iss = issuer_bytes.decode()
        self.iat = int(time.time())
        self.jti = self.hash()

        claim.update_version()

        # encoded json
        payload: bytes = serialize(claim)
        # concatenate header and payload for signing
        to_sign: bytes = base64.urlsafe_b64encode(h).rstrip(b"=") + b"." + base64.urlsafe_b64encode(payload).rstrip(
            b"=")

        if header.alg == AlgorithmNkeyOld:
            raise NotImplementedError(f"{AlgorithmNkeyOld} not supported to write jwtV2")

        if header.alg != AlgorithmNkey:
            raise ValueError(f"{header.alg} not supported to write jwtV2")

        # sign the payload
        sign: bytes = kp.sign(to_sign)

        # return concat of header, payload, and signature
        return to_sign.decode() + "." + base64.urlsafe_b64encode(sign).rstrip(b"=").decode()

    def hash(self) -> str:
        """ Hash returns a hash of the claims
        """
        s: bytes = serialize(self)

        sha256: SHA512Hash = SHA512.new(truncate="256")
        sha256.update(s)
        return base64.b32encode(sha256.digest()).rstrip(b"=").decode()

    def _encode(self, kp: nkeys.KeyPair, payload: Claims) -> str:
        """ Encode encodes a claim into a JWT token. The claim is signed with the
        provided nkey's private key
        """
        return self.do_encode(Header(AlgorithmNkey, TokenTypeJwt), kp, payload)

    def __str__(self):
        return serialize(self).decode()

    def verify(self, payload: bytes, sig: bytes, pub_key: str = "") -> bool:
        """ Verifies the signature of the payload with the provided public key.

        If a public key is not provided, the method verifies if this instance of claim did sign the payload.

        Args:
            payload: payload, raw bytes.
                For info, JWT signature is calculated for base64_enc(header + payload), so payload should be
                base64 encoded string.
            sig: signature, raw bytes.
            pub_key: public key in nats format, it's starting with one of NKEYS PREFIX BYTE.
                Later it will be decoded to an ed25519 public key.
        """

        with contextlib.suppress(ErrInvalidSignature):
            keypair_from_pubkey((pub_key or self.sub).encode()).verify(payload, sig)
            return True

        return False

    def verify_jwt(self, token: str) -> bool:
        payload, sig = extract_payload_sig_from_jwt(token)

        return self.verify(payload, sig)

    def encode(self, kp: nkeys.KeyPair, payload: AnyClaims, *_, **__) -> str:  # noqa
        """ Encode encodes a claim into a JWT token. The claim is signed with the
        provided nkey's private key
        """
        return self.do_encode(
            Header(TokenTypeJwt, AlgorithmNkey),
            kp,
            payload
        )

    def validate(self, vr: ValidationResults):
        now = int(time.time())
        if 0 < self.exp < now:
            vr.add("claim is expired", level="e")

        if self.nbf is not None and self.nbf > now:
            vr.add("claim is not valid yet", level="e")

    @classmethod
    def load(cls: Type[T], data: dict, version: int) -> T:
        if version > 2 or version == 1:
            raise Warning(f"This lib does not support jwt version {version}. (only v2 is supported)")

        return dacite.from_dict(cls, data=data)

    @classmethod
    def decode_claims(cls: Type[T], token: str) -> T:
        """
        Raises:
            ValueError: if Decode fails

        Args:
            token: JWT token as string

        Returns:
            Claims: decoded claims based on class calling this method
        """
        from nats_jwt.v2.decoder import decode

        claims: Claims = decode(token)
        if not isinstance(claims, cls):
            raise ValueError(f"token is not a {cls.__name__} claim, got: {type(claims)}")

        return claims

    def update_version(self) -> None:
        self.nats.version = LIB_VERSION
