import contextlib
from dataclasses import dataclass
from typing import Protocol

import nkeys

from jwt.nkeys_ext import Decode
from jwt.v2.claims import Claims
from jwt.v2.user_claims import UserClaims, UserPermissionLimits
from jwt.v2.validation import ValidationResults


class Scope(Protocol):
    def signing_key(self) -> str: ...

    def validate_scope_signer(self, claim: Claims): ...

    def validate(self, vr: ValidationResults): ...


class ScopeType(int):
    def __str__(self):
        if self == UserScopeType:
            return "user_scope"
        return "unknown"


UserScopeType: ScopeType = ScopeType(1)


@dataclass
class UserScope:
    kind: ScopeType = UserScopeType
    key: str = ""
    role: str = ""
    template: UserPermissionLimits = None

    def __post_init__(self):
        self.template = UserPermissionLimits()
        self.kind = UserScopeType

    def signing_key(self) -> str:
        return self.key

    def validate(self, vr: ValidationResults) -> None:
        with contextlib.suppress(ValueError):
            Decode(nkeys.PREFIX_BYTE_ACCOUNT, self.key.encode())
            return
        vr.add(f"{self.key} is not an account public key")

    def validate_scope_signer(self, claim: Claims) -> None:
        if isinstance(claim, UserClaims):
            raise ValueError("not an user claim - scoped signing key requires user claim")
        claim: UserClaims
        if claim.iss != self.key:
            raise ValueError("issuer not the scoped signer")
        if not claim.has_empty_permissions():
            raise ValueError("scoped users require no permissions or limits set")


class SigningKeys(dict[str, Scope | None]):
    def validate(self, vr: ValidationResults) -> None:
        for key, scope in self.items():
            if scope is None:
                # TODO: !nkeys.IsValidPublicAccountKey(k) => "%q is not a valid account signing key", k)
                continue
            scope.validate(vr)

    def add(self, *keys: str) -> None:
        for key in keys:
            self[key] = None

    def add_scoped_signer(self, s: Scope):
        self[s.signing_key()] = s
