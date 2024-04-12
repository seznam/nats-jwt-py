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

from dataclasses import dataclass, field
from typing import Generator

import nkeys
from dataclasses_json import dataclass_json

from nats_jwt.nkeys_ext import Decode
from nats_jwt.v2.version import LIB_VERSION
from nats_jwt.v2.claims import _claim_data_config, Claims, ClaimsData, GenericFields, OperatorClaim
from nats_jwt.v2.validation import ValidationResults


def parse_version(version: str) -> tuple[int, ...]:
    def check(x: str, index: int):
        versions = ["major", "minor", "update"]
        if not x.isdigit():
            raise ValueError(f"Invalid {versions[index]} version {version}")
        if int(x) < 0:
            raise ValueError(f"{versions[index]} version can not be negative - {version}")
        return int(x)

    return tuple(check(x, i) for i, x in enumerate(version.split(".")))


@dataclass_json
@dataclass
class Operator(GenericFields):
    signing_keys: list[str] = field(default_factory=list, metadata=_claim_data_config)
    account_server_url: str = field(default_factory=str, metadata=_claim_data_config)
    account_server_signing_key: str = field(default_factory=str, metadata=_claim_data_config)
    operator_service_urls: list[str] = field(default_factory=list, metadata=_claim_data_config)
    system_account: str = field(default_factory=str, metadata=_claim_data_config)
    assert_server_version: str = field(default_factory=str, metadata=_claim_data_config)
    strict_signing_key_usage: bool = field(default=False, metadata=_claim_data_config)

    def validate(self, vr: ValidationResults):
        err = self.validate_account_server_url()
        if err:
            vr.add(err)

        [vr.add(e) for e in self.validate_account_service_urls()]

        for k in self.signing_keys:
            try:
                Decode(nkeys.PREFIX_BYTE_OPERATOR, k.encode())
            except ValueError as e:
                vr.add(f"invalid signing key: {e}")

        if self.system_account != "":
            try:
                Decode(nkeys.PREFIX_BYTE_ACCOUNT, self.system_account.encode())
            except ValueError as e:
                vr.add(f"invalid system account: {e}")

        parse_version(self.assert_server_version)

    @staticmethod
    def validate_account_service_url(v) -> str | None:
        if v == "":
            return None

    def validate_account_server_url(self) -> str | None:
        if self.account_server_url == "":
            return "account server url is required"

    def validate_account_service_urls(self) -> Generator[str, None, None]:
        for i, v in enumerate(self.operator_service_urls):
            err = self.validate_account_service_url(v)
            if err is not None:
                yield err


@dataclass
class OperatorClaims(ClaimsData):
    nats: Operator = field(default_factory=Operator)

    def __post_init__(self):
        if self.sub == "":
            raise ValueError("subject can not be empty")
        self.iss = self.sub
        self.nats.version = LIB_VERSION

    def did_signing_key_rotate(self, op: Claims) -> bool:
        if op is None:
            return False
        iss = op.claims().iss
        if iss == self.sub:
            if not self.nats.strict_signing_key_usage:
                return True
            return op.claims().sub == self.sub

        return iss in self.nats.signing_keys

    def encode(self, pair: nkeys.KeyPair) -> str:  # noqa
        Decode(nkeys.PREFIX_BYTE_OPERATOR, pair.public_key)  # throws ValueError

        self.nats.type = OperatorClaim
        return super().encode(pair, self)
