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
from typing import Final

import nkeys

from nats_jwt.nkeys_ext import Decode
from nats_jwt.v2.claims import _claim_data_config, ClaimsData, GenericFields, PrefixByte, UserClaim
from nats_jwt.v2.types import Limits, Permissions
from nats_jwt.v2.validation import ValidationResults

ConnectionTypeStandard: Final[str] = "STANDARD"
ConnectionTypeWebsocket: Final[str] = "WEBSOCKET"
ConnectionTypeLeafnode: Final[str] = "LEAFNODE"
ConnectionTypeLeafnodeWS: Final[str] = "LEAFNODE_WS"
ConnectionTypeMqtt: Final[str] = "MQTT"
ConnectionTypeMqttWS: Final[str] = "MQTT_WS"


@dataclass
class UserPermissionLimits(Permissions, Limits):
    bearer_token: bool = None
    allowed_connection_types: list[str] = None

    def as_user_permission_limits(self) -> "UserPermissionLimits":
        return UserPermissionLimits(
            bearer_token=self.bearer_token,
            allowed_connection_types=self.allowed_connection_types,
            pub=self.pub,
            sub=self.sub,
            resp=self.resp,
            subs=self.subs,
            data=self.data,
            payload=self.payload
        )


@dataclass
class _User(UserPermissionLimits):
    """ NOTE: Class created due to dataclasses required argument
    if arguments of this class are defined in `User` class, that will cause
    `Non-default argument(s) follows default argument(s) defined in 'UserPermissionLimits', 'Permissions', 'Limits' `
    """
    issuer_account: str = field(default="", metadata=_claim_data_config)


@dataclass
class User(GenericFields, _User):
    """ User defines the user-specific data in a user JWT """

    def validate(self, vr: ValidationResults) -> None:
        self.as_permissions().validate(vr)


@dataclass
class UserClaims(ClaimsData):
    nats: User = field(default_factory=User)

    def __post_init__(self):
        from nats_jwt.v2.account_claims import Limits

        if self.sub == "":
            raise ValueError("subject is required")

        self.nats.nats_limits = Limits()

    def has_empty_permissions(self) -> bool:
        return self.nats.as_user_permission_limits() == UserPermissionLimits()

    def encode(self, pair: nkeys.KeyPair) -> str: # noqa
        """
        Raises:
            ValueError: if Decode fails
        :param pair:
        :return:
        """
        # nkeys.IsValidPublicUserKey
        Decode(nkeys.PREFIX_BYTE_USER, self.sub.encode())

        self.nats.type = UserClaim
        return super().encode(pair, self)

    def validate(self, vr: ValidationResults):
        super().validate(vr)
        self.nats.validate(vr)

    def expected_prefixes(self) -> list[PrefixByte]:
        return [nkeys.PREFIX_BYTE_USER]

    def claims(self) -> ClaimsData:
        return self

    def payload(self) -> User:
        return self.nats

    def is_bearer_token(self) -> bool:
        return self.nats.bearer_token
