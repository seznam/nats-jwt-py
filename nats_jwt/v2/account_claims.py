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
from datetime import datetime
from typing import Final, TYPE_CHECKING, Literal

from dataclasses_json import config, dataclass_json
import nkeys

from nats_jwt.nkeys_ext import Decode
from nats_jwt.v2.claims import _claim_data_config, AccountClaim, Claims, ClaimsData, GenericFields
from nats_jwt.v2.common import NoLimit
from nats_jwt.v2.revocation_list import RevocationList
from nats_jwt.v2.signing_keys import SigningKeys
from nats_jwt.v2.types import Limits, Permissions
from nats_jwt.v2.validation import ValidationResults

if TYPE_CHECKING:
    from nats_jwt.v2.user_claims import UserClaims

AnyAccount: Final[str] = "*"


@dataclass
class AccountLimits:
    """

    Attributes:
        imports: Max number of imports
        exports: Max number of exports
        wildcards: Are wildcards allowed in exports
        disallow_bearer: User JWT can't be bearer token
        conn: Max number of active connections
        leaf: Max number of active leaf node connections
    """

    imports: int = field(default=NoLimit, metadata=_claim_data_config)
    exports: int = field(default=NoLimit, metadata=_claim_data_config)
    wildcards: bool = field(default=True, metadata=_claim_data_config)
    disallow_bearer: bool = field(default=False, metadata=_claim_data_config)
    conn: int = field(default=NoLimit, metadata=_claim_data_config)
    leaf: int = field(default=NoLimit, metadata=_claim_data_config)

    def is_unlimited(self) -> bool:
        """ Check if all limits are set to unlimited

        :return: True if all limits are set to unlimited
        """
        return (
                self.imports == NoLimit
                and self.exports == NoLimit
                and self.wildcards is True
                and self.disallow_bearer is False
                and self.conn == NoLimit
                and self.leaf == NoLimit
        )

    def __bool__(self):
        return not self.is_unlimited()


@dataclass
class JetStreamLimits:
    """
    Attributes:
        memory_storage: Max number of bytes stored in memory across all streams. (0 means disabled)
        disk_storage: Max number of bytes stored on disk across all streams. (0 means disabled)
        streams: Max number of streams
        consumer: Max number of consumers
        max_ack_pending: Max ack pending of a Stream
        memory_max_stream_bytes: Max bytes a memory backed stream can have. (0 means disabled/unlimited)
        disk_max_stream_bytes: Max bytes a disk backed stream can have. (0 means disabled/unlimited)
        max_bytes_required: Max bytes required by all Streams
    """

    memory_storage: int = field(default=0, metadata=_claim_data_config)
    disk_storage: int = field(default=0, metadata=_claim_data_config)
    streams: int = field(default=0, metadata=_claim_data_config)
    consumer: int = field(default=0, metadata=_claim_data_config)
    max_ack_pending: int = field(default=0, metadata=_claim_data_config)
    memory_max_stream_bytes: int = field(default=0, metadata=_claim_data_config)
    disk_max_stream_bytes: int = field(default=0, metadata=_claim_data_config)
    max_bytes_required: bool = field(default=False, metadata=_claim_data_config)

    def is_unlimited(self) -> bool:
        """ Check if all limits are set to unlimited

        :return: True if all limits are set to unlimited
        """
        return (
                self.memory_storage == NoLimit
                and self.disk_storage == NoLimit
                and self.streams == NoLimit
                and self.consumer == NoLimit
                and self.max_bytes_required is False
                # workaround, if NoLimit was set instead 0 (disabled)
                and self.max_ack_pending <= 0
                and self.memory_max_stream_bytes <= 0
                and self.disk_max_stream_bytes <= 0
        )


JetStreamTieredLimits_T = dict[str, JetStreamLimits]


@dataclass_json
@dataclass()
class OperatorLimits(Limits, AccountLimits, JetStreamLimits):
    tiered_limits: JetStreamTieredLimits_T = field(default_factory=dict, metadata=config(exclude=lambda _: True))

    def __getitem__(self, item: str) -> JetStreamLimits:
        return self.tiered_limits[item]

    def __setitem__(self, key: str, value: JetStreamLimits) -> None:
        self.tiered_limits[key] = value

    def is_js_enabled(self):
        if len(self.tiered_limits) > 0:
            for js_limit in self.tiered_limits.values():  # type: JetStreamLimits
                if js_limit.memory_storage != 0 or js_limit.disk_storage != 0:
                    return True
            return False

        return self.memory_storage != 0 or self.disk_storage != 0

    def is_empty(self) -> bool:
        """ Check if all limits are set to unlimited

        :return: True if all limits are set to unlimited
        """
        return (
                super(Limits).is_unlimited()
                and super(AccountLimits).is_unlimited()
                and super(JetStreamLimits).is_unlimited()
                and len(self.tiered_limits) == 0
        )

    def is_unlimited(self) -> bool:
        return self.is_empty()

    def validate(self, vr: ValidationResults) -> None:
        """ Validate checks that the operator limits contain valid values
        """
        if len(self.tiered_limits) > 0:
            if self.tiered_limits.get(""):
                vr.add("Tiered JetStream Limits can not contain a blank \"\" tier name", level="e")

    def __bool__(self):
        return not self.is_empty()


ExportType = Literal["stream", "service", "unknown"]


@dataclass_json
@dataclass
class Export:
    name: str
    subject: str
    type: ExportType = "stream"
    token_req: bool = field(default_factory=bool, metadata=_claim_data_config)
    revocations: RevocationList = field(default_factory=RevocationList)
    response_type: Literal["Stream", "Chunked", "Singleton"] = field(default_factory=str, metadata=_claim_data_config)
    response_threshold: int = field(default_factory=int, metadata=_claim_data_config)
    account_token_position: int = field(default_factory=int, metadata=_claim_data_config)
    advertise: bool = field(default_factory=bool, metadata=_claim_data_config)


@dataclass_json
@dataclass
class Import:
    """ Import describes a mapping from another account into this one

    Attributes:
        name: Name of the import

        subject: Subject field in an import is always from the perspective of the
            initial publisher - in the case of a stream it is the account owning
            the stream (the exporter), and in the case of a service it is the
            account making the request (the importer).

        account: Account to import from

        token: Token to use for the import

        to: Deprecated: use LocalSubject instead
            To field in an import is always from the perspective of the subscriber
            in the case of a stream it is the client of the stream (the importer),
            from the perspective of a service, it is the subscription waiting for
            requests (the exporter). If the field is empty, it will default to the
            value in the Subject field.

        local_subject: Local subject used to subscribe (for streams) and publish (for services) to.
            This value only needs setting if you want to change the value of Subject.
            If the value of Subject ends in > then LocalSubject needs to end in > as well.
            LocalSubject can contain $<number> wildcard references where number references the nth wildcard in Subject.
            The sum of wildcard reference and * tokens needs to match the number of * token in Subject.

        type: Type of import

        share: sharing information (for latency tracking), for type:`service` only
    """
    name: str
    subject: str
    account: str
    type: ExportType
    token: str = field(default_factory=str, metadata=_claim_data_config)
    to: str = field(default_factory=str, metadata=_claim_data_config)
    local_subject: str = field(default_factory=str, metadata=_claim_data_config)
    share: bool = field(default_factory=bool, metadata=_claim_data_config)


@dataclass_json
@dataclass
class Account(GenericFields):
    """ Account holds account-specific claims data
    """
    imports: list[Import] = field(default_factory=list, metadata=_claim_data_config)
    exports: list[Export] = field(default_factory=list, metadata=_claim_data_config)
    limits: OperatorLimits = field(default_factory=OperatorLimits, metadata=_claim_data_config)
    signing_keys: SigningKeys = field(default_factory=SigningKeys, metadata=_claim_data_config)
    revocations: RevocationList = field(default_factory=RevocationList, metadata=_claim_data_config)
    default_permissions: Permissions = field(default_factory=Permissions, metadata=_claim_data_config)

    def validate(self, vr: ValidationResults) -> None:
        self.limits.validate(vr)
        self.default_permissions.validate(vr)


@dataclass_json
@dataclass
class AccountClaims(ClaimsData):
    nats: Account = field(default_factory=Account)

    def __post_init__(self):
        if self.sub == "":
            raise ValueError("subject is required")

        self.nats.signing_keys = SigningKeys()

    def encode(self, pair: nkeys.KeyPair) -> str:  # noqa
        """
        Raises:
            ValueError: if Decode fails
        :param pair:
        :return:
        """
        # nkeys.IsValidPublicAccountKey
        Decode(nkeys.PREFIX_BYTE_ACCOUNT, self.sub.encode())  # throws ValueError
        self.nats.type = AccountClaim
        return super().encode(pair, self)

    def payload(self) -> Account:
        return self.nats

    def validate(self, vr: ValidationResults):
        super().validate(vr)
        self.nats.validate(vr)

        Decode(nkeys.PREFIX_BYTE_ACCOUNT, self.sub.encode())  # throws ValueError

        if not self.nats.limits.is_empty():
            vr.add("self-signed account JWTs shouldn't contain operator limits")

    def claims(self) -> ClaimsData:
        return self

    def get_tags(self) -> list[str]:
        return self.tags

    def did_sign(self, c: Claims) -> bool:
        from nats_jwt.v2.user_claims import UserClaims

        if c is None:
            return False

        iss = c.claims().iss
        if iss == self.sub:
            return True

        if isinstance(c, UserClaims):
            return iss in self.nats.signing_keys

    def revoke_at(self, pub_key: str, timestamp: datetime) -> None:
        self.nats.revocations.revoke(pub_key, timestamp)

    def clear_revocations(self, pub_key: str) -> None:
        self.nats.revocations.clear_revocations(pub_key)

    def is_revoked(self, pub_key: str, timestamp: datetime) -> bool:
        return self.nats.revocations.is_revoked(pub_key, timestamp)

    def is_claim_revoked(self, claim: "UserClaims") -> bool:
        if claim is None or claim.iat == 0 or claim.sub == "":
            return True
        return self.nats.revocations.is_revoked(claim.sub, datetime.fromtimestamp(claim.iat))
