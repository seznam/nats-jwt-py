from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, TYPE_CHECKING

from dataclasses_json import config, dataclass_json
from nkeys import nkeys

from jwt.nkeys_ext import Decode
from jwt.v2.activation_claims import ActivationClaims
from jwt.v2.claims import _claim_data_config, AccountClaim, Claims, ClaimsData, GenericFields
from jwt.v2.common import NoLimit
from jwt.v2.exports import Export
from jwt.v2.imports import Import
from jwt.v2.revocation_list import RevocationList
from jwt.v2.signing_keys import SigningKeys
from jwt.v2.types import Info, NatsLimits, Permissions, Subject
from jwt.v2.validation import ValidationResults

if TYPE_CHECKING:
    from jwt.v2.user_claims import UserClaims

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
class OperatorLimits(NatsLimits, AccountLimits, JetStreamLimits):
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
                super(NatsLimits).is_unlimited()
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


@dataclass(frozen=True)
class WeightedMapping:
    subject: Subject
    weight: int = None
    cluster: str = None

    def get_weight(self) -> int:
        if self.weight == 0:
            return 100
        return self.weight


class Mapping(dict[Subject, list[WeightedMapping]]):
    def validate(self, vr: ValidationResults):
        for ub_from, wm in self.items():
            ub_from.validate(vr)
            total = 0
            for _wm in wm:
                _wm.subject.validate(vr)
                total += _wm.get_weight()
            if total > 100:
                vr.add(f"Mapping \"{ub_from}\" exceeds 100% among all of it's weighted to mappings", level="e")

    def add_mapping(self, sub: Subject, to: list[WeightedMapping]):
        self[sub] = to


@dataclass(frozen=True)
class ExternalAuthorization:
    """ Enable external authorization for account users.
    AuthUsers are those users specified to bypass the
        authorization callout and should be used for the authorization service itself.
    AllowedAccounts specifies which accounts, if any, that the authorization service can bind an authorized user to.
    The authorization response, a user JWT, will still need to be signed by the correct account.

    If optional XKey is specified, that is the public xkey (x25519) and the server will encrypt the request such that
        only the holder of the private key can decrypt.

    The auth service can also optionally encrypt the response back to the server using it's public xkey
        which will be in the authorization request.
    """
    auth_users: list[str] | None = None
    allowed_accounts: list[str] | None = field(default_factory=list, metadata=_claim_data_config)
    xkey: str | None = field(default=None, metadata=_claim_data_config)

    def is_enabled(self) -> bool:
        return len(self.auth_users) > 0

    def validate(self, vr: ValidationResults) -> None:
        if len(self.allowed_accounts) > 0 and len(self.auth_users) == 0:
            vr.add("External authorization cannot have accounts without users specified")

        for user in self.auth_users:
            try:
                Decode(nkeys.PREFIX_BYTE_USER, user.encode())
            except ValueError:
                vr.add(f"AuthUser {user} is not a valid user public key")


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
    mappings: Mapping = field(default_factory=Mapping, metadata=_claim_data_config)
    authorization: ExternalAuthorization = field(default_factory=ExternalAuthorization, metadata=_claim_data_config)
    info: Info = field(default_factory=Info, metadata=_claim_data_config)

    def validate(self, acct: "AccountClaims", vr: ValidationResults) -> None:
        for imp in self.imports:
            imp.validate(acct.sub, vr)
        for exp in self.exports:
            Subject(exp).validate(vr)
        self.limits.validate(vr)
        self.default_permissions.validate(vr)
        self.mappings.validate(vr)
        self.authorization.validate(vr)


@dataclass_json
@dataclass
class AccountClaims(ClaimsData):
    nats: Account = field(default_factory=Account)

    def __post_init__(self):
        if self.sub == "":
            raise ValueError("subject is required")

        if isinstance(self.nats, dict):
            self.nats = Account(**self.nats)

        self.nats.signing_keys = SigningKeys()

        limits: OperatorLimits = self.nats.limits
        limits.nats_limits = NatsLimits()
        limits.account_limits = AccountLimits()
        limits.jetstream_limits = JetStreamLimits()
        limits.tiered_limits = {}

        self.mappings = Mapping()

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
        self.nats.validate(self, vr)

        Decode(nkeys.PREFIX_BYTE_ACCOUNT, self.sub.encode())  # throws ValueError

        if not self.nats.limits.is_empty():
            vr.add("self-signed account JWTs shouldn't contain operator limits")

    def claims(self) -> ClaimsData:
        return self

    def get_tags(self) -> list[str]:
        return self.tags

    def did_sign(self, c: Claims) -> bool:
        from jwt.v2.user_claims import UserClaims

        if c is None:
            return False

        iss = c.claims().iss
        if iss == self.sub:
            return True

        if isinstance(c, (UserClaims, ActivationClaims)):
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
