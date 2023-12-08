import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Final, TYPE_CHECKING

import pytz

from jwt.v2.claims import _claim_data_config
from jwt.v2.common import NoLimit

if TYPE_CHECKING:
    from jwt.v2.account_claims import NatsLimits
    from jwt.v2.validation import ValidationResults

MaxInfoLength: Final[int] = 8 * 1024


@dataclass(frozen=True)
class Info:
    description: str = field(default="", metadata=_claim_data_config)
    info_url: str = field(default="", metadata=_claim_data_config)

    def validate(self, vs: "ValidationResults") -> None:
        if len(self.description) > MaxInfoLength:
            vs.add("Description is too long", level="e")

        if self.info_url != "":
            if len(self.info_url) > MaxInfoLength:
                vs.add("Info URL is too long", level="e")

            # TODO: parse URL
            # u, err := url.Parse(s.InfoURL)
            # if err == nil && (u.Hostname() == "" || u.Scheme == "") {
            # 	err = fmt.Errorf("no hostname or scheme")
            # }
            # if err != nil {
            # 	vr.AddError("error parsing info url: %v", err)
            # }

    def __bool__(self):
        return not (self.description == "" and self.info_url == "")


class ExportType(Enum):
    """ ExportType defines the type of import/export

    Attributes:
        Unknown: Unknown is used if we don't know the type
        Stream: Stream defines the type field value for a stream "stream"
        Service: Service defines the type field value for a service "service"
    """
    Unknown: Final[str] = "unknown"
    Stream: Final[str] = "stream"
    Service: Final[str] = "service"


class Subject(str):
    def validate(self, vs: "ValidationResults") -> None:
        if self == "":
            vs.add("subject cannot be empty", level="e")
        if " " in self:
            vs.add(f"subject `{self}` cannot contain spaces", level="e")

    def count_token_wildcards(self) -> int:
        return self.count("*")

    def has_wildcards(self) -> bool:
        return (self == "*"
                or self == ">"
                or self.endswith(".*")
                or self.endswith(".>")
                or self.startswith("*.")
                or ".*.*" in self
                )

    def is_contained_in(self, other: "Subject") -> bool:
        my_tokens = self.split(".")
        other_tokens = other.split(".")

        if len(my_tokens) > len(other_tokens) and other_tokens[-1] != ">":
            return False

        if len(my_tokens) < len(other_tokens):
            return False

        for i, token in enumerate(my_tokens):
            if i == len(other_tokens) - 1 and token == ">":
                return True

            if token != my_tokens[i] and token != "*":
                return False

        return True


class RenamingSubject(Subject):
    def validate(self, f: Subject, vr: "ValidationResults"):  # noqa
        Subject(self).validate(vr)

        if f == "":
            vr.add("from subject cannot be empty", level="e")

        if " " in self:
            vr.add(f"from subject `{self}` cannot contain spaces", level="e")

        matched_suffix: callable = lambda s: s == ">" or s.endswith(".>")

        if matched_suffix(self) and not matched_suffix(f):
            vr.add("both, renaming subject and subject, need to end or not end in >", level="e")

        from_cnt = f.count_token_wildcards()
        ref_cnt = 0

        for token in self.split("."):
            if token == "*":
                ref_cnt += 1

            if len(token) < 2:
                continue

            if token[0] == "$":
                # if idx, err := strconv.Atoi(tk[1:]); err == ni
                if token[1:].isdigit():
                    if int(token[1:]) > from_cnt:
                        vr.add(f"Reference ${token[1:]} in `{self}` reference * in {f} that do not exist", level="e")
                    else:
                        ref_cnt += 1

        if ref_cnt < from_cnt:
            vr.add("subject does not contain enough * or reference wildcards $[0-9]", level="e")

    def to_subject(self) -> Subject:
        if "$" not in self:
            return Subject(self)

        tokens = self.split(".")
        for i, token in enumerate(tokens):
            convert = False
            if len(token) > 1 and token[0] == "$":
                if token[1:].isdigit():
                    convert = True
            if convert:
                tokens[i] = "*"
            else:
                tokens[i] = token

            if i != len(tokens) - 1:
                tokens[i] += "."

        return Subject("".join(tokens))


@dataclass(frozen=True)
class TimeRange:
    start: str = ""
    end: str = ""

    def validate(self, vs: "ValidationResults"):
        if self.start == "":
            vs.add("time ranges start must contain a start", level="e")
        else:
            for t in {self.start, self.end}:
                try:
                    time.strptime(t, "%H:%M:%S")  # format 15:04:05
                except ValueError:
                    vs.add(f"Start/End in time range is invalid \"{t}\"",
                           level="e")  # a bit different from the go version


@dataclass(frozen=False)
class CIDRList:
    values: list[str] = field(default_factory=list, metadata=_claim_data_config)

    def contains(self, p: str) -> bool:
        return p in self.values

    def add(self, p: str) -> None:
        self.values.append(p)

    def remove(self, p: str) -> None:
        self.values.remove(p)

    def set(self, values: str) -> None:
        self.values = [v.lower() for v in values.split(",")]

    def __post_init__(self):
        if self.values is None:
            self.values = []

    def __len__(self):
        return len(self.values)

    def __iter__(self):
        return iter(self.values)


@dataclass
class UserLimits:
    """
    Attributes:
        src: A comma separated list of CIDR specifications
        times: A list of time ranges
        locale: The locale to use for time ranges
    """
    src: CIDRList = field(default_factory=CIDRList, metadata=_claim_data_config)
    times: list[TimeRange] = None
    locale: str = ""

    def empty(self) -> bool:
        return self.src == "" and self.times is None and self.locale == ""

    def is_unlimited(self) -> bool:
        return self.src == "" and self.times is None

    def validate(self, vr: "ValidationResults") -> None:
        if len(self.src) > 0:
            for _ in self.src:
                pass


@dataclass
class NatsLimits:
    """
    Attributes:
        subs: Max number of subscriptions
        data: Max number of bytes
        payload: Max message payload
    """

    subs: int = field(default=NoLimit, metadata=_claim_data_config)
    data: int = field(default=NoLimit, metadata=_claim_data_config)
    payload: int = field(default=NoLimit, metadata=_claim_data_config)

    def is_unlimited(self) -> bool:
        """ Check if all limits are set to unlimited

        :return: True if all limits are set to unlimited
        """
        return (
                self.subs == NoLimit
                and self.data == NoLimit
                and self.payload == NoLimit
        )


@dataclass
class Limits(UserLimits, NatsLimits):

    def is_unlimited(self) -> bool:
        return super(UserLimits).is_unlimited() and super(NatsLimits).is_unlimited()

    def validate(self, vr: "ValidationResults") -> None:
        if len(self.src) != 0:
            for _ in self.src:
                # TODO: parse CIDR
                # _, ipNet, err := net.ParseCIDR(cidr)
                # if err != nil || ipNet == nil {
                #     vr.AddError("invalid cidr %q in user src limits", cidr)
                # }
                pass

        if len(self.times) > 0:
            for t in self.times:
                t.validate(vr)

        if self.locale != "":
            try:
                pytz.timezone(self.locale).localize(time.localtime())
            except pytz.UnknownTimeZoneError:
                vr.add(f"could not parse iana time zone by name \"{self.locale}\" ", level="e")

    def as_limits(self) -> "Limits":
        """ as_limits returns the limits as a Limits object
        for objects that has multiple inheritance and this clas may be shadowed,
        """
        return Limits(
            src=self.src,
            times=self.times,
            locale=self.locale,
            subs=self.subs,
            data=self.data,
            payload=self.payload,
        )


@dataclass(frozen=True)
class Permission:
    allow: list[str] = field(default_factory=list, metadata=_claim_data_config)
    deny: list[str] = field(default_factory=list, metadata=_claim_data_config)

    def empty(self) -> bool:
        return len(self.allow) == 0 and len(self.deny) == 0

    @staticmethod
    def check_permission(vr: "ValidationResults", subj: str, permit_queue: bool) -> None:
        tk = subj.split(" ")
        if len(tk) == 1:
            Subject(tk[0]).validate(vr)
        elif len(tk) == 2:
            Subject(tk[0]).validate(vr)
            Subject(tk[1]).validate(vr)
            if not permit_queue:
                vr.add(f"Permission Subject \"{subj}\" is not allowed to contain queue", level="e")
        else:
            vr.add(f"Permission Subject \"{subj}\" contains too many spaces", level="e")

    def validate(self, vr: "ValidationResults", permit_queue: bool) -> None:
        for subj in self.allow:
            self.check_permission(vr, subj, permit_queue)
        for subj in self.deny:
            self.check_permission(vr, subj, permit_queue)


@dataclass(frozen=True)
class ResponsePermission:
    max_msgs: int = field(default=0, metadata=_claim_data_config)
    expires: int = field(default=0, metadata=_claim_data_config)

    def validate(self, vr: "ValidationResults") -> None:
        """
        jwt/origin:
            v 2.5.3 - Any values can be valid for now
        """
        return


@dataclass
class Permissions:
    pub: Permission = field(default_factory=Permission)
    sub: Permission = field(default_factory=Permission)
    resp: ResponsePermission = field(default_factory=ResponsePermission, metadata=_claim_data_config)

    def validate(self, vr: "ValidationResults") -> None:
        if self.resp is not None:
            self.resp.validate(vr)
        self.sub.validate(vr, True)
        self.pub.validate(vr, False)

    def as_permissions(self) -> "Permissions":
        """ as_permissions returns the permissions as a Permissions object
        for objects that has multiple inheritance and this clas may be shadowed.
        """
        return Permissions(self.pub, self.sub, self.resp)
