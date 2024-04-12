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
from typing import Final, TYPE_CHECKING


from nats_jwt.v2.claims import _claim_data_config
from nats_jwt.v2.common import NoLimit

if TYPE_CHECKING:
    from nats_jwt.v2.validation import ValidationResults

MaxInfoLength: Final[int] = 8 * 1024


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


@dataclass
class Limits:
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


@dataclass
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
