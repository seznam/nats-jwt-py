from dataclasses import dataclass

from jwt.v2.activation_claims import ActivationClaims
from jwt.v2.types import ExportType, RenamingSubject, Subject
from jwt.v2.validation import ValidationResults


@dataclass(frozen=True)
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

        share: Share import with other accounts
    """
    name: str = None
    subject: Subject = None
    account: str = None
    token: str = None
    to: Subject = None
    local_subject: RenamingSubject = None
    type: ExportType = None
    share: bool = None

    def is_service(self) -> bool:
        return self.type == ExportType.Service

    def is_stream(self) -> bool:
        return self.type == ExportType.Stream

    def get_to(self) -> str:
        return str(self.to)

    def validate(self, act_pub_key: str, vr: ValidationResults) -> None:
        if not self.is_service() and not self.is_stream():
            vr.add(f"invalid import type: {self.type}", level="e")

        if self.account == "":
            vr.add("account to import from is not specified", level="e")

        if self.get_to() != "":
            vr.add("the field to has been deprecated (use LocalSubject instead)", level="w")

        self.subject.validate(vr)
        if self.local_subject != "":
            self.local_subject.validate(self.subject, vr)
            if self.to != "":
                vr.add("Local Subject replaces To", level="e")

        if self.share and not self.is_service():
            vr.add(f"sharing information (for latency tracking) is only valid for services: {self.subject}", level="e")

        act: ActivationClaims | None = None

        if self.token != "":
            # TODO:
            act = self.decode_activation_claims(self.token, vr)

        if act is not None:
            if not (act.iss == self.account or act.nats.issuer_account == self.account):
                vr.add(f"activation token doesn't match account for import {self.subject}", level="e")
            if act.sub != act_pub_key:
                vr.add(f"activation token doesn't match account it is being included in, {self.subject}", level="e")
            if act.nats.import_type != self.type:
                vr.add(f"mismatch between token import type {act.nats.import_type} and type of import {self.type}",
                       level="e")
            act.validate_with_time_checks(vr, False)
            subj = self.subject
            if self.is_service() and self.to != "":
                subj = self.to
            if not subj.is_contained_in(act.nats.import_subject):
                vr.add(f"activation token import subject {act.nats.import_subject} doesn't match import {self.subject}",
                       level="e")

    def decode_activation_claims(self, token: str, vr: ValidationResults):
        raise NotImplementedError("TODO: decode_activation_claims")
