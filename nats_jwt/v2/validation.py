from __future__ import annotations

from dataclasses import dataclass
from functools import singledispatchmethod
from typing import Generator, Literal


class ValidationIssue(Exception):
    Description: str
    Blocking: bool
    TimeCheck: bool

    def __str__(self):
        return self.Description


@dataclass
class ValidationResults:
    issues: list[ValidationIssue]

    def __init__(self):
        self.issues = []

    @singledispatchmethod
    def add(self, issue: ValidationIssue, **_):
        self.issues.append(issue)

    @add.register(str)
    def _(self, issue: str, *, level: Literal["e", "w", "tc", "b"] = "e"):
        """ Add an issue to the validation results

        :param issue: Description of the issue
        :param level: Level of the issue
            - e: Error
            - w: Warning
            - tc: TimeCheck
            - b: Blocking
        :return:
        """
        if level == "e":
            self.issues.append(ValidationIssue(issue, True, False))

    def is_blocking(self, include_time_checks: bool = False) -> bool:
        """
        :return: True if the list contains a blocking error
        """

        return any(
            issue.Blocking or (include_time_checks and issue.TimeCheck)
            for issue in self.issues
        )

    def is_empty(self):
        return len(self.issues) == 0

    def errors(self) -> Generator[ValidationIssue, None, None]:
        yield from (issue for issue in self.issues if issue.Blocking)

    def warnings(self) -> Generator[ValidationIssue, None, None]:
        yield from (issue for issue in self.issues if not issue.Blocking)
