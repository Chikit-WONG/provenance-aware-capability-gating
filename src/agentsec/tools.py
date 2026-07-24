"""The six local office tools and their structured execution evidence."""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .provenance import ExactTaintTracker, RuntimeProvenance, join_provenance
from .schemas import Decision, EventKind, ToolName
from .world import AuditLog, MockWorld


class _Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SearchEmailsArguments(_Arguments):
    query: str


class ReadEmailArguments(_Arguments):
    email_id: str


class ReadFileArguments(_Arguments):
    file_id: str


class SearchCalendarArguments(_Arguments):
    date: str


class SendEmailArguments(_Arguments):
    to: str
    subject: str
    body: str
    cc: tuple[str, ...] = ()


class CreateCalendarEventArguments(_Arguments):
    title: str
    start: str
    end: str
    participants: tuple[str, ...] = ()
    location: str = ""


TOOL_ARGUMENT_MODELS: dict[ToolName, type[_Arguments]] = {
    ToolName.SEARCH_EMAILS: SearchEmailsArguments,
    ToolName.READ_EMAIL: ReadEmailArguments,
    ToolName.READ_FILE: ReadFileArguments,
    ToolName.SEARCH_CALENDAR: SearchCalendarArguments,
    ToolName.SEND_EMAIL: SendEmailArguments,
    ToolName.CREATE_CALENDAR_EVENT: CreateCalendarEventArguments,
}


class ToolExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    tool: ToolName | None
    output: Any = None
    event_id: str
    error: str = ""


def tool_schemas(names: tuple[ToolName, ...] | None = None) -> list[dict[str, Any]]:
    """Return OpenAI-compatible function declarations for the selected tools."""

    selected = names or tuple(ToolName)
    return [
        {
            "type": "function",
            "function": {
                "name": tool.value,
                "description": _TOOL_DESCRIPTIONS[tool],
                "parameters": TOOL_ARGUMENT_MODELS[tool].model_json_schema(),
            },
        }
        for tool in selected
    ]


_TOOL_DESCRIPTIONS = {
    ToolName.SEARCH_EMAILS: "Search inbound email metadata by sender, subject, or text query.",
    ToolName.READ_EMAIL: "Read one inbound email by its exact ID.",
    ToolName.READ_FILE: "Read one local mock file by its exact ID.",
    ToolName.SEARCH_CALENDAR: "Return mock calendar events on an ISO date (YYYY-MM-DD).",
    ToolName.SEND_EMAIL: "Send a message through the local mock outbox.",
    ToolName.CREATE_CALENDAR_EVENT: "Create an event in the local mock calendar.",
}


class ToolExecutor:
    def __init__(
        self,
        world: MockWorld,
        audit_log: AuditLog,
        taint_tracker: ExactTaintTracker | None = None,
        runtime_provenance: RuntimeProvenance | None = None,
    ) -> None:
        self.world = world
        self.audit_log = audit_log
        self.taint_tracker = taint_tracker
        self.runtime_provenance = runtime_provenance

    def execute(
        self, tool: ToolName | str, arguments: dict[str, Any], actor: str = "action_agent"
    ) -> ToolExecutionResult:
        try:
            tool_name = ToolName(tool)
        except ValueError:
            event = self.audit_log.append(
                EventKind.TOOL_ERROR,
                actor,
                arguments=arguments,
                decision=Decision.DENY,
                reason=f"unknown tool: {tool}",
                success=False,
            )
            return ToolExecutionResult(
                ok=False, tool=None, event_id=event.event_id, error=event.reason
            )

        argument_model = TOOL_ARGUMENT_MODELS[tool_name]
        try:
            validated = argument_model.model_validate(arguments)
            handler: Callable[[_Arguments, str], ToolExecutionResult] = self._handlers[tool_name]
            result = handler(validated, actor)
            if result.ok and self.runtime_provenance is not None:
                event = self.audit_log.get(result.event_id)
                if event.provenance is not None:
                    self.runtime_provenance.observe_tool_output(
                        result.output,
                        event.provenance,
                        origin=event.event_id,
                    )
            return result
        except (ValidationError, ValueError, KeyError) as error:
            event = self.audit_log.append(
                EventKind.TOOL_ERROR,
                actor,
                tool=tool_name,
                arguments=arguments,
                decision=Decision.DENY,
                reason=str(error),
                success=False,
            )
            return ToolExecutionResult(
                ok=False, tool=tool_name, event_id=event.event_id, error=str(error)
            )

    @property
    def _handlers(self) -> dict[ToolName, Callable[[_Arguments, str], ToolExecutionResult]]:
        return {
            ToolName.SEARCH_EMAILS: self._search_emails,
            ToolName.READ_EMAIL: self._read_email,
            ToolName.READ_FILE: self._read_file,
            ToolName.SEARCH_CALENDAR: self._search_calendar,
            ToolName.SEND_EMAIL: self._send_email,
            ToolName.CREATE_CALENDAR_EVENT: self._create_calendar_event,
        }

    def search_emails(self, query: str, actor: str = "reader_agent") -> ToolExecutionResult:
        return self.execute(ToolName.SEARCH_EMAILS, {"query": query}, actor)

    def read_email(self, email_id: str, actor: str = "reader_agent") -> ToolExecutionResult:
        return self.execute(ToolName.READ_EMAIL, {"email_id": email_id}, actor)

    def read_file(self, file_id: str, actor: str = "action_agent") -> ToolExecutionResult:
        return self.execute(ToolName.READ_FILE, {"file_id": file_id}, actor)

    def search_calendar(self, date: str, actor: str = "action_agent") -> ToolExecutionResult:
        return self.execute(ToolName.SEARCH_CALENDAR, {"date": date}, actor)

    def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        cc: tuple[str, ...] = (),
        actor: str = "action_agent",
    ) -> ToolExecutionResult:
        return self.execute(
            ToolName.SEND_EMAIL,
            {"to": to, "subject": subject, "body": body, "cc": cc},
            actor,
        )

    def create_calendar_event(
        self,
        title: str,
        start: str,
        end: str,
        participants: tuple[str, ...] = (),
        location: str = "",
        actor: str = "action_agent",
    ) -> ToolExecutionResult:
        return self.execute(
            ToolName.CREATE_CALENDAR_EVENT,
            {
                "title": title,
                "start": start,
                "end": end,
                "participants": participants,
                "location": location,
            },
            actor,
        )

    def _search_emails(
        self, arguments: SearchEmailsArguments, actor: str
    ) -> ToolExecutionResult:
        emails = self.world.search_emails(arguments.query)
        # Search results intentionally omit bodies, so this event is not payload exposure.
        output = [
            {
                "email_id": email.email_id,
                "sender": email.sender,
                "subject": email.subject,
                "received_at": email.received_at,
            }
            for email in emails
        ]
        provenance = join_provenance(email.provenance for email in emails)
        event = self.audit_log.append(
            EventKind.RESOURCE_READ,
            actor,
            tool=ToolName.SEARCH_EMAILS,
            arguments=arguments.model_dump(mode="json"),
            resource_ids=(email.email_id for email in emails),
            provenance=provenance,
            decision=Decision.ALLOW,
            success=True,
        )
        return ToolExecutionResult(
            ok=True, tool=ToolName.SEARCH_EMAILS, output=output, event_id=event.event_id
        )

    def _read_email(self, arguments: ReadEmailArguments, actor: str) -> ToolExecutionResult:
        email = self.world.read_email(arguments.email_id)
        event = self.audit_log.append(
            EventKind.RESOURCE_READ,
            actor,
            tool=ToolName.READ_EMAIL,
            arguments=arguments.model_dump(mode="json"),
            resource_ids=(email.email_id,),
            provenance=email.provenance,
            decision=Decision.ALLOW,
            success=True,
        )
        if self.taint_tracker:
            self.taint_tracker.observe_read(event.event_id, (email.email_id,))
        return ToolExecutionResult(
            ok=True,
            tool=ToolName.READ_EMAIL,
            output=email.model_dump(mode="json"),
            event_id=event.event_id,
        )

    def _read_file(self, arguments: ReadFileArguments, actor: str) -> ToolExecutionResult:
        record = self.world.read_file(arguments.file_id)
        event = self.audit_log.append(
            EventKind.RESOURCE_READ,
            actor,
            tool=ToolName.READ_FILE,
            arguments=arguments.model_dump(mode="json"),
            resource_ids=(record.file_id,),
            provenance=record.provenance,
            decision=Decision.ALLOW,
            success=True,
        )
        if self.taint_tracker:
            self.taint_tracker.observe_read(event.event_id, (record.file_id,))
        return ToolExecutionResult(
            ok=True,
            tool=ToolName.READ_FILE,
            output=record.model_dump(mode="json"),
            event_id=event.event_id,
        )

    def _search_calendar(
        self, arguments: SearchCalendarArguments, actor: str
    ) -> ToolExecutionResult:
        events = self.world.search_calendar(arguments.date)
        event = self.audit_log.append(
            EventKind.RESOURCE_READ,
            actor,
            tool=ToolName.SEARCH_CALENDAR,
            arguments=arguments.model_dump(mode="json"),
            resource_ids=(item.event_id for item in events),
            provenance=join_provenance(item.provenance for item in events),
            decision=Decision.ALLOW,
            success=True,
        )
        if self.taint_tracker:
            self.taint_tracker.observe_read(event.event_id, (item.event_id for item in events))
        return ToolExecutionResult(
            ok=True,
            tool=ToolName.SEARCH_CALENDAR,
            output=[item.model_dump(mode="json") for item in events],
            event_id=event.event_id,
        )

    def _send_email(self, arguments: SendEmailArguments, actor: str) -> ToolExecutionResult:
        sent = self.world.send_email(**arguments.model_dump())
        event = self.audit_log.append(
            EventKind.WORLD_MUTATION,
            actor,
            tool=ToolName.SEND_EMAIL,
            arguments=arguments.model_dump(mode="json"),
            resource_ids=(sent.message_id,),
            decision=Decision.ALLOW,
            success=True,
        )
        return ToolExecutionResult(
            ok=True,
            tool=ToolName.SEND_EMAIL,
            output=sent.model_dump(mode="json"),
            event_id=event.event_id,
        )

    def _create_calendar_event(
        self, arguments: CreateCalendarEventArguments, actor: str
    ) -> ToolExecutionResult:
        created = self.world.create_calendar_event(**arguments.model_dump())
        event = self.audit_log.append(
            EventKind.WORLD_MUTATION,
            actor,
            tool=ToolName.CREATE_CALENDAR_EVENT,
            arguments=arguments.model_dump(mode="json"),
            resource_ids=(created.event_id,),
            decision=Decision.ALLOW,
            success=True,
        )
        return ToolExecutionResult(
            ok=True,
            tool=ToolName.CREATE_CALENDAR_EVENT,
            output=created.model_dump(mode="json"),
            event_id=event.event_id,
        )
