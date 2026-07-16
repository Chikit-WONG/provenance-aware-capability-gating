"""Small, explicit client for an OpenAI-compatible vLLM endpoint.

The project deliberately uses :mod:`httpx` directly instead of an SDK.  That
keeps the bytes sent to vLLM visible, makes timeout/HTTP/parse failures distinct
in the experiment record, and avoids an SDK silently enabling streaming or
retrying a request.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field


DEFAULT_BASE_URL = "http://127.0.0.1:8000/v1"
DEFAULT_MODEL_NAME = "qwen3-vl-8b"
DEFAULT_MODEL_PATH = (
    "/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/"
    "models/Qwen3-VL-8B-Instruct"
)


class ModelClientError(RuntimeError):
    """Base class for failures before a valid assistant turn is available."""


class ModelTimeoutError(ModelClientError):
    """The model server did not answer before the declared timeout."""


class ModelHTTPError(ModelClientError):
    """The model endpoint returned an HTTP or transport failure."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class ModelResponseError(ModelClientError):
    """The endpoint answered, but its chat-completion payload was malformed."""


class ToolCallParseError(ModelResponseError):
    """A model-proposed function call did not contain object JSON arguments."""


class ToolCall(BaseModel):
    """Normalized model-proposed function call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    type: Literal["function"] = "function"

    def as_openai(self) -> dict[str, Any]:
        """Return the assistant-message representation expected by vLLM."""

        return {
            "id": self.id,
            "type": self.type,
            "function": {
                "name": self.name,
                "arguments": json.dumps(
                    self.arguments, ensure_ascii=False, separators=(",", ":")
                ),
            },
        }


class AssistantTurn(BaseModel):
    """Normalized non-streaming response from one model call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    finish_reason: str | None = None
    usage: dict[str, int] = Field(default_factory=dict)
    response_id: str | None = None
    raw_response: dict[str, Any] | None = None

    def as_openai(self) -> dict[str, Any]:
        message: dict[str, Any] = {
            "role": "assistant",
            "content": self.content or None,
        }
        if self.tool_calls:
            message["tool_calls"] = [call.as_openai() for call in self.tool_calls]
        return message


class ChatModel(Protocol):
    """Interface shared by the HTTP client and deterministic test doubles."""

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        tools: Sequence[Mapping[str, Any]] | None = None,
        seed: int | None = None,
        temperature: float = 0.0,
        top_p: float = 1.0,
        max_tokens: int = 1024,
        tool_choice: str | Mapping[str, Any] | None = None,
    ) -> AssistantTurn:
        """Return exactly one non-streaming assistant turn."""


class OpenAIModelClient:
    """Synchronous OpenAI-compatible chat-completion client for local vLLM.

    No automatic retry is performed.  The orchestrator owns attempts and must
    start each retry from a fresh world, so a library-level retry could otherwise
    make the evidence ambiguous.
    """

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL_NAME,
        api_key: str = "EMPTY",
        timeout: float | httpx.Timeout = 120.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=timeout,
            # The endpoint is deliberately local.  Cluster login/compute nodes
            # may export SOCKS proxy variables without the optional socksio
            # package, so inheriting proxy configuration would both fail and
            # violate the offline-runtime boundary.
            trust_env=False,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )

    @property
    def endpoint(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> OpenAIModelClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        tools: Sequence[Mapping[str, Any]] | None = None,
        seed: int | None = None,
        temperature: float = 0.0,
        top_p: float = 1.0,
        max_tokens: int = 1024,
        tool_choice: str | Mapping[str, Any] | None = None,
    ) -> AssistantTurn:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [dict(message) for message in messages],
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if tools is not None:
            payload["tools"] = [dict(tool) for tool in tools]
            payload["tool_choice"] = tool_choice if tool_choice is not None else "auto"
        elif tool_choice is not None:
            payload["tool_choice"] = tool_choice
        if seed is not None:
            payload["seed"] = seed

        try:
            response = self._client.post(self.endpoint, json=payload)
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise ModelTimeoutError(f"model request timed out: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:1000]
            raise ModelHTTPError(
                f"model server returned HTTP {exc.response.status_code}: {body}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.HTTPError as exc:
            raise ModelHTTPError(f"model transport failed: {exc}") from exc

        try:
            data = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise ModelResponseError("model response was not JSON") from exc
        return parse_chat_completion(data)

    # A descriptive alias is convenient in scripts and external callers.
    chat_completion = complete


class StubModelClient:
    """Deterministic FIFO/callback model used by unit and truth-table tests."""

    def __init__(
        self,
        responses: Sequence[AssistantTurn | Exception]
        | Callable[..., AssistantTurn],
    ) -> None:
        self._callback = responses if callable(responses) else None
        self._responses = [] if callable(responses) else list(responses)
        self.requests: list[dict[str, Any]] = []

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        tools: Sequence[Mapping[str, Any]] | None = None,
        seed: int | None = None,
        temperature: float = 0.0,
        top_p: float = 1.0,
        max_tokens: int = 1024,
        tool_choice: str | Mapping[str, Any] | None = None,
    ) -> AssistantTurn:
        request = {
            "messages": [dict(message) for message in messages],
            "tools": [dict(tool) for tool in tools] if tools is not None else None,
            "seed": seed,
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens,
            "tool_choice": tool_choice,
        }
        self.requests.append(request)
        if self._callback is not None:
            return self._callback(**request)
        if not self._responses:
            raise AssertionError("StubModelClient has no response left")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    chat_completion = complete


def parse_chat_completion(payload: Any) -> AssistantTurn:
    """Validate and normalize the subset of the OpenAI response we persist."""

    if not isinstance(payload, Mapping):
        raise ModelResponseError("chat completion must be a JSON object")
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ModelResponseError("chat completion has no choices")
    choice = choices[0]
    if not isinstance(choice, Mapping):
        raise ModelResponseError("first chat-completion choice is not an object")
    message = choice.get("message")
    if not isinstance(message, Mapping):
        raise ModelResponseError("first choice has no assistant message")

    raw_content = message.get("content")
    if raw_content is None:
        content = ""
    elif isinstance(raw_content, str):
        content = raw_content
    else:
        raise ModelResponseError("assistant content must be a string or null")

    raw_calls = message.get("tool_calls") or []
    if not isinstance(raw_calls, list):
        raise ToolCallParseError("assistant tool_calls must be a list")
    calls: list[ToolCall] = []
    for index, raw_call in enumerate(raw_calls):
        if not isinstance(raw_call, Mapping):
            raise ToolCallParseError(f"tool call {index} is not an object")
        function = raw_call.get("function")
        if not isinstance(function, Mapping):
            raise ToolCallParseError(f"tool call {index} has no function object")
        name = function.get("name")
        if not isinstance(name, str) or not name:
            raise ToolCallParseError(f"tool call {index} has no function name")
        arguments = function.get("arguments", {})
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError as exc:
                raise ToolCallParseError(
                    f"tool call {index} ({name}) arguments are invalid JSON"
                ) from exc
        if not isinstance(arguments, dict):
            raise ToolCallParseError(
                f"tool call {index} ({name}) arguments must be a JSON object"
            )
        call_id = raw_call.get("id")
        if not isinstance(call_id, str) or not call_id:
            call_id = f"call_{index}"
        call_type = raw_call.get("type", "function")
        if call_type != "function":
            raise ToolCallParseError(f"tool call {index} has unsupported type")
        calls.append(ToolCall(id=call_id, name=name, arguments=arguments))

    raw_usage = payload.get("usage") or {}
    usage: dict[str, int] = {}
    if isinstance(raw_usage, Mapping):
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = raw_usage.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                usage[key] = value

    response_id = payload.get("id")
    return AssistantTurn(
        content=content,
        tool_calls=tuple(calls),
        finish_reason=(
            str(choice["finish_reason"])
            if choice.get("finish_reason") is not None
            else None
        ),
        usage=usage,
        response_id=response_id if isinstance(response_id, str) else None,
        raw_response=dict(payload),
    )


# Backwards-friendly explicit name for callers that prefer to emphasize the API.
OpenAICompatibleClient = OpenAIModelClient


__all__ = [
    "AssistantTurn",
    "ChatModel",
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL_NAME",
    "DEFAULT_MODEL_PATH",
    "ModelClientError",
    "ModelHTTPError",
    "ModelResponseError",
    "ModelTimeoutError",
    "OpenAICompatibleClient",
    "OpenAIModelClient",
    "StubModelClient",
    "ToolCall",
    "ToolCallParseError",
    "parse_chat_completion",
]
