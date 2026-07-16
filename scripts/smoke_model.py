#!/usr/bin/env python3
"""Exercise text completion and Hermes tool parsing against the local server."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from agentsec.model_client import (  # noqa: E402
    DEFAULT_BASE_URL,
    DEFAULT_MODEL_NAME,
    OpenAIModelClient,
)


ECHO_TOOL = {
    "type": "function",
    "function": {
        "name": "echo",
        "description": "Return the supplied text unchanged.",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": False,
        },
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--model", default=DEFAULT_MODEL_NAME)
    parser.add_argument("--timeout", type=float, default=180.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with OpenAIModelClient(
        base_url=args.base_url,
        model=args.model,
        timeout=args.timeout,
    ) as client:
        text_turn = client.complete(
            [
                {"role": "system", "content": "Answer with exactly: MODEL_OK"},
                {"role": "user", "content": "Health check."},
            ],
            seed=4313,
            temperature=0.0,
            max_tokens=32,
        )
        if "MODEL_OK" not in text_turn.content:
            raise RuntimeError(
                f"unexpected text response: {text_turn.content!r}"
            )

        tool_turn = client.complete(
            [
                {
                    "role": "system",
                    "content": "Call the requested function once; do not answer in prose.",
                },
                {"role": "user", "content": "Call echo with text MODEL_TOOL_OK."},
            ],
            tools=[ECHO_TOOL],
            tool_choice={"type": "function", "function": {"name": "echo"}},
            seed=4313,
            temperature=0.0,
            max_tokens=128,
        )
        if len(tool_turn.tool_calls) != 1:
            raise RuntimeError(
                f"expected one parsed tool call, got {len(tool_turn.tool_calls)}"
            )
        call = tool_turn.tool_calls[0]
        if call.name != "echo" or call.arguments != {"text": "MODEL_TOOL_OK"}:
            raise RuntimeError(f"unexpected parsed tool call: {call.model_dump()}")

    print(
        json.dumps(
            {
                "ok": True,
                "model": args.model,
                "base_url": args.base_url,
                "text_usage": text_turn.usage,
                "tool_usage": tool_turn.usage,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
