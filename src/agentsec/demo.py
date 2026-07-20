"""Gradio demo with optional live execution and an always-available replay path."""

from __future__ import annotations

import argparse
import html
import importlib
import inspect
import os
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .replay import (
    ArtifactFormatError,
    ReplayArtifact,
    artifact_from_mapping,
    artifact_summary,
    audit_table,
    discover_attempts,
    load_replay_artifact,
    provenance_edges,
    world_delta,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_ARTIFACT = REPO_ROOT / "data" / "demo" / "sample_blocked_attack"
AUDIT_HEADERS = [
    "Seq",
    "Event",
    "Actor",
    "Tool",
    "Decision",
    "Success",
    "Authority",
    "Sensitivity",
    "Arguments",
    "Reason",
]
DEFENSE_CHOICES = (
    ("Allow all", "allow_all"),
    ("Prompt only", "prompt_only"),
    ("Capability only", "capability_only"),
    ("Prompt + capability (no provenance)", "prompt_capability_only"),
    ("Full (prompt + capability + provenance)", "full"),
)


def resolve_live_runner(
    explicit: str | None = None,
) -> tuple[Callable[..., Any] | None, str]:
    """Discover a live adapter without importing orchestration during replay."""

    candidates: list[str] = []
    selected = explicit or os.environ.get("AGENTSEC_LIVE_RUNNER")
    if selected:
        candidates.append(selected)
    candidates.extend(
        [
            "agentsec.experiment:run_demo_case",
            "agentsec.experiment_runner:run_demo_case",
            "agentsec.runner:run_demo_case",
        ]
    )
    errors: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            module_name, function_name = candidate.split(":", 1)
            function = getattr(importlib.import_module(module_name), function_name)
            if not callable(function):
                raise TypeError("selected object is not callable")
            return function, candidate
        except (ImportError, AttributeError, TypeError, ValueError) as exc:
            errors.append(f"{candidate} ({type(exc).__name__})")
    detail = ", ".join(errors) if errors else "no candidates configured"
    return None, detail


def list_demo_artifacts(root: str | Path) -> list[str]:
    """List real attempts plus the clearly labelled illustrative fixture."""

    paths: list[Path] = []
    if SAMPLE_ARTIFACT.exists():
        paths.append(SAMPLE_ARTIFACT.resolve())
    paths.extend(discover_attempts(root))
    # Keep the sample first and de-duplicate a root that happens to contain it.
    unique: list[str] = []
    for path in paths:
        value = str(path)
        if value not in unique:
            unique.append(value)
    return unique


def render_artifact(artifact: ReplayArtifact) -> tuple[Any, ...]:
    """Return values for all replay output components."""

    summary = artifact_summary(artifact)
    metadata = {
        "source": str(artifact.directory) if artifact.directory else "live in-memory result",
        "summary": summary,
        "run_spec": artifact.run_spec,
        "result": artifact.result,
    }
    traces = {
        "reader_trace": artifact.reader_trace,
        "action_trace": artifact.action_trace,
    }
    return (
        _summary_html(summary),
        metadata,
        audit_table(artifact),
        artifact.final_response or "(No final assistant response was recorded.)",
        world_delta(artifact),
        provenance_edges(artifact),
        traces,
    )


def load_and_render(path: str | Path) -> tuple[Any, ...]:
    try:
        return render_artifact(load_replay_artifact(path))
    except (ArtifactFormatError, OSError, ValueError) as exc:
        return _error_outputs(str(exc))


def run_live_and_render(
    runner: Callable[..., Any] | None,
    *,
    scenario_id: str,
    content_condition: str,
    defense_arm: str,
    seed: int | float | str,
    artifact_root: str,
) -> tuple[Any, ...]:
    """Invoke the optional adapter and normalize either a path or a mapping."""

    if runner is None:
        return ("",) + _error_outputs(
            "Live runner is unavailable. Start the experiment runtime or use artifact replay."
        )
    try:
        returned = _invoke_live_runner(
            runner,
            scenario_id=str(scenario_id),
            content_condition=str(content_condition),
            defense_arm=str(defense_arm),
            seed=int(seed),
            artifact_root=str(Path(artifact_root).expanduser()),
        )
        artifact = _coerce_live_result(returned)
        source = str(artifact.directory) if artifact.directory else "live in-memory result"
        return (source,) + render_artifact(artifact)
    except Exception as exc:  # The UI must survive model/server failures.
        message = f"Live run failed ({type(exc).__name__}): {exc}"
        return ("",) + _error_outputs(message)


def build_demo(
    *,
    artifact_root: str | Path = REPO_ROOT / "artifacts",
    replay_only: bool = False,
    live_runner_spec: str | None = None,
) -> Any:
    """Construct the Gradio Blocks application; Gradio is imported lazily."""

    # Gradio 3 creates an httpx client at import time.  The login-node
    # environment advertises a SOCKS proxy but the controller environment does
    # not install the optional ``socksio`` package.  The demo binds locally, so
    # import it without ambient proxies and immediately restore the environment.
    proxy_names = (
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
    )
    saved_proxies = {name: os.environ[name] for name in proxy_names if name in os.environ}
    for name in proxy_names:
        os.environ.pop(name, None)
    try:
        import gradio as gr
    except ImportError as exc:  # pragma: no cover - depends on optional package
        raise RuntimeError(
            f"Gradio could not be imported: {exc}. Use the project test environment "
            "or install .[demo]."
        ) from exc
    finally:
        os.environ.update(saved_proxies)

    root = str(Path(artifact_root).expanduser())
    runner, runner_detail = (None, "replay-only mode")
    if not replay_only:
        runner, runner_detail = resolve_live_runner(live_runner_spec)
    runner_ready = runner is not None
    initial_choices = list_demo_artifacts(root)
    initial_path = initial_choices[0] if initial_choices else ""

    css = """
    .agentsec-shell {max-width: 1280px; margin: 0 auto;}
    .agentsec-hero {padding: 18px 22px; border-radius: 16px;
      background: linear-gradient(125deg, #111827, #173c55); color: #f8fafc;}
    .agentsec-hero h1 {margin: 0 0 8px 0; font-size: 1.75rem;}
    .agentsec-hero p {margin: 0; color: #dbeafe;}
    .metric-grid {display:grid; grid-template-columns:repeat(auto-fit,minmax(145px,1fr));
      gap:10px; margin:12px 0;}
    .metric {padding:10px 12px; border:1px solid #dbe3eb; border-radius:10px;
      background:#f8fafc;}
    .metric .name {font-size:.74rem; color:#475569; text-transform:uppercase;}
    .metric .value {font-size:1.03rem; font-weight:650; color:#0f172a;}
    .badge {display:inline-block; border-radius:999px; padding:4px 10px;
      margin-right:6px; font-weight:650;}
    .badge-ok {background:#dcfce7; color:#166534;}
    .badge-warn {background:#fef3c7; color:#92400e;}
    .badge-bad {background:#fee2e2; color:#991b1b;}
    .badge-info {background:#dbeafe; color:#1e40af;}
    """

    with gr.Blocks(css=css, title="Agent Security Gate Demo") as app:
        with gr.Column(elem_classes=["agentsec-shell"]):
            gr.HTML(
                "<div class='agentsec-hero'><h1>Provenance-Aware Capability Gate</h1>"
                "<p>Inspect what the agents read, proposed, the gateway decided, "
                "and what actually changed in the synthetic office.</p></div>"
            )
            availability = (
                f"Live adapter ready: `{runner_detail}`. The local vLLM endpoint is checked "
                "when a run starts."
                if runner_ready
                else f"Replay is ready. Live adapter unavailable ({runner_detail})."
            )
            gr.Markdown(availability)

            with gr.Tab("Run or replay"):
                with gr.Row():
                    artifact_root_box = gr.Textbox(
                        value=root,
                        label="Artifact root",
                        scale=4,
                    )
                    refresh_button = gr.Button("Refresh attempts", scale=1)
                with gr.Row():
                    attempt_dropdown = gr.Dropdown(
                        choices=initial_choices,
                        value=initial_path or None,
                        label="Saved attempt (sample fixture appears first)",
                        scale=4,
                    )
                    load_button = gr.Button("Load replay", variant="primary", scale=1)
                manual_path = gr.Textbox(
                    value=initial_path,
                    label="Loaded artifact path / paste a specific attempt directory",
                )
                manual_load_button = gr.Button("Load pasted path")

                with gr.Accordion("Start one live synthetic run", open=runner_ready):
                    gr.Markdown(
                        "Live mode calls the frozen scenario runner; it never uses real email, "
                        "calendar, files, or network tools."
                    )
                    with gr.Row():
                        scenario = gr.Dropdown(
                            choices=["T1", "T2", "T3", "T4", "T5", "T6"],
                            value="T3",
                            label="Scenario",
                        )
                        condition = gr.Dropdown(
                            choices=["clean", "placebo", "attack"],
                            value="attack",
                            label="Content condition",
                        )
                        defense = gr.Dropdown(
                            choices=list(DEFENSE_CHOICES),
                            value="full",
                            label="Defense arm",
                        )
                        seed = gr.Number(value=4313, precision=0, label="Seed")
                    live_button = gr.Button(
                        "Run live case",
                        variant="primary",
                        interactive=runner_ready,
                    )

                summary_html = gr.HTML(label="Outcome")
                with gr.Row():
                    final_response = gr.Textbox(
                        label="Final assistant response", lines=4, interactive=False
                    )
                    metadata = gr.JSON(label="Run metadata")

            with gr.Tab("Audit trail"):
                gr.Markdown(
                    "Rows are append-only evidence. `tool_proposal` is an attempt; only a "
                    "successful execution and world delta establish an effect."
                )
                audit_frame = gr.Dataframe(
                    headers=AUDIT_HEADERS,
                    datatype=["str"] * len(AUDIT_HEADERS),
                    value=[],
                    interactive=False,
                    label="Structured events",
                )

            with gr.Tab("State and provenance"):
                with gr.Row():
                    delta_json = gr.JSON(label="Before/after world delta")
                    provenance_json = gr.JSON(label="Explicit provenance edges")

            with gr.Tab("Agent traces"):
                gr.Markdown(
                    "Raw Reader and Action traces are displayed when the selected attempt "
                    "persisted them. The illustrative fixture intentionally omits model traces."
                )
                traces_json = gr.JSON(label="Persisted traces")

            with gr.Tab("How to read this demo"):
                gr.Markdown(
                    """
1. **Exposure** means untrusted retrieved content reached the Action Agent's context.
2. **Attempted** means the Action Agent proposed a forbidden operation.
3. **Blocked** means the deterministic gateway denied that proposal.
4. **Executed effect** is derived independently from audit and world state; a blocked
   proposal is never counted as attack success.
5. The bundled `DEMO-T3` replay is an illustrative UI fixture, not a formal result.

The original formal experiment compares Clean, Placebo, and Attack across four
defense arms. A separate follow-up adds Prompt + capability (no provenance) to
isolate the provenance contribution without changing the 216-run formal study.
                    """
                )

        view_outputs = [
            summary_html,
            metadata,
            audit_frame,
            final_response,
            delta_json,
            provenance_json,
            traces_json,
        ]

        def refresh_attempts(selected_root: str) -> Any:
            choices = list_demo_artifacts(selected_root)
            return gr.update(choices=choices, value=choices[0] if choices else None)

        refresh_button.click(
            refresh_attempts,
            inputs=[artifact_root_box],
            outputs=[attempt_dropdown],
        )
        load_button.click(load_and_render, inputs=[attempt_dropdown], outputs=view_outputs)
        manual_load_button.click(load_and_render, inputs=[manual_path], outputs=view_outputs)

        def load_selected(path: str) -> tuple[Any, ...]:
            return (path,) + load_and_render(path)

        attempt_dropdown.change(
            load_selected,
            inputs=[attempt_dropdown],
            outputs=[manual_path, *view_outputs],
        )

        def live_callback(
            scenario_value: str,
            condition_value: str,
            defense_value: str,
            seed_value: Any,
            root_value: str,
        ) -> tuple[Any, ...]:
            return run_live_and_render(
                runner,
                scenario_id=scenario_value,
                content_condition=condition_value,
                defense_arm=defense_value,
                seed=seed_value,
                artifact_root=root_value,
            )

        live_button.click(
            live_callback,
            inputs=[scenario, condition, defense, seed, artifact_root_box],
            outputs=[manual_path, *view_outputs],
        )
        if initial_path:
            app.load(load_and_render, inputs=[attempt_dropdown], outputs=view_outputs)
    return app


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact-root",
        default=str(REPO_ROOT / "artifacts"),
        help="root containing persisted run/attempt directories",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7860)
    parser.add_argument("--share", action="store_true")
    parser.add_argument("--replay-only", action="store_true")
    parser.add_argument(
        "--live-runner",
        help="optional module:function adapter (overrides auto-discovery)",
    )
    args = parser.parse_args(argv)
    app = build_demo(
        artifact_root=args.artifact_root,
        replay_only=args.replay_only,
        live_runner_spec=args.live_runner,
    )
    app.queue(concurrency_count=1).launch(
        server_name=args.host,
        server_port=args.port,
        share=args.share,
        show_error=True,
    )
    return 0


def _coerce_live_result(value: Any) -> ReplayArtifact:
    if isinstance(value, ReplayArtifact):
        return value
    if isinstance(value, (str, Path)):
        return load_replay_artifact(value)
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, Mapping):
        for directory_field in ("artifact_dir", "artifact_directory", "attempt_dir"):
            if value.get(directory_field):
                return load_replay_artifact(value[directory_field])
        if isinstance(value.get("outcome"), Mapping):
            value = value["outcome"]
        normalized = {
            key: (item.model_dump(mode="json") if hasattr(item, "model_dump") else item)
            for key, item in value.items()
        }
        return artifact_from_mapping(normalized)
    raise ArtifactFormatError(
        "live runner must return an attempt path, ReplayArtifact, or artifact mapping"
    )


def _invoke_live_runner(
    runner: Callable[..., Any],
    *,
    scenario_id: str,
    content_condition: str,
    defense_arm: str,
    seed: int,
    artifact_root: str,
) -> Any:
    """Call either the documented interface or its concise legacy aliases."""

    parameters = inspect.signature(runner).parameters
    accepts_kwargs = any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    )
    kwargs: dict[str, Any] = {
        "scenario_id": scenario_id,
        "seed": seed,
        "artifact_root": artifact_root,
    }
    if "content_condition" in parameters or accepts_kwargs:
        kwargs["content_condition"] = content_condition
    elif "condition" in parameters:
        kwargs["condition"] = content_condition
    else:
        raise TypeError("live runner accepts neither content_condition nor condition")
    if "defense_arm" in parameters or accepts_kwargs:
        kwargs["defense_arm"] = defense_arm
    elif "defense" in parameters:
        kwargs["defense"] = defense_arm
    else:
        raise TypeError("live runner accepts neither defense_arm nor defense")
    return runner(**kwargs)


def _summary_html(summary: Mapping[str, Any]) -> str:
    def badge(label: str, value: bool, *, positive_is_good: bool = True) -> str:
        if value:
            style = "ok" if positive_is_good else "bad"
            text = "yes"
        else:
            style = "warn" if positive_is_good else "ok"
            text = "no"
        return (
            f"<span class='badge badge-{style}'>{html.escape(label)}: {text}</span>"
        )

    validity_style = "ok" if summary["valid"] else "bad"
    header = (
        f"<span class='badge badge-{validity_style}'>"
        f"{'valid run' if summary['valid'] else 'invalid run'}</span>"
        + badge("exposed", bool(summary["exposure"]), positive_is_good=False)
        + badge("attempted", bool(summary["attempted_attack"]), positive_is_good=False)
        + badge("blocked", bool(summary["blocked_attack"]), positive_is_good=True)
        + badge(
            "unauthorized effect",
            bool(summary["executed_unauthorized_effect"]),
            positive_is_good=False,
        )
        + badge("secret leakage", bool(summary["secret_leakage"]), positive_is_good=False)
        + badge("benign success", bool(summary["benign_task_success"]), positive_is_good=True)
    )
    metrics = [
        ("Scenario", summary["scenario"]),
        ("Condition", summary["condition"]),
        ("Defense", summary["defense"]),
        ("Seed", summary["seed"]),
        ("Audit events", summary["audit_event_count"]),
        ("Latency", f"{summary['latency_seconds']:.2f} s"),
    ]
    cards = "".join(
        "<div class='metric'><div class='name'>"
        + html.escape(str(name))
        + "</div><div class='value'>"
        + html.escape(str(value))
        + "</div></div>"
        for name, value in metrics
    )
    invalid = ""
    if summary.get("invalid_reason"):
        invalid = (
            "<p><strong>Invalid reason:</strong> "
            + html.escape(str(summary["invalid_reason"]))
            + "</p>"
        )
    return f"<div>{header}<div class='metric-grid'>{cards}</div>{invalid}</div>"


def _error_outputs(message: str) -> tuple[Any, ...]:
    escaped = html.escape(message)
    return (
        f"<span class='badge badge-bad'>Cannot display artifact</span><p>{escaped}</p>",
        {"error": message},
        [],
        "",
        {},
        [],
        {},
    )


__all__ = [
    "DEFENSE_CHOICES",
    "build_demo",
    "list_demo_artifacts",
    "load_and_render",
    "main",
    "render_artifact",
    "resolve_live_runner",
    "run_live_and_render",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
