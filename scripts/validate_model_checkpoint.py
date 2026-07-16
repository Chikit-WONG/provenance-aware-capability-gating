#!/usr/bin/env python3
"""Validate the local Qwen checkpoint structure without loading tensors."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


DEFAULT_MODEL = Path(
    "/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/"
    "Qwen3-VL-8B-Instruct"
)


def validate(model_dir: Path) -> dict[str, object]:
    config_path = model_dir / "config.json"
    index_path = model_dir / "model.safetensors.index.json"
    required = [
        config_path,
        index_path,
        model_dir / "tokenizer.json",
        model_dir / "tokenizer_config.json",
        model_dir / "chat_template.json",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing checkpoint files: {missing}")

    config = json.loads(config_path.read_text(encoding="utf-8"))
    index = json.loads(index_path.read_text(encoding="utf-8"))
    weight_map: dict[str, str] = index["weight_map"]
    expected_files = sorted(set(weight_map.values()))
    file_reports: list[dict[str, object]] = []
    seen_keys: set[str] = set()

    for filename in expected_files:
        path = model_dir / filename
        if not path.is_file():
            raise FileNotFoundError(f"missing weight shard: {path}")
        with path.open("rb") as handle:
            header_size_bytes = handle.read(8)
            if len(header_size_bytes) != 8:
                raise ValueError(f"truncated safetensors prefix: {path}")
            header_size = struct.unpack("<Q", header_size_bytes)[0]
            header = json.loads(handle.read(header_size))
        keys = set(header) - {"__metadata__"}
        expected_keys = {key for key, shard in weight_map.items() if shard == filename}
        max_end = max(
            value["data_offsets"][1]
            for key, value in header.items()
            if key != "__metadata__"
        )
        payload_size = path.stat().st_size - 8 - header_size
        if keys != expected_keys:
            raise ValueError(f"tensor/index mismatch in {filename}")
        if max_end > payload_size:
            raise ValueError(f"tensor data exceeds shard size in {filename}")
        seen_keys.update(keys)
        file_reports.append(
            {
                "file": filename,
                "bytes": path.stat().st_size,
                "tensors": len(keys),
                "header_ok": True,
            }
        )

    template = (model_dir / "chat_template.json").read_text(encoding="utf-8")
    if seen_keys != set(weight_map):
        raise ValueError("checkpoint tensor set does not match the index")
    if not all(token in template for token in ("tools", "<tool_call>", "tool_response")):
        raise ValueError("checkpoint chat template lacks expected tool-call support")

    return {
        "valid": True,
        "model_dir": str(model_dir.resolve()),
        "model_type": config.get("model_type"),
        "architectures": config.get("architectures"),
        "dtype": config.get("text_config", {}).get("dtype"),
        "indexed_weight_bytes": index.get("metadata", {}).get("total_size"),
        "weight_shards": file_reports,
        "tensor_count": len(seen_keys),
        "tool_template": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    args = parser.parse_args()
    print(json.dumps(validate(args.model), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

