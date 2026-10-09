import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from build_client_delivery import ALLOWED, build


def test_client_package_requires_delivery_gate(tmp_path):
    dist = tmp_path / "dist"
    runtime = tmp_path / "runtime"
    out = tmp_path / "out"
    dist.mkdir()
    runtime.mkdir()
    try:
        build(dist, runtime, out)
        assert False
    except RuntimeError as exc:
        assert "Delivery Gate" in str(exc)


def test_client_package_contains_all_exported_formats_and_excludes_raw_runtime(tmp_path):
    dist = tmp_path / "dist"
    runtime = tmp_path / "runtime"
    out = tmp_path / "out"
    dist.mkdir()
    runtime.mkdir()
    for name in ALLOWED:
        (dist / name).write_bytes(("synthetic " + name).encode("utf-8"))
    (runtime / "assessment.json").write_text('{"secret":"raw"}')
    (runtime / "delivery-gate.json").write_text(
        json.dumps({"status": "ready_for_client_review"})
    )

    result = build(dist, runtime, out)

    assert {item["name"] for item in result["files"]} == ALLOWED
    assert all((out / name).is_file() for name in ALLOWED)
    assert not (out / "assessment.json").exists()
    assert result["branding"] == "SoftwareOne"
    assert all(item["sha256"] for item in result["files"])


def test_client_package_blocks_when_any_export_is_missing(tmp_path):
    dist = tmp_path / "dist"
    runtime = tmp_path / "runtime"
    out = tmp_path / "out"
    dist.mkdir()
    runtime.mkdir()
    (dist / "assessment.html").write_text("<html/>")
    (runtime / "delivery-gate.json").write_text(
        json.dumps({"status": "ready_for_client_review"})
    )

    try:
        build(dist, runtime, out)
        assert False
    except RuntimeError as exc:
        assert "Artefatos obrigatórios ausentes" in str(exc)
