import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from build_client_delivery import build


def test_client_package_requires_delivery_gate(tmp_path):
    dist=tmp_path/"dist"; runtime=tmp_path/"runtime"; out=tmp_path/"out"
    dist.mkdir(); runtime.mkdir()
    try:
        build(dist,runtime,out)
        assert False
    except RuntimeError as exc:
        assert "Delivery Gate" in str(exc)


def test_client_package_excludes_raw_runtime(tmp_path):
    dist=tmp_path/"dist"; runtime=tmp_path/"runtime"; out=tmp_path/"out"
    dist.mkdir(); runtime.mkdir()
    (dist/"assessment.pdf").write_bytes(b"pdf")
    (runtime/"assessment.json").write_text('{"secret":"raw"}')
    (runtime/"delivery-gate.json").write_text(json.dumps({"status":"ready_for_client_review"}))
    result=build(dist,runtime,out)
    assert (out/"assessment.pdf").exists()
    assert not (out/"assessment.json").exists()
    assert result["branding"] == "SoftwareOne"
    assert result["files"][0]["sha256"]
