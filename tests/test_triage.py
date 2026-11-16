import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import triage  # noqa: E402


def run(tmp_path):
    out = tmp_path / "timeline.json"
    r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "triage.py"),
                        os.path.join(ROOT, "evidence"), str(out)],
                       capture_output=True, text=True)
    return r, out


def _report():
    return triage.build_report(os.path.join(ROOT, "evidence"))


def test_evidence_present():
    for name in ("bash_history.txt", "auth_excerpt.log", "files.txt"):
        assert os.path.exists(os.path.join(ROOT, "evidence", name))


def test_labels_have_entry_and_persistence():
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        labels = json.load(fh)
    assert labels["entry_vector"]
    assert labels["persistence"]


def test_triage_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "hits" in json.loads(out.read_text(encoding="utf-8"))


def test_hits_have_file_and_line(tmp_path):
    _, out = run(tmp_path)
    for h in json.loads(out.read_text(encoding="utf-8"))["hits"]:
        assert h.get("file") and h.get("line")


# ---------------------------------------------------------------------------
# Behavioural tests for the forensic requirements
# ---------------------------------------------------------------------------

def test_chain_is_ordered_login_key_unit_enable():
    report = _report()
    sources = [(e["source"]["file"], e["source"]["line"]) for e in report["timeline"]]
    # login -> authorized_keys change (sshd) -> key append -> unit write -> enable
    assert sources == [
        ("auth_excerpt.log", 26),
        ("auth_excerpt.log", 27),
        ("bash_history.txt", 52),
        ("bash_history.txt", 54),
        ("bash_history.txt", 56),
    ]
    phases = [e["phase"] for e in report["timeline"]]
    assert "登录" in phases[0]
    assert "密钥落地" in phases[2]
    assert "写 systemd" in phases[3]
    assert "启用服务" in phases[4]


def test_benign_commands_are_noise_not_hits():
    report = _report()
    hit_refs = {(h["file"], h["line"]) for h in report["hits"]}
    # lines 2-50 of bash history are benign day-to-day work
    benign_lines = {2, 4, 6, 8, 10, 12, 14, 16, 26, 32, 34, 36, 38, 40, 48, 50}
    for ln in benign_lines:
        assert ("bash_history.txt", ln) not in hit_refs
    # explicit check: normal read-only systemd usage must never be alerted
    assert not any("systemctl status" in h["text"] for h in report["hits"])
    noise_refs = {(n["file"], n["line"]) for n in report["noise_excluded"]}
    assert ("bash_history.txt", 8) in noise_refs      # systemctl status nginx
    assert ("bash_history.txt", 26) in noise_refs     # git pull
    # all 25 benign ops logins excluded from the chain too
    auth_noise = [n for n in report["noise_excluded"] if n["file"] == "auth_excerpt.log"]
    assert len(auth_noise) == 25


def test_key_delivery_verdict_is_reuse_with_cited_evidence():
    report = _report()
    kd = report["key_delivery"]
    assert "stolen ssh key" in kd["entry_mechanism"]
    cited = {(e["file"], e["line"]) for e in kd["supporting_evidence"]}
    assert ("auth_excerpt.log", 26) in cited
    assert ("auth_excerpt.log", 27) in cited
    assert ("bash_history.txt", 52) in cited
    # written-key login must be explicitly ruled out with a reason
    assert any("authorized_keys" in r["mechanism"] for r in kd["ruled_out"])
    assert kd["inference_notes"]


def test_every_finding_is_cited_with_file_and_line():
    report = _report()
    assert report["findings"]
    for f in report["findings"]:
        assert f["evidence"], f["id"]
        for e in f["evidence"]:
            assert e["file"] and isinstance(e["line"], int)
    # the three must_cite sources from labels.json all appear somewhere
    cited_files = {e["file"] for f in report["findings"] for e in f["evidence"]}
    cited_files |= {h["file"] for h in report["hits"]}
    for name in ("bash_history.txt", "auth_excerpt.log", "files.txt"):
        assert name in cited_files


def test_clock_caveats_separate_timestamp_dependent_from_inference():
    report = _report()
    cc = report["clock_caveats"]
    assert cc["timestamp_dependent"]
    assert cc["inference_only"]
    assert cc["content_dependent"]
    # timeline entries themselves declare whether they rest on timestamps
    for event in report["timeline"]:
        assert event["timestamp_basis"] == "timestamp"


def test_other_artifacts_kept_out_of_main_chain():
    report = _report()
    paths = {a["path"]: a for a in report["other_artifacts"]}
    assert paths["/var/www/html/uploads/shell.php"]["in_ssh_systemd_chain"] is False
    assert "可疑" in paths["/var/www/html/uploads/shell.php"]["assessment"]
    assert paths["/etc/passwd"]["assessment"] == "系统基线文件，未见异常"
    # manifest artifacts must not leak into hits
    assert all(h["file"] != "files.txt" for h in report["hits"])


def test_summary_names_citations():
    report = _report()
    for token in ("auth_excerpt.log:26", "auth_excerpt.log:27",
                  "bash_history.txt:52", "bash_history.txt:54",
                  "bash_history.txt:56"):
        assert token in report["summary"]
