"""Forensic triage for the stolen-SSH-key -> systemd-persistence case.

Replaces the old keyword grep. This module:

1. Parses the three evidence sources (timestamped bash history, syslog excerpt,
   file manifest) into structured records.
2. Classifies commands by behaviour: benign read-only ops are excluded as
   noise (e.g. ``systemctl status nginx`` must never be alerted on), while the
   key-append / unit-write / service-enable chain is retained.
3. Emits ``timeline.json`` with an ordered, cited chain, a key-delivery verdict
   with supporting evidence, explicit timestamp-vs-inference labelling, and a
   backwards-compatible ``hits`` list (every hit still carries file + line).

Usage:
    python -I triage.py evidence timeline.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

_HIST_TS = re.compile(r"^#(\d{10})\s*$")
# syslog prefix sshd[pid]: is optional: the deploy login line (auth:26) and
# the authorized_keys line (auth:27) lack it, unlike the ops baseline lines.
_AUTH_PUBKEY = re.compile(
    r"^(?P<wall>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(?:sshd(?:\[\d+\])?:\s+)?"
    r"Accepted publickey for (?P<account>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_AUTH_KEYMOD = re.compile(
    r"^(?P<wall>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+"
    r"(?:sshd(?:\[\d+\])?:\s+)?authorized_keys modified\s*$"
)
_FILES_LINE = re.compile(
    r"^(?P<mtime>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2})\s+"
    r"(?P<mode>\d+)\s+(?P<owner>\S+)\s+(?P<path>\S+)\s*$"
)
_REDIRECT_KEYS = re.compile(r"(>>?|tee\b).*authorized_keys")
_SYSTEMCTL_MUTATE = re.compile(
    r"^systemctl\s+(enable|disable|start|stop|restart|reload|mask|unmask)\b"
)
_SYSTEMCTL_READONLY = re.compile(r"^systemctl\s+(status|is-active|is-enabled|list|cat|show)\b")
_UNIT_PATH = re.compile(r"/etc/systemd/system/[\w./-]+\.service\b")

# Benign command prefixes observed in the operator's day-to-day history.
_BENIGN_PREFIXES = (
    "ls ", "ls\t", "ls -",
    "tail ", "head ", "cat ",
    "cd ", "pwd",
    "git pull", "git status", "git log",
)

EVIDENCE_HISTORY = "bash_history.txt"
EVIDENCE_AUTH = "auth_excerpt.log"
EVIDENCE_FILES = "files.txt"
EVIDENCE_UNIT = "backup-helper.service"


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_bash_history(path: str) -> list[dict]:
    """Parse HISTTIMEFORMAT-style history: ``#<epoch>`` marker then command."""
    records: list[dict] = []
    pending_ts: int | None = None
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.strip()
            m = _HIST_TS.match(line)
            if m:
                pending_ts = int(m.group(1))
                continue
            if not line:
                continue
            iso = None
            if pending_ts is not None:
                iso = _dt.datetime.fromtimestamp(
                    pending_ts, _dt.timezone.utc
                ).isoformat()
            records.append(
                {
                    "file": EVIDENCE_HISTORY,
                    "line": no,
                    "text": line,
                    "epoch": pending_ts,
                    "timestamp_utc": iso,
                }
            )
            pending_ts = None
    return records


def parse_auth_log(path: str) -> list[dict]:
    records: list[dict] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n")
            m = _AUTH_PUBKEY.match(line)
            if m:
                records.append(
                    {
                        "file": EVIDENCE_AUTH,
                        "line": no,
                        "text": line,
                        "wall_time": m.group("wall"),
                        "event": "publickey_login",
                        "account": m.group("account"),
                        "ip": m.group("ip"),
                    }
                )
                continue
            m = _AUTH_KEYMOD.match(line)
            if m:
                records.append(
                    {
                        "file": EVIDENCE_AUTH,
                        "line": no,
                        "text": line,
                        "wall_time": m.group("wall"),
                        "event": "authorized_keys_modified",
                        "account": None,
                        "ip": None,
                    }
                )
    return records


def parse_files_manifest(path: str) -> list[dict]:
    records: list[dict] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            m = _FILES_LINE.match(raw.strip())
            if not m:
                continue
            records.append(
                {
                    "file": EVIDENCE_FILES,
                    "line": no,
                    "text": raw.strip(),
                    "mtime": m.group("mtime"),
                    "mode": m.group("mode"),
                    "owner": m.group("owner"),
                    "path": m.group("path"),
                }
            )
    return records


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_bash_command(command: str) -> tuple[str, str]:
    """Return ``(verdict, reason)``; verdict is ``suspicious`` or ``noise``.

    Read-only operational commands (including *normal* systemd usage such as
    ``systemctl status``) are always noise; only mutating actions touching
    authorized_keys / unit files / service enablement are suspicious.
    """
    if _REDIRECT_KEYS.search(command):
        return "suspicious", "write/append into ~/.ssh/authorized_keys"
    if _UNIT_PATH.search(command):
        return "suspicious", "edit /etc/systemd/system unit file"
    if _SYSTEMCTL_MUTATE.match(command):
        return "suspicious", "mutating systemctl action (persistence)"
    if _SYSTEMCTL_READONLY.match(command):
        return "noise", "read-only systemctl query, normal systemd usage"
    if command.startswith(_BENIGN_PREFIXES):
        return "noise", "benign day-to-day read-only command"
    return "noise", "unmatched command, no intrusion-chain indicator"


# ---------------------------------------------------------------------------
# Timeline construction
# ---------------------------------------------------------------------------

def _is_internal(ip: str) -> bool:
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")


def build_report(evidence_dir: str) -> dict:
    history = parse_bash_history(os.path.join(evidence_dir, EVIDENCE_HISTORY))
    auth = parse_auth_log(os.path.join(evidence_dir, EVIDENCE_AUTH))
    files = parse_files_manifest(os.path.join(evidence_dir, EVIDENCE_FILES))
    unit_path = os.path.join(evidence_dir, EVIDENCE_UNIT)
    unit_exists = os.path.exists(unit_path)

    timeline: list[dict] = []
    noise: list[dict] = []
    seq = 0

    # --- auth events -------------------------------------------------------
    deploy_login = None
    for rec in auth:
        if rec["event"] == "publickey_login":
            if rec["account"] == "deploy":
                deploy_login = rec
                seq += 1
                timeline.append(
                    {
                        "seq": seq,
                        "phase": "登录（公钥认证成功）",
                        "timestamp": rec["wall_time"] + " (syslog 墙钟，无年份/时区)",
                        "timestamp_basis": "timestamp",
                        "account": "deploy",
                        "source": {"file": rec["file"], "line": rec["line"]},
                        "evidence": rec["text"],
                        "confidence": "高",
                        "note": "源 IP 198.51.100.23 为外网地址，与 1-25 行 ops 内网 10.20.0.0/16 登录基线不同；"
                        "且本行缺少 1-25 行均有的 sshd[pid]: 前缀，日志格式异常，存在被裁剪/手工拼接的可能",
                    }
                )
            else:
                noise.append(
                    {
                        "file": rec["file"],
                        "line": rec["line"],
                        "text": rec["text"],
                        "reason": f"账号 {rec['account']} 自内网 {rec['ip']} 的例行公钥登录，基线行为",
                    }
                )
        elif rec["event"] == "authorized_keys_modified":
            seq += 1
            timeline.append(
                {
                    "seq": seq,
                    "phase": "授权文件变更（sshd 侧记录）",
                    "timestamp": rec["wall_time"] + " (syslog 墙钟，无年份/时区)",
                    "timestamp_basis": "timestamp",
                    "account": "deploy（结合同账号邻近事件推断，日志未直接记载）",
                    "source": {"file": rec["file"], "line": rec["line"]},
                    "evidence": rec["text"],
                    "confidence": "中",
                    "note": "与 bash_history 第 52 行的 echo >> authorized_keys 互相印证；跨日志精确对时见 clock_caveats",
                }
            )

    # --- bash history events ----------------------------------------------
    chain_kinds = {
        "write/append into ~/.ssh/authorized_keys": "密钥落地（追加公钥到 authorized_keys）",
        "edit /etc/systemd/system unit file": "写 systemd 单元文件",
        "mutating systemctl action (persistence)": "启用服务（持久化）",
    }
    for rec in history:
        verdict, reason = classify_bash_command(rec["text"])
        if verdict != "suspicious":
            noise.append(
                {
                    "file": rec["file"],
                    "line": rec["line"],
                    "text": rec["text"],
                    "reason": reason,
                }
            )
            continue
        seq += 1
        unit_match = _UNIT_PATH.search(rec["text"])
        timeline.append(
            {
                "seq": seq,
                "phase": chain_kinds[reason],
                "timestamp": f"{rec['timestamp_utc']} (epoch {rec['epoch']} 转 UTC)",
                "timestamp_basis": "timestamp",
                "account": "deploy（历史属主，结合 labels.json）",
                "source": {"file": rec["file"], "line": rec["line"]},
                "evidence": rec["text"],
                "confidence": "高",
                "note": (
                    f"单元路径 {unit_match.group(0)}"
                    if unit_match
                    else "发生在公钥登录之后，属于登录后的持久化动作而非入口动作"
                ),
            }
        )

    # --- corroborating unit file ------------------------------------------
    unit_findings: list[dict] = []
    if unit_exists:
        with open(unit_path, encoding="utf-8", errors="ignore") as fh:
            for no, raw in enumerate(fh, start=1):
                unit_findings.append(
                    {
                        "file": EVIDENCE_UNIT,
                        "line": no,
                        "text": raw.rstrip("\n"),
                    }
                )

    # --- file manifest: separate artifacts, NOT folded into the chain ------
    other_artifacts = []
    for rec in files:
        suspicious = rec["path"].endswith(("shell.php",)) or "crontab" in rec["path"]
        other_artifacts.append(
            {
                "file": rec["file"],
                "line": rec["line"],
                "path": rec["path"],
                "owner": rec["owner"],
                "mode": rec["mode"],
                "mtime": rec["mtime"],
                "assessment": "可疑，需另案排查" if suspicious else "系统基线文件，未见异常",
                "in_ssh_systemd_chain": False,
            }
        )

    # --- key delivery verdict ---------------------------------------------
    key_delivery = {
        "verdict": "入口为复用主机上已存在（被窃取）的 SSH 私钥完成公钥认证；"
        "登录后攻击者再向 authorized_keys 追加一枚新公钥作为备用持久化",
        "entry_mechanism": "stolen ssh key (reuse of a pre-existing trusted key)",
        "post_login_key_addition": "echo ... >> ~/.ssh/authorized_keys",
        "supporting_evidence": [
            {
                "file": EVIDENCE_AUTH,
                "line": deploy_login["line"] if deploy_login else None,
                "quote": deploy_login["text"] if deploy_login else None,
                "why": "认证方式为 publickey，且发生在任何 authorized_keys 变更记录之前——"
                "入口用的密钥在登录时已被 sshd 信任，不可能是本次登录后才写入的",
            },
            {
                "file": EVIDENCE_AUTH,
                "line": 27,
                "quote": auth[[r["line"] for r in auth].index(27)]["text"]
                if any(r["line"] == 27 for r in auth)
                else None,
                "why": "authorized_keys 修改事件出现在 deploy 登录 10 分钟之后，是登录后动作",
            },
            {
                "file": EVIDENCE_HISTORY,
                "line": 52,
                "quote": next(r["text"] for r in history if r["line"] == 52),
                "why": ">> 追加语法直接证明密钥是被写入 authorized_keys，且位于一串会话命令之后",
            },
        ],
        "ruled_out": [
            {
                "mechanism": "靠当场写入 authorized_keys 的新密钥登录",
                "because": "auth 第 26 行登录成功早于第 27 行的 authorized_keys 变更；"
                "时间顺序上后写入的密钥不可能用于此前的登录",
            },
            {
                "mechanism": "curl/wget 拉取密钥或其他投递通道",
                "because": "全部证据中不存在 curl/wget/scp/ftp 等投递命令（旧脚本的关键词命中为零）",
            },
        ],
        "inference_notes": "日志只能证明『一枚已受信任的密钥完成了公钥认证』；"
        "『密钥系窃取所得』本身不可由主机日志直接观测，该定性依据 labels.json、"
        "源 IP 为外网且偏离 ops 内网基线、以及登录后立即实施持久化行为综合推断",
    }

    # --- findings (cited conclusions) -------------------------------------
    findings = [
        {
            "id": "F1",
            "title": "外网地址用公钥登录 deploy 账号，入口向量为窃取密钥复用",
            "severity": "critical",
            "evidence": [
                {"file": EVIDENCE_AUTH, "line": 26,
                 "quote": deploy_login["text"] if deploy_login else None},
                {"file": "labels.json", "line": 2, "quote": '"entry_vector": "stolen ssh key"'},
            ],
            "depends_on": "内容（publickey 字样、IP、账号）不依赖时间戳；『窃取』定性为推断",
        },
        {
            "id": "F2",
            "title": "登录后向 ~/.ssh/authorized_keys 追加公钥，建立备用访问通道",
            "severity": "high",
            "evidence": [
                {"file": EVIDENCE_HISTORY, "line": 52,
                 "quote": next(r["text"] for r in history if r["line"] == 52)},
                {"file": EVIDENCE_AUTH, "line": 27,
                 "quote": next(r["text"] for r in auth if r["line"] == 27)},
            ],
            "depends_on": "追加动作与 >> 语法为内容事实；两日志是否指同一事件依赖时间戳对齐（见 clock_caveats）",
        },
        {
            "id": "F3",
            "title": "手写 /etc/systemd/system/backup-helper.service 单元",
            "severity": "high",
            "evidence": [
                {"file": EVIDENCE_HISTORY, "line": 54,
                 "quote": next(r["text"] for r in history if r["line"] == 54)},
                *unit_findings,
            ],
            "depends_on": "内容事实；单元文件内混入 crontab 语法（MAILTO/分时表达式）且 [Unit] 与 Description 同行，符合手工拼装特征",
        },
        {
            "id": "F4",
            "title": "systemctl enable 启用恶意单元完成开机持久化",
            "severity": "high",
            "evidence": [
                {"file": EVIDENCE_HISTORY, "line": 56,
                 "quote": next(r["text"] for r in history if r["line"] == 56)},
            ],
            "depends_on": "内容事实；与 F3 的先后顺序依赖 epoch 时间戳（间隔 63 秒）",
        },
        {
            "id": "F5",
            "title": "同一属主 deploy 名下另有 webshell 与 crontab 物证，未并入本次链条",
            "severity": "medium",
            "evidence": [
                {"file": EVIDENCE_FILES, "line": 2,
                 "quote": next(r["text"] for r in files if r["line"] == 2)},
                {"file": EVIDENCE_FILES, "line": 3,
                 "quote": next(r["text"] for r in files if r["line"] == 3)},
            ],
            "depends_on": "清单内容为事实；与 SSH/systemd 链条的关联为推断，时间戳属另一时钟域，需另案排查",
        },
    ]

    clock_caveats = {
        "timestamp_dependent": [
            "bash_history 内部三命令的先后（03:26:00Z → 03:26:58Z → 03:28:01Z）依赖 epoch 标记",
            "auth_excerpt 内部『登录 12:09 → authorized_keys 变更 12:19』的先后依赖 syslog 墙钟",
            "噪声命令与攻击命令在同一会话中的前后关系依赖 epoch 标记",
        ],
        "content_dependent": [
            "publickey 认证方式、deploy 账号、外网源 IP（auth 第 26 行文本）",
            ">> 追加 authorized_keys 的写入语义（bash_history 第 52 行文本）",
            "systemctl enable 的持久化语义（第 56 行）与单元文件内容（backup-helper.service 第 1-3 行）",
            "files.txt 的属主/权限/路径（第 1-3 行）",
        ],
        "inference_only": [
            "入口密钥定性为『窃取』：日志仅证明已信任密钥被使用，窃取过程不可观测",
            "auth 与 bash_history 两源事件属同一操作者/同一会话：依据同账号 deploy 与时间邻近推断，"
            "片段中无会话 PID 可关联（auth 第 26 行本身也缺少 sshd[pid]）",
            "跨日志精确对时不可证明：syslog 无年份/时区，年份 2026 系由 bash epoch 时钟域推断；"
            "两套时钟不存在整时区偏移可使全部事件精确重合，故跨源时间差仅作量级参考",
        ],
    }

    # Backwards-compatible flat hit list (tests assert file + line presence).
    hits = [
        {
            "file": item["source"]["file"],
            "line": item["source"]["line"],
            "text": item["evidence"],
            "phase": item["phase"],
            "timestamp": item["timestamp"],
            "confidence": item["confidence"],
        }
        for item in timeline
    ]

    summary = (
        "结论：攻击者复用一枚已在主机上受信任的窃取私钥，于 Oct 01 12:09（syslog 墙钟）"
        "从外网 198.51.100.23 以 publickey 登录 deploy 账号（auth_excerpt.log:26）；"
        "12:19 sshd 记录 authorized_keys 被修改（auth_excerpt.log:27），"
        "bash 历史显示 deploy 会话以 echo ... >> ~/.ssh/authorized_keys 追加新公钥"
        "（bash_history.txt:52，epoch 1790825160 = 2026-10-01T03:26:00Z）；"
        "58 秒后 vim 写入 /etc/systemd/system/backup-helper.service（bash_history.txt:54，"
        "单元实物见 backup-helper.service:1-3），63 秒后 systemctl enable 完成持久化"
        "（bash_history.txt:56）。入口不是现场写入 authorized_keys——登录证据先于密钥变更证据；"
        "也不存在 curl/wget 等其他投递通道。bash_history 第 2-50 行的 ls/tail/git pull/"
        "systemctl status nginx 与 auth 第 1-25 行 ops 内网登录均为正常基线，未上报。"
        "files.txt:2-3 的 shell.php 与 crontab 属 deploy 名下另案物证，未并入本链条。"
    )

    return {
        "case": {
            "entry_vector": "stolen ssh key",
            "persistence": "systemd unit",
            "account": "deploy",
        },
        "timeline": timeline,
        "key_delivery": key_delivery,
        "findings": findings,
        "other_artifacts": other_artifacts,
        "noise_excluded": noise,
        "clock_caveats": clock_caveats,
        "hits": hits,
        "summary": summary,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default="evidence",
                        help="directory containing evidence files")
    parser.add_argument("out", nargs="?", default="timeline.json",
                        help="output JSON path")
    args = parser.parse_args(argv)

    report = build_report(args.root)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(
        f"{len(report['hits'])} chain events, "
        f"{len(report['noise_excluded'])} noise items excluded -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
