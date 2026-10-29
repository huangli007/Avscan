"""解析器自检。

扫毒工具最危险的缺陷不是漏扫，而是「跑完了但读不懂输出，然后报无毒」。
这里用构造样本逐个验证解析器：该判检出时必须判检出，读不懂时必须判未知，
绝不能把空输出当成 clean。
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from .engines import (
    CLEAN,
    ENGINE_MAP,
    ERROR,
    INFECTED,
    UNKNOWN,
    _parse_avast,
    _parse_avira,
    _parse_defender,
    _parse_kaspersky,
    _parse_mbam,
    _parse_stinger,
)


@dataclass
class Case:
    name: str
    parse: object
    stdout: str
    rc: int
    expected: str
    report_file: str = ""
    report_text: str = ""
    expect_detections: int = 0


CASES: list[Case] = [
    # ---- Defender ----
    Case(
        name="Defender / 干净目录",
        parse=_parse_defender,
        stdout="Scan starting...\nScan finished.\nScanning C:\\t found no threats.\n",
        rc=0,
        expected=CLEAN,
    ),
    Case(
        name="Defender / 检出 3 项",
        parse=_parse_defender,
        stdout=(
            "Scan starting...\nScan finished.\nScanning C:\\t found 3 threats.\n"
            "Threat: Trojan:Win32/Wacatac.B!ml\n"
        ),
        rc=2,
        expected=INFECTED,
        expect_detections=1,
    ),
    Case(
        name="Defender / 异常退出码",
        parse=_parse_defender,
        stdout="",
        rc=1,
        expected=ERROR,
    ),
    # ---- Kaspersky ----
    Case(
        name="卡巴 / 报告中检出",
        parse=_parse_kaspersky,
        stdout="",
        rc=0,
        expected=INFECTED,
        report_file="kaspersky.report.txt",
        report_text="15:00:00  C:\\t\\a.exe  detected  HEUR:Trojan.Win32.Generic\n",
        expect_detections=1,
    ),
    Case(
        name="卡巴 / 报告无检出",
        parse=_parse_kaspersky,
        stdout="",
        rc=0,
        expected=CLEAN,
        report_file="kaspersky.report.txt",
        report_text="15:00:00  Scan completed. No threats found.\n",
    ),
    Case(
        name="卡巴 / 空报告必须判未知",
        parse=_parse_kaspersky,
        stdout="",
        rc=0,
        expected=UNKNOWN,
    ),
    # ---- Avira ----
    Case(
        name="Avira / ALERT 行",
        parse=_parse_avira,
        stdout="",
        rc=0,
        expected=INFECTED,
        report_file="avira.log",
        report_text="ALERT: [WORM/Rbot.Gen] C:\\t\\a.exe <<< Contains recognition pattern\n",
        expect_detections=1,
    ),
    Case(
        name="Avira / 无病毒",
        parse=_parse_avira,
        stdout="",
        rc=0,
        expected=CLEAN,
        report_file="avira.log",
        report_text="Scan finished. No viruses found.\n",
    ),
    # ---- Stinger ----
    Case(
        name="Stinger / Infected 行",
        parse=_parse_stinger,
        stdout="",
        rc=0,
        expected=INFECTED,
        report_file="stinger.report.txt",
        report_text="Infected: C:\\t\\a.exe  Trojan-Foo\n",
        expect_detections=1,
    ),
    Case(
        name="Stinger / 无感染",
        parse=_parse_stinger,
        stdout="",
        rc=0,
        expected=CLEAN,
        report_file="stinger.report.txt",
        report_text="No infected objects found\n",
    ),
    # ---- Avast ----
    Case(
        name="Avast / Threat 行",
        parse=_parse_avast,
        stdout="",
        rc=0,
        expected=INFECTED,
        report_file="avast.report.txt",
        report_text="[L] Threat: Win32:Evo-gen [Susp]\n",
        expect_detections=1,
    ),
    # ---- Malwarebytes ----
    Case(
        name="Malwarebytes / Detected 行",
        parse=_parse_mbam,
        stdout="",
        rc=0,
        expected=INFECTED,
        report_file="mbam.report.txt",
        report_text="Detected: Trojan.Agent\n",
        expect_detections=1,
    ),
    Case(
        name="Malwarebytes / 空输出必须判未知",
        parse=_parse_mbam,
        stdout="",
        rc=0,
        expected=UNKNOWN,
    ),
]


def run(verbose: bool = False) -> int:
    passed = 0
    failed: list[str] = []

    print(f"解析器自检：{len(CASES)} 个样本")
    print("-" * 62)

    with tempfile.TemporaryDirectory() as tmp:
        outdir = Path(tmp)
        for case in CASES:
            # 每个样本独立的报告目录，避免互相污染
            for leftover in outdir.iterdir():
                leftover.unlink()
            if case.report_file:
                (outdir / case.report_file).write_text(case.report_text, encoding="utf-8")

            try:
                status, detections, message = case.parse(  # type: ignore[operator]
                    case.stdout, "", case.rc, outdir
                )
            except Exception as exc:  # noqa: BLE001
                failed.append(f"{case.name} -> 解析抛异常：{exc}")
                print(f"  [FAIL] {case.name}：解析抛异常 {exc}")
                continue

            ok = status == case.expected
            if ok and case.expect_detections:
                ok = len(detections) >= case.expect_detections
            if ok:
                passed += 1
                print(f"  [PASS] {case.name} -> {status}")
            else:
                failed.append(f"{case.name} -> 期望 {case.expected}，实际 {status}（{message}）")
                print(f"  [FAIL] {case.name} -> 期望 {case.expected}，实际 {status}（{message}）")

            if verbose:
                print(f"         说明：{message}")

    print("-" * 62)
    print(f"结果：{passed}/{len(CASES)} 通过")
    if failed:
        print("\n失败项：")
        for item in failed:
            print(f"  · {item}")
        return 1

    # 附带确认引擎注册表完整
    print(f"引擎注册表：{len(ENGINE_MAP)} 个引擎已登记")
    return 0
