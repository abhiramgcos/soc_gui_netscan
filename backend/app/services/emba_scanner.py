"""
Stage B — Run EMBA firmware analysis.

Executes EMBA on a downloaded firmware binary and stores
the log directory path.  Supports optional GPT-assisted scanning.

Also exposes:
  prepare_emba(log_dir, logger) — Stage B pre-flight: refresh CVE DB + write IoT profile.
  validate_emba_output(log_dir, logger) — Stage D: check expected output files exist.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import pathlib
import re
import shlex
import shutil
from typing import Any, Awaitable, Callable

from app.config import settings
from app.utils.exceptions import EMBAScanError, EMBAScanTimeout
from app.utils.logging import get_logger

log = get_logger("firmware.emba")

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

EMBA_LOGS = pathlib.Path(settings.emba_logs_dir)
EMBA_LOGS.mkdir(parents=True, exist_ok=True)


async def prepare_emba(
    log_dir: str,
    emba_container_name: str,
    emba_home: str,
) -> None:
    """
    Stage B pre-flight: refresh CVE DB inside the EMBA container and write a
    minimal IoT scan profile into *log_dir*.

    Exit code 1 from cve-bin-tool update is treated as success (cached DB).
    Any other failure is logged as a warning and does not abort the pipeline.
    """
    profile_path = pathlib.Path(log_dir) / "iot-scan.emba"
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(
        "# Auto-generated IoT scan profile\n"
        "export MODULE_BLACKLIST=(\"S109_jtr\" \"F20_vul_aggregator\")\n"
        "export QUICK=1\n"
    )
    log.info("emba_profile_written", path=str(profile_path))

    docker_bin = shutil.which("docker")
    if not docker_bin:
        log.warning("emba_prep_skipped", reason="docker CLI not found")
        return

    cve_update_cmd = [
        "docker", "exec", emba_container_name,
        "/bin/bash", "-lc",
        (
            f"cd {shlex.quote(emba_home)} && "
            "source external/emba_venv/bin/activate 2>/dev/null || true && "
            "cve-bin-tool update -n api -u latest 2>&1 || true"
        ),
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cve_update_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        output = (stdout or b"").decode(errors="replace")[:500]
        # rc 0 = updated, rc 1 = already current / used cached
        if proc.returncode not in (0, 1):
            log.warning(
                "emba_cve_update_partial",
                returncode=proc.returncode,
                output=output,
            )
        else:
            log.info("emba_cve_update_ok", returncode=proc.returncode)
    except asyncio.TimeoutError:
        log.warning("emba_cve_update_timeout")
    except Exception as exc:
        log.warning("emba_cve_update_failed", error=str(exc))


def validate_emba_output(log_dir: str) -> dict[str, Any]:
    """
    Stage D: check that EMBA produced at least the expected output files.

    Returns a dict with keys:
      - ``valid`` (bool): True if all expected files are present.
      - ``files`` (dict[str, bool]): per-file presence flags.

    Missing files are logged as warnings; the function never raises.
    """
    expected = {
        "fw_grep.log": (pathlib.Path(log_dir) / "fw_grep.log").exists(),
        "s08_main_package_sbom.txt": (pathlib.Path(log_dir) / "s08_main_package_sbom.txt").exists(),
        "html-report": (pathlib.Path(log_dir) / "html-report").is_dir(),
    }
    missing = [k for k, v in expected.items() if not v]
    if missing:
        log.warning("emba_output_incomplete", missing=missing, log_dir=log_dir)
    else:
        log.info("emba_output_valid", log_dir=log_dir)
    return {"valid": len(missing) == 0, "files": expected}


async def run_emba(
    fw_path: str,
    device_id: str,
    ip: str,
    *,
    gpt_level: str = "1",
    on_progress: Callable[[str], Awaitable[None] | None] | None = None,
    timeout: int | None = None,
) -> str:
    """
    Run EMBA against *fw_path* and return the log directory path.

    Args:
        fw_path: Absolute path to the firmware binary.
        device_id: Unique identifier (used for log folder naming).
        ip: Device IP address (for labelling).
        gpt_level: EMBA GPT_OPTION level (1=scripts/configs, 2=+binary).
        on_progress: Optional callback for status updates.
        timeout: Maximum EMBA runtime in seconds.

    Returns:
        Path to EMBA log directory.

    Raises:
        RuntimeError: If EMBA exits with a non-zero return code.
        asyncio.TimeoutError: If EMBA exceeds the timeout.
    """
    effective_timeout = int(timeout if timeout is not None else getattr(settings, "emba_timeout", 1800))

    log_dir = str(EMBA_LOGS / f"device_{device_id}_{ip.replace('.', '_')}")
    fw_path_for_emba = str(pathlib.Path(fw_path))
    log_dir_for_emba = str(pathlib.Path(log_dir))
    emba_path = getattr(settings, "emba_path", "/opt/emba/emba")
    emba_home = getattr(settings, "emba_home", "/opt/emba")
    emba_container_name = getattr(settings, "emba_container_name", "soc_emba")
    emba_profile = getattr(settings, "emba_profile", "quick-scan.emba")
    emba_fast_mode = str(getattr(settings, "emba_fast_mode", "1")).lower() in {"1", "true", "yes", "on"}
    emba_modules_raw = getattr(settings, "emba_modules", "p05,s10,s20,s40")
    emba_modules = [module.strip() for module in emba_modules_raw.split(",") if module.strip()]

    resolved_emba_path = pathlib.Path(emba_path)
    fallback_emba_path = pathlib.Path(emba_home) / "emba"
    use_emba_container = False
    if not (resolved_emba_path.exists() and os.access(resolved_emba_path, os.X_OK)):
        if fallback_emba_path.exists() and os.access(fallback_emba_path, os.X_OK):
            resolved_emba_path = fallback_emba_path
            emba_path = str(resolved_emba_path)
        else:
            docker_bin = shutil.which("docker")
            if docker_bin:
                use_emba_container = True
            else:
                message = (
                    "EMBA binary not found and docker CLI unavailable. "
                    f"Checked EMBA_PATH='{emba_path}' and fallback '{fallback_emba_path}'. "
                    "Ensure EMBA is available locally or provide docker socket + EMBA container."
                )
                log.error("emba_runtime_missing", emba_path=emba_path, emba_home=emba_home)
                raise RuntimeError(message)

    async def notify(message: str):
        if not on_progress:
            return
        maybe_awaitable = on_progress(message)
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable

    await notify(f"Starting EMBA scan on {ip} ({fw_path})")

    # ── Stage B pre-flight: CVE DB refresh + IoT profile ───────────
    await notify("Preparing EMBA: refreshing CVE database and writing IoT profile")
    await prepare_emba(
        log_dir=log_dir_for_emba,
        emba_container_name=emba_container_name,
        emba_home=emba_home,
    )

    log.info(
        "emba_start",
        fw_path=fw_path,
        fw_path_for_emba=fw_path_for_emba,
        log_dir=log_dir,
        log_dir_for_emba=log_dir_for_emba,
        gpt_level=gpt_level,
    )

    env = os.environ.copy()
    env["GPT_OPTION"] = gpt_level
    env.setdefault("USER", "root")
    env.setdefault("SUDO_USER", "root")
    env.setdefault("SUDO_UID", "0")
    env.setdefault("SUDO_GID", "0")

    cmd = [emba_path, "-f", fw_path_for_emba, "-l", log_dir_for_emba, "-F", "-y"]

    # Check for profile availability and extend command if needed
    # Prefer the auto-generated IoT profile, then fall back to configured/default ones
    iot_profile_path = pathlib.Path(log_dir_for_emba) / "iot-scan.emba"
    profile_candidates = [
        str(iot_profile_path) if iot_profile_path.exists() else "",
        emba_profile,
        "quick-scan.emba",
        "default-scan.emba",
    ]
    selected_profile = ""
    profile_args: list[str] = []
    if use_emba_container:
        selected_profile = str(iot_profile_path) if iot_profile_path.exists() else emba_profile
    else:
        for candidate in profile_candidates:
            if not candidate:
                continue
            # Absolute path (IoT profile written to log_dir)
            cpath = pathlib.Path(candidate)
            if cpath.is_absolute() and cpath.exists():
                selected_profile = candidate
                profile_args = ["-p", candidate]
                break
            # Relative path resolved from emba_home/scan-profiles
            candidate_path = pathlib.Path(emba_home) / "scan-profiles" / candidate
            if candidate_path.exists():
                selected_profile = candidate
                profile_args = ["-p", f"scan-profiles/{candidate}"]
                break

    module_args_list: list[str] = []
    for module in emba_modules:
        module_args_list.extend(["-m", module])

    if use_emba_container:
        requested_profile = shlex.quote(emba_profile)
        module_arg_str = " ".join(f"-m {shlex.quote(module)}" for module in emba_modules)
        fast_mode_arg = "-q" if emba_fast_mode else ""
        emba_shell_cmd = (
            "export USER=root SUDO_USER=root SUDO_UID=0 SUDO_GID=0 HOME=/root; "
            "if [ ! -x /emba/external/binwalk/target/release/binwalk ] && [ -d /external ]; then "
            "rm -rf /emba/external; ln -s /external /emba/external; "
            "fi; "
            "mkdir -p /emba/config; "
            "if [ ! -f /emba/config/cve-database.db ] && [ -f /external/cve-bin-tool/cve-database.db ]; then "
            "cp /external/cve-bin-tool/cve-database.db /emba/config/cve-database.db; "
            "fi; "
            "if [ ! -f /external/nvd-json-data-feeds/README.md ]; then "
            "rm -rf /external/nvd-json-data-feeds; "
            "timeout 180 git clone --depth 1 https://github.com/EMBA-support-repos/nvd-json-data-feeds /external/nvd-json-data-feeds >/dev/null 2>&1 || true; "
            "if [ ! -f /external/nvd-json-data-feeds/README.md ]; then "
            "mkdir -p /external/nvd-json-data-feeds; "
            "printf '%s\n' 'EMBA offline fallback: NVD JSON feed mirror unavailable during bootstrap.' > /external/nvd-json-data-feeds/README.md; "
            "fi; "
            "fi; "
            "if [ -x /emba/external/emba_venv/bin/cve-bin-tool ]; then "
            "export PATH=/emba/external/emba_venv/bin:$PATH; "
            "fi; "
            "if [ ! -x /emba/emba ]; then "
            "echo 'EMBA binary missing at /emba/emba (check EMBA_HOST_PATH mount)' >&2; "
            "exit 127; "
            "fi; "
            f"PROFILE={requested_profile}; "
            "PROFILE_ARG=''; "
            "for p in \"$PROFILE\" quick-scan.emba default-scan.emba; do "
            "if [ -n \"$p\" ] && [ -f \"/emba/scan-profiles/$p\" ]; then PROFILE_ARG=\"-p scan-profiles/$p\"; break; fi; "
            "done; "
            "cd /emba && "
            f"./emba -f '{fw_path_for_emba}' -l '{log_dir_for_emba}' "
            f"$PROFILE_ARG {module_arg_str} {fast_mode_arg} -c -D -F -y"
        )
        cmd = [
            "docker",
            "exec",
            emba_container_name,
            "/bin/bash",
            "-lc",
            emba_shell_cmd,
        ]
    else:
        fast_mode_args = ["-q"] if emba_fast_mode else []
        cmd = [
            emba_path,
            "-f",
            fw_path_for_emba,
            "-l",
            log_dir_for_emba,
            *profile_args,
            *module_args_list,
            *fast_mode_args,
            "-c",
            "-F",
            "-y",
        ]

    await notify(f"EMBA running on {ip} (timeout: {effective_timeout}s)")

    async def stream_output(stream: asyncio.StreamReader | None, prefix: str):
        if stream is None:
            return
        while True:
            try:
                line = await stream.readline()
            except ValueError:
                line = await stream.read(4096)
            if not line:
                break
            text = line.decode(errors="replace").strip()
            if not text:
                continue
            text = ANSI_ESCAPE_RE.sub("", text)
            text = text[:300]
            await notify(f"{prefix} {text}")

    proc = None
    try:
        process_cwd = None if use_emba_container else emba_home
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=process_cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout_task = asyncio.create_task(stream_output(proc.stdout, "[EMBA]"))
        stderr_task = asyncio.create_task(stream_output(proc.stderr, "[EMBA-ERR]"))

        await asyncio.wait_for(proc.wait(), timeout=effective_timeout)
        await asyncio.gather(stdout_task, stderr_task)

        stderr_tail = ""
        if proc.stderr is not None:
            remaining = await proc.stderr.read()
            stderr_tail = remaining.decode(errors="replace")[:2000] if remaining else ""

        if proc.returncode != 0:
            err_msg = stderr_tail or "Unknown error"
            log.error("emba_failed", returncode=proc.returncode, stderr=err_msg[:500])
            raise EMBAScanError(
                f"EMBA exited with code {proc.returncode}: {err_msg[:500]}"
            )

        # ── Stage D: quick output quality gate ──────
        fw_grep = pathlib.Path(log_dir) / "fw_grep.log"
        if not fw_grep.exists():
            raise EMBAScanError(
                f"EMBA produced no fw_grep.log in {log_dir} — scan likely produced no output"
            )

        log.info("emba_done", log_dir=log_dir)
        await notify(f"EMBA scan completed for {ip}")

    except asyncio.TimeoutError:
        log.error("emba_timeout", timeout=effective_timeout)
        if proc and proc.returncode is None:
            proc.kill()
        if use_emba_container:
            cleanup_cmd = [
                "docker",
                "exec",
                emba_container_name,
                "/bin/bash",
                "-lc",
                (
                    f"pkill -f {shlex.quote(log_dir_for_emba)} || true; "
                    f"pkill -f {shlex.quote(fw_path_for_emba)} || true"
                ),
            ]
            try:
                cleanup_proc = await asyncio.create_subprocess_exec(
                    *cleanup_cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(cleanup_proc.wait(), timeout=10)
            except Exception:
                log.warning("emba_timeout_cleanup_failed", log_dir=log_dir_for_emba)
        await notify(f"EMBA scan timed out after {effective_timeout}s")
        raise EMBAScanTimeout(f"EMBA exceeded timeout of {effective_timeout}s for {ip}")

    return log_dir
