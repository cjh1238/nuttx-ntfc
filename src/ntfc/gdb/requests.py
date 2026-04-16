############################################################################
# SPDX-License-Identifier: Apache-2.0
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.
#
############################################################################

"""gdbrpc Request classes executed inside GDB's Python interpreter.

These classes are serialized and sent to the GDB process via gdbrpc.
Each ``__call__`` runs in GDB's event loop with access to the ``gdb``
module.  Results are returned via the ``q`` (queue) parameter.
"""

import gdbrpc

# ── Configuration ──────────────────────────────────────────────


class InitializeGcoreConfig(gdbrpc.Request):
    """Initialize gcore output path configuration object in GDB."""

    def __init__(self, default_path: str):
        super().__init__()
        self.default_path = default_path

    def __call__(self, q):
        import gdb

        if not hasattr(gdb, "_gcore_config"):

            class GcoreConfig:
                def __init__(self, default_path):
                    self.paths = {}
                    self.default_path = default_path

                def set_path(self, location, path):
                    self.paths[location] = path

                def get_path(self, location):
                    return self.paths.get(location, self.default_path)

            gdb._gcore_config = GcoreConfig(self.default_path)
            q.put({"success": True, "initialized": True})
        else:
            q.put({"success": True, "initialized": False})


class UpdateGcorePath(gdbrpc.Request):
    """Update gcore output path for a breakpoint location."""

    def __init__(self, location: str, new_path: str):
        super().__init__()
        self.location = location
        self.new_path = new_path

    def __call__(self, q):
        import gdb

        if hasattr(gdb, "_gcore_config"):
            gdb._gcore_config.set_path(self.location, self.new_path)
            q.put({"success": True, "location": self.location})
        else:
            q.put({"success": False, "error": "gcore config not initialized"})


# ── Breakpoints ────────────────────────────────────────────────


class CrashBreakpointRequest(gdbrpc.Request):
    """Set a crash breakpoint that generates a coredump when hit.

    When the breakpoint fires, a coredump is generated via ``gcore``,
    a backtrace is captured, and all other crash breakpoints are deleted
    to prevent duplicate triggers from the same crash call chain.

    :param location: Symbol name for the breakpoint (e.g. ``"_assert"``).
    :param gcore_cmd: GDB gcore command name.
    :param all_locations: All crash breakpoint locations for cross-deletion.
    :param pause_after: If True, keep the program paused after gcore.
    """

    def __init__(
        self,
        location: str,
        gcore_cmd: str = "gcore",
        all_locations: list = None,
        pause_after: bool = False,
    ):
        super().__init__()
        self.location = location
        self.gcore_cmd = gcore_cmd
        self.all_locations = all_locations or []
        self.pause_after = pause_after

    def __call__(self, q):
        import time

        import gdb

        if not hasattr(gdb, "_gcore_config"):
            raise RuntimeError("gcore config not initialized")

        pause_flag = self.pause_after
        all_locs = self.all_locations

        class _CrashBP(gdb.Breakpoint):
            def __init__(self, loc, result_queue, gcore_command):
                super().__init__(loc, internal=False, temporary=True)
                self.bp_location = loc
                self.queue = result_queue
                self.gcore_command = gcore_command

            def stop(self):
                timestamp = time.time()
                time_str = time.strftime("%Y%m%d_%H%M%S")
                output_dir = gdb._gcore_config.get_path(self.bp_location)

                try:
                    import os

                    os.makedirs(output_dir, exist_ok=True)
                    coredump_path = os.path.join(
                        output_dir,
                        f"crash_{self.bp_location}_{time_str}.core",
                    )
                    gcore_result = gdb.execute(
                        f"{self.gcore_command} {coredump_path}",
                        to_string=True,
                    )
                    bt = gdb.execute("bt", to_string=True)

                    valid_elf = False
                    size = 0
                    if os.path.exists(coredump_path):
                        size = os.path.getsize(coredump_path)
                        with open(coredump_path, "rb") as f:
                            valid_elf = f.read(4) == b"\x7fELF"

                    # Delete other crash breakpoints
                    for bp in gdb.breakpoints():
                        if bp is None:
                            continue
                        bp_loc = getattr(bp, "location", None)
                        if (
                            bp_loc
                            and bp_loc != self.bp_location
                            and bp_loc in all_locs
                        ):
                            try:
                                bp.delete()
                            except Exception:
                                pass

                    self.queue.put(
                        {
                            "location": self.bp_location,
                            "coredump_path": coredump_path,
                            "timestamp": timestamp,
                            "backtrace": bt,
                            "gcore_output": gcore_result,
                            "size": size,
                            "valid_elf": valid_elf,
                            "success": True,
                            "paused": pause_flag,
                        }
                    )
                    return pause_flag

                except Exception as e:
                    import traceback

                    traceback.print_exc()
                    self.queue.put(
                        {
                            "location": self.bp_location,
                            "error": str(e),
                            "success": False,
                        }
                    )
                    return pause_flag

        _CrashBP(self.location, q, self.gcore_cmd)


class PoweroffBreakpointRequest(gdbrpc.Request):
    """Set poweroff breakpoint with optional memory leak check.

    :param check_mmleak: Whether to run ``mm leak`` before shutdown.
    :param gcore_cmd: GDB gcore command name.
    """

    def __init__(self, check_mmleak: bool = True, gcore_cmd: str = "gcore"):
        super().__init__()
        self.check_mmleak = check_mmleak
        self.gcore_cmd = gcore_cmd

    def __call__(self, q):
        import re
        import time

        import gdb

        if not hasattr(gdb, "_gcore_config"):
            q.put({"error": "gcore config not initialized"})
            return

        output_dir = gdb._gcore_config.get_path("poweroff")

        class _PoweroffBP(gdb.Breakpoint):
            def __init__(self, result_queue, do_mmleak, gcore_command):
                super().__init__(
                    "reboot_notifier_call_chain",
                    internal=False,
                    temporary=True,
                )
                self.queue = result_queue
                self.do_mmleak = do_mmleak
                self.gcore_command = gcore_command

            def stop(self):
                timestamp = time.time()
                time_str = time.strftime("%Y%m%d_%H%M%S")
                result = {"timestamp": timestamp, "reason": "normal"}

                try:
                    bt = gdb.execute("bt", to_string=True)
                    result["backtrace"] = bt

                    if self.do_mmleak:
                        try:
                            mmleak_out = gdb.execute("mm leak", to_string=True)
                            match = re.search(
                                r"Leaked (\d+) blks, (\d+) bytes",
                                mmleak_out,
                            )
                            has_leak = False
                            if match:
                                blks = int(match.group(1))
                                bts = int(match.group(2))
                                has_leak = blks > 0

                            result["memory_leak"] = has_leak
                            if has_leak:
                                import os

                                report = os.path.join(
                                    output_dir, f"nuttx_{time_str}.mmleak"
                                )
                                with open(report, "w") as f:
                                    f.write(mmleak_out)

                                core_path = os.path.join(
                                    output_dir, f"mmleak_{time_str}.core"
                                )
                                gdb.execute(
                                    f"{self.gcore_command} {core_path}",
                                    to_string=True,
                                )
                                result["mmleak_info"] = {
                                    "has_leak": True,
                                    "leaked_blks": blks,
                                    "leaked_bytes": bts,
                                    "report_path": report,
                                    "coredump_path": core_path,
                                }
                            else:
                                result["mmleak_info"] = {"has_leak": False}
                        except Exception as e:
                            result["mmleak_error"] = str(e)
                            result["memory_leak"] = False
                    else:
                        result["memory_leak"] = None

                    self.queue.put(result)
                except Exception as e:
                    self.queue.put({"error": str(e)})
                return False

        _PoweroffBP(q, self.check_mmleak, self.gcore_cmd)


# ── Program Control ────────────────────────────────────────────


class PingRequest(gdbrpc.Request):
    """Heartbeat ping — returns timestamp."""

    def __call__(self, q):
        import time

        q.put({"status": "ok", "timestamp": time.time()})


class InterruptProgram(gdbrpc.Request):
    """Interrupt a running program.

    Returns ``{success, state, was_running}``.
    """

    def __call__(self, q):
        import gdb

        try:
            try:
                output = gdb.execute("info threads", to_string=True)
                if output and output.strip():
                    q.put(
                        {
                            "success": True,
                            "state": "already_stopped",
                            "was_running": False,
                        }
                    )
                    return
            except gdb.error:
                pass

            gdb.execute("interrupt", to_string=False)
            q.put(
                {"success": True, "state": "interrupted", "was_running": True}
            )
        except Exception as e:
            q.put({"success": False, "error": str(e), "was_running": False})


class ContinueProgram(gdbrpc.Request):
    """Resume program execution."""

    def __call__(self, q):
        import gdb

        try:
            try:
                result = gdb.execute("continue&", to_string=True)
                q.put({"success": True, "command": "continue&"})
                return
            except gdb.error:
                pass

            try:
                gdb.execute("continue", to_string=False)
                q.put({"success": True, "command": "continue"})
                return
            except Exception as e2:
                q.put({"success": False, "error": str(e2)})
        except Exception as e:
            q.put({"success": False, "error": str(e)})


class ExecuteCommand(gdbrpc.Request):
    """Execute an arbitrary GDB command and return output.

    Program must be stopped first.
    """

    def __init__(self, command: str):
        super().__init__()
        self.command = command

    def __call__(self, q):
        import gdb

        try:
            output = gdb.execute(self.command, to_string=True)
            q.put({"success": True, "output": output})
        except Exception as e:
            q.put({"success": False, "error": str(e)})


class GenerateCoredump(gdbrpc.Request):
    """Actively generate a coredump.

    Interrupts the program if running, generates the coredump,
    then resumes execution.
    """

    def __init__(self, output_dir: str, prefix: str, gcore_cmd: str = "gcore"):
        super().__init__()
        self.output_dir = output_dir
        self.prefix = prefix
        self.gcore_cmd = gcore_cmd

    def __call__(self, q):
        import os
        import time

        import gdb

        try:
            already_stopped = False
            try:
                gdb.execute("info threads", to_string=True)
                already_stopped = True
            except gdb.error:
                pass

            if not already_stopped:
                try:
                    gdb.execute("interrupt", to_string=False)
                except Exception as e:
                    q.put(
                        {"success": False, "error": f"interrupt failed: {e}"}
                    )
                    return

            time_str = time.strftime("%Y%m%d_%H%M%S")
            os.makedirs(self.output_dir, exist_ok=True)
            coredump_path = os.path.join(
                self.output_dir, f"{self.prefix}_{time_str}.core"
            )

            gcore_result = gdb.execute(
                f"{self.gcore_cmd} {coredump_path}", to_string=True
            )

            valid_elf = False
            size = 0
            if os.path.exists(coredump_path):
                size = os.path.getsize(coredump_path)
                with open(coredump_path, "rb") as f:
                    valid_elf = f.read(4) == b"\x7fELF"

            result = {
                "success": True,
                "path": coredump_path,
                "size": size,
                "valid_elf": valid_elf,
                "gcore_output": gcore_result,
            }

            if not already_stopped:
                try:
                    gdb.execute("continue&", to_string=False)
                    result["resumed"] = True
                except Exception:
                    result["resumed"] = False

            q.put(result)

        except Exception as e:
            import traceback

            traceback.print_exc()
            q.put({"success": False, "error": str(e)})


class DeleteCrashBreakpoints(gdbrpc.Request):
    """Delete all crash-related breakpoints."""

    def __init__(self, locations: list):
        super().__init__()
        self.locations = locations

    def __call__(self, q):
        import gdb

        try:
            deleted = 0
            for bp in gdb.breakpoints():
                if bp is None:
                    continue
                bp_loc = getattr(bp, "location", None)
                if bp_loc and bp_loc in self.locations:
                    try:
                        bp.delete()
                        deleted += 1
                    except Exception:
                        pass
            q.put({"success": True, "deleted_count": deleted})
        except Exception as e:
            q.put({"success": False, "error": str(e)})
