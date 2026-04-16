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

"""GDB configuration dataclass."""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class GDBConfig:
    """GDB integration configuration.

    :param binary_path: Path to the NuttX ELF binary.
    :param enable: Whether GDB integration is enabled.
    :param enable_gdbserver: Use gdbserver mode (SIM). If False, use QEMU -S mode.
    :param target_addr: GDB target address (e.g. ``":20820"`` or ``"localhost:1234"``).
    :param gdb_script: Path to GDB init script (e.g. nuttxgdb gdbinit.py).
    :param gdb_command: GDB executable name (default ``"gdb-multiarch"``).
    :param rpc_host: gdbrpc server host (default ``"127.0.0.1"``).
    :param rpc_port: gdbrpc server port (default ``20819``).
    :param gcore_cmd: Command to generate coredump (default ``"gcore"``).
    :param enable_mmleak: Enable memory leak check on poweroff.
    :param heartbeat_interval: Seconds between heartbeat pings (default ``30``).
    :param result_dir: Directory for persistent GDB state files.
    :param crash_breakpoints: Breakpoint locations for crash detection.
    :param poweroff_breakpoint: Breakpoint location for poweroff detection.
    """

    binary_path: str = ""
    enable: bool = False
    enable_gdbserver: bool = False
    target_addr: str = ""
    gdb_script: str = ""
    gdb_command: str = "gdb-multiarch"
    rpc_host: str = "127.0.0.1"
    rpc_port: int = 20819
    gcore_cmd: str = "gcore"
    enable_mmleak: bool = False
    heartbeat_interval: int = 30
    result_dir: str = ""
    crash_breakpoints: List[str] = field(
        default_factory=lambda: [
            "dump_assert_info",
            "dump_mini_info",
            "dump_core_info",
            "_assert",
        ]
    )
    poweroff_breakpoint: str = "reboot_notifier_call_chain"

    @classmethod
    def from_dict(
        cls, gdb_conf: Dict[str, Any], binary_path: str = ""
    ) -> "GDBConfig":
        """Construct from a configuration dictionary.

        :param gdb_conf: GDB section from NTFC YAML config.
        :param binary_path: Path to the NuttX ELF binary.
        :return: :class:`GDBConfig` instance.
        """
        script_path = gdb_conf.get("script_path", "")
        if script_path and os.path.isdir(script_path):
            script_path = os.path.join(script_path, "gdbinit.py")

        # Accept multiple key names for target address
        target_addr = gdb_conf.get("target_addr", "") or gdb_conf.get(
            "socket", ""
        )

        default_crash_bps = [
            "dump_assert_info",
            "dump_mini_info",
            "dump_core_info",
            "_assert",
        ]
        crash_bps = gdb_conf.get("crash_breakpoints", default_crash_bps)

        return cls(
            binary_path=binary_path,
            enable=gdb_conf.get("enable", False),
            enable_gdbserver=gdb_conf.get("enable_gdbserver", False),
            target_addr=target_addr,
            gdb_script=script_path,
            gdb_command=gdb_conf.get("gdb_command", "gdb-multiarch"),
            rpc_host=gdb_conf.get("rpc_host", "127.0.0.1"),
            rpc_port=gdb_conf.get("rpc_port", 20819),
            gcore_cmd=gdb_conf.get("gcore_cmd", "gcore"),
            enable_mmleak=gdb_conf.get("mmleak_check", False),
            heartbeat_interval=gdb_conf.get("heartbeat_interval", 30),
            result_dir=gdb_conf.get("result_dir", ""),
            crash_breakpoints=crash_bps,
            poweroff_breakpoint=gdb_conf.get(
                "poweroff_breakpoint", "reboot_notifier_call_chain"
            ),
        )
