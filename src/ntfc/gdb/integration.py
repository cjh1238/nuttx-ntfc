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

"""High-level GDB integration API for the Product/Device layer.

This class provides a clean interface between the NTFC Product layer
and the underlying :class:`GDBRPCMonitor`.  It handles:

- Availability checks (enabled + no previous errors)
- Spawn command modification (gdbserver / QEMU -S)
- Monitor lifecycle (start/stop)
- Proxy methods for coredump and GDB control
"""

import os
from typing import Any, Callable, Dict, List, Optional

from ntfc.gdb.config import GDBConfig
from ntfc.gdb.monitor import GDBRPCMonitor
from ntfc.log.logger import logger


class GDBIntegration:
    """Composition-based GDB integration manager.

    Owned by the Product/Device layer.  Separates GDB debugging concerns
    from device lifecycle management.

    :param config: :class:`GDBConfig` instance.
    """

    def __init__(self, config: GDBConfig) -> None:
        self._config = config
        self._error_file = (
            os.path.join(config.result_dir, ".gdb-error")
            if config.result_dir
            else ""
        )
        self._monitor: Optional[GDBRPCMonitor] = None

    @property
    def available(self) -> bool:
        """True if GDB is enabled and no previous error exists."""
        if not self._config.enable:
            return False
        if self._error_file and os.path.exists(self._error_file):
            logger.warning("GDB has failed before, skipping")
            return False
        return True

    def prepare_command(self, cmd: List[str]) -> List[str]:
        """Modify spawn command for GDB debugging.

        For gdbserver mode (SIM): inserts ``gdbserver :port`` before binary.
        For QEMU mode: appends ``-S`` to pause until GDB connects.

        :param cmd: Original spawn command list.
        :return: Modified command list, or original if GDB unavailable.
        """
        if not self.available:
            return cmd

        if self._config.enable_gdbserver:
            target = self._config.target_addr
            if not target:
                target = ":20820"
                self._config.target_addr = target
            port = target.split(":")[-1]
            binary = self._config.binary_path
            logger.info(
                "GDB enabled (SIM): inserting gdbserver :%s before %s",
                port,
                binary,
            )
            return [
                c.replace(binary, f"gdbserver :{port} {binary}") for c in cmd
            ]
        else:
            logger.info("GDB enabled (QEMU): appending -S")
            return cmd + ["-S"]

    def start(
        self,
        output_dir: str,
        coredump_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> bool:
        """Start GDB RPC Monitor.

        Call after device spawn, before boot check.

        :param output_dir: Directory for GDB output files.
        :param coredump_callback: Optional callback for coredump events.
        :return: True if started successfully.
        """
        if not self.available:
            return True  # GDB disabled is not an error

        self._monitor = GDBRPCMonitor(
            config=self._config,
            output_dir=output_dir,
        )
        if coredump_callback:
            self._monitor.register_coredump_callback(coredump_callback)
        return self._monitor.start()

    def stop(self) -> None:
        """Stop GDB monitor. Safe to call multiple times."""
        if self._monitor:
            self._monitor.stop()
            self._monitor = None

    # ── Coredump Proxies ──────────────────────────────────

    def get_last_corefile(self) -> Optional[str]:
        """Get path of the last generated coredump file."""
        return self._monitor.get_last_corefile() if self._monitor else None

    def has_crashed(self) -> bool:
        """Check if any crash has occurred."""
        return self._monitor.has_crashed() if self._monitor else False

    def wait_for_crash(self, timeout: float = 300) -> Optional[Dict[str, Any]]:
        """Wait for a crash event."""
        return self._monitor.wait_for_crash(timeout) if self._monitor else None

    def generate_coredump(self, directory: str, prefix: str) -> Optional[str]:
        """Actively generate a coredump."""
        return (
            self._monitor.generate_coredump(directory, prefix)
            if self._monitor
            else None
        )

    def set_output_dir(self, new_dir: str) -> bool:
        """Update coredump output directory."""
        return (
            self._monitor.set_output_dir(new_dir) if self._monitor else False
        )

    # ── Atomic GDB Control Proxies ────────────────────────

    def interrupt(self, timeout_ms: int = 2000) -> bool:
        """Interrupt the running program."""
        return self._monitor.interrupt(timeout_ms) if self._monitor else False

    def continue_program(self) -> bool:
        """Resume program execution."""
        return self._monitor.continue_program() if self._monitor else False

    def execute_gdb_command(
        self, command: str, timeout: float = 30
    ) -> Optional[str]:
        """Execute an arbitrary GDB command."""
        return (
            self._monitor.execute_gdb_command(command, timeout)
            if self._monitor
            else None
        )

    def handle_hang(self, **kwargs: Any) -> Dict[str, Any]:
        """Busyloop handling: PC sampling + gcore."""
        return self._monitor.handle_hang(**kwargs) if self._monitor else {}

    @property
    def monitor(self) -> Optional[GDBRPCMonitor]:
        """Access the underlying monitor (for advanced usage)."""
        return self._monitor
