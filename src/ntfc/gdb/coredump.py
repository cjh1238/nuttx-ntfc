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

"""Offline GDB instance for loading ELF + coredump for post-mortem analysis.

Unlike the online :class:`GDBRPCMonitor`, this does NOT connect to a
running target.  It starts a GDB process, loads the binary + core file,
starts a gdbrpc server, and executes diagnostic commands.
"""

import logging
import os
import socket
import subprocess
import time
from typing import Any, Optional

import gdbrpc

from ntfc.log.logger import logger


class CoredumpGDB:
    """Standalone GDB instance for offline coredump analysis.

    :param elf_path: Path to the NuttX ELF binary.
    :param core_path: Path to the coredump file.
    :param gdb_command: GDB executable name.
    :param gdb_script: Optional GDB init script (e.g. nuttxgdb).
    :param rpc_host: gdbrpc server host.
    :param rpc_port: gdbrpc server port (0 = auto-pick).
    """

    def __init__(
        self,
        elf_path: str,
        core_path: str,
        gdb_command: str = "gdb-multiarch",
        gdb_script: str = "",
        rpc_host: str = "127.0.0.1",
        rpc_port: int = 0,
    ) -> None:
        self._elf_path = elf_path
        self._core_path = core_path
        self._gdb_command = gdb_command
        self._gdb_script = gdb_script
        self._rpc_host = rpc_host
        self._rpc_port = rpc_port or self._find_free_port()
        self._process: Optional[subprocess.Popen[bytes]] = None
        self._client: Optional[gdbrpc.Client] = None
        self._init_script: Optional[str] = None
        self._gdb_log: Optional[Any] = None

    @staticmethod
    def _find_free_port() -> int:
        """Find a free TCP port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return int(s.getsockname()[1])

    def start(self, log_dir: str = "/tmp") -> bool:
        """Start GDB process with ELF + core-file and gdbrpc server.

        :param log_dir: Directory for GDB log files.
        :return: True if started and connected successfully.
        """
        try:
            self._init_script = self._create_init_script(log_dir)
            cmd = [self._gdb_command, self._elf_path]
            if self._gdb_script:
                cmd.extend(["-x", self._gdb_script])
            cmd.extend(["-x", self._init_script])

            logger.info("CoredumpGDB starting: %s", " ".join(cmd))
            gdb_log_path = os.path.join(log_dir, "coredump_gdb_output.log")
            self._gdb_log = open(gdb_log_path, "a")  # noqa: SIM115
            self._process = subprocess.Popen(
                cmd,
                stdout=self._gdb_log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
            )

            if not self._wait_server_ready():
                logger.error("CoredumpGDB RPC server failed to start")
                self.stop()
                return False

            self._client = gdbrpc.Client(
                host=self._rpc_host, port=self._rpc_port
            )
            for _ in range(5):
                if self._client.connect():
                    logger.info("CoredumpGDB client connected")
                    return True
                time.sleep(0.5)

            logger.error("CoredumpGDB client failed to connect")
            self.stop()
            return False

        except Exception as e:
            logger.error("CoredumpGDB start failed: %s", e)
            self.stop()
            return False

    def execute_command(
        self, command: str, timeout: float = 120
    ) -> Optional[str]:
        """Execute a GDB command and return output.

        :param command: GDB command string.
        :param timeout: RPC call timeout.
        :return: Command output, or None on failure.
        """
        if not self._client:
            return None
        try:
            from ntfc.gdb.requests import ExecuteCommand

            result = self._client.call(
                ExecuteCommand(command), timeout=timeout
            )
            if result.get("success"):
                return str(result.get("output", ""))
            return None
        except Exception as e:
            logger.error("CoredumpGDB command failed: %s", e)
            return None

    def stop(self) -> None:
        """Stop GDB process and clean up."""
        if self._client:
            try:
                self._client.disconnect()
            except Exception:
                pass
            self._client = None

        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
            except Exception:
                pass
            self._process = None

        if self._gdb_log:
            try:
                self._gdb_log.close()
            except Exception:
                pass
            self._gdb_log = None

        if self._init_script and os.path.exists(self._init_script):
            try:
                os.remove(self._init_script)
            except Exception:
                pass

    def _create_init_script(self, log_dir: str) -> str:
        """Create GDB init script for offline coredump analysis."""
        path = os.path.join(log_dir, "coredump_gdb_init.py")
        content = f"""
import sys, os, glob, logging
for _sp in glob.glob(os.path.join(os.path.dirname(__file__),
                     '../../.venv/lib/python*/site-packages')):
    if _sp not in sys.path:
        sys.path.insert(0, _sp)

import gdb
gdb.execute("set pagination off")
gdb.execute("set confirm off")

def _init():
    gdb.execute("core-file {self._core_path}")
    from gdbrpc.server import Server
    server = Server(host='{self._rpc_host}', port={self._rpc_port},
                    log_level=logging.INFO,
                    log_path='{os.path.join(log_dir, "coredump_gdbrpc.log")}')
    server.start()
    print(f"CoredumpGDB RPC on {{server.host}}:{{server.port}}")

gdb.post_event(_init)
"""
        with open(path, "w") as f:
            f.write(content)
        return path

    def _wait_server_ready(self, timeout: float = 10.0) -> bool:
        """Wait for gdbrpc server to accept connections."""
        start = time.time()
        while time.time() - start < timeout:
            if self._process and self._process.poll() is not None:
                return False
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((self._rpc_host, self._rpc_port)) == 0:
                    s.close()
                    return True
                s.close()
            except Exception:
                pass
            time.sleep(0.2)
        return False
