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

"""GDB process lifecycle management.

Handles starting/stopping the ``gdb-multiarch`` process, creating the
auto-generated init script that launches the gdbrpc server, and waiting
for the RPC port to become ready.
"""

import os
import socket
import subprocess
import time
from typing import Any, Optional

from ntfc.gdb.config import GDBConfig
from ntfc.log.logger import logger


class GDBManager:
    """Manages the GDB subprocess and gdbrpc server lifecycle.

    :param config: :class:`GDBConfig` instance.
    """

    def __init__(self, config: GDBConfig) -> None:
        self._config = config
        self.process: Optional[subprocess.Popen[bytes]] = None
        self._gdb_init_script: Optional[str] = None
        self._gdb_log_file: Optional[Any] = None

        # Build target remote command
        self._target_remote_cmd = f"target remote {config.target_addr}"

    def start(self, log_dir: str) -> bool:
        """Start GDB process with gdbrpc server.

        :param log_dir: Directory for GDB log files.
        :return: True if GDB started and RPC server is ready.
        """
        gdb_log = None
        try:
            self._gdb_init_script = self._create_init_script(log_dir)

            cmd = [self._config.gdb_command, self._config.binary_path]
            if self._config.gdb_script:
                cmd.extend(["-x", self._config.gdb_script])
            cmd.extend(["-x", self._gdb_init_script])

            logger.info("Starting GDB: %s", " ".join(cmd))
            gdb_log_path = os.path.join(log_dir, "gdb_output.log")
            gdb_log = open(gdb_log_path, "a")  # noqa: SIM115
            gdb_log.write(f"\n{'=' * 70}\n")
            gdb_log.write(
                f"GDB Session started at "
                f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            gdb_log.write(f"{'=' * 70}\n")
            gdb_log.flush()

            self.process = subprocess.Popen(
                cmd,
                stdout=gdb_log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
            )
            self._gdb_log_file = gdb_log
            gdb_log = None  # ownership transferred
            logger.info("GDB process started (PID: %d)", self.process.pid)

            if not self._wait_server_ready(timeout=10.0):
                logger.error("GDB RPC server failed to start in time")
                self.stop()
                return False

            time.sleep(0.5)
            logger.info("GDB process started successfully")
            return True

        except Exception as e:
            logger.error("Failed to start GDB: %s", e)
            if gdb_log:
                try:
                    gdb_log.close()
                except Exception:
                    pass
            if self.process:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=2)
                except Exception:
                    try:
                        self.process.kill()
                    except Exception:
                        pass
            return False

    def stop(self) -> None:
        """Stop GDB process and clean up resources."""
        if self._gdb_log_file:
            try:
                self._gdb_log_file.close()
            except Exception:
                pass
            self._gdb_log_file = None

        if self.process:
            try:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
            except Exception as e:
                logger.error("Error stopping GDB: %s", e)
            finally:
                self.process = None

        if self._gdb_init_script and os.path.exists(self._gdb_init_script):
            try:
                os.remove(self._gdb_init_script)
            except Exception:
                pass

    def is_alive(self) -> bool:
        """Check if GDB process is still running."""
        if not self.process:
            return False
        return self.process.poll() is None

    def _create_init_script(self, log_dir: str) -> str:
        """Create auto-generated GDB init script for gdbrpc server."""
        init_path = os.path.join(log_dir, "gdb_init_rpc.py")
        rpc_log = os.path.join(log_dir, "gdbrpc_server.log")
        cfg = self._config

        script = f"""#!/usr/bin/env python3
# Auto-generated GDB initialization script for NTFC gdbrpc
import sys, os, glob, logging, time

# Add site-packages so GDB Python can find gdbrpc
for _sp in glob.glob(os.path.join(os.path.dirname(__file__),
                     '../../.venv/lib/python*/site-packages')):
    if _sp not in sys.path:
        sys.path.insert(0, _sp)

import gdb
gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("handle SIGPIPE nostop noprint pass")

def _start_rpc():
    from gdbrpc.server import Server
    server = Server(host="{cfg.rpc_host}", port={cfg.rpc_port},
                    log_level=logging.INFO, log_path="{rpc_log}")
    server.start()
    print(f"gdbrpc server on {{server.host}}:{{server.port}}")
    time.sleep(0.5)
    target_cmd = "{self._target_remote_cmd}"
    print(f"Connecting: {{target_cmd}}")
    try:
        gdb.execute(target_cmd)
        print("Connected to target")
    except Exception as e:
        print(f"Failed to connect: {{e}}")
        raise RuntimeError(f"GDB target connect failed: {{e}}")

gdb.post_event(_start_rpc)
"""
        with open(init_path, "w") as f:
            f.write(script)
        return init_path

    def _wait_server_ready(self, timeout: float = 10.0) -> bool:
        """Wait for gdbrpc server port to accept connections."""
        start = time.time()
        cfg = self._config
        while time.time() - start < timeout:
            if self.process and self.process.poll() is not None:
                logger.error("GDB process died while waiting for server")
                return False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((cfg.rpc_host, cfg.rpc_port)) == 0:
                    sock.close()
                    elapsed = time.time() - start
                    logger.info("GDB RPC server ready after %.3fs", elapsed)
                    return True
                sock.close()
            except Exception:
                pass
            time.sleep(0.1)
        return False
