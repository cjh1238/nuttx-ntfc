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

"""GDB RPC Monitor — core orchestrator for remote GDB debugging."""

import os
import threading
import time
import weakref
from typing import Any, Callable, Dict, List, Optional

import gdbrpc

from ntfc.gdb.config import GDBConfig
from ntfc.gdb.manager import GDBManager
from ntfc.gdb.requests import (
    ContinueProgram,
    CrashBreakpointRequest,
    DeleteCrashBreakpoints,
    ExecuteCommand,
    GenerateCoredump,
    InitializeGcoreConfig,
    InterruptProgram,
    PingRequest,
    PoweroffBreakpointRequest,
    UpdateGcorePath,
)
from ntfc.log.logger import logger

_monitor_registry: Dict[str, "weakref.ref[GDBRPCMonitor]"] = {}
_registry_lock = threading.Lock()

CoredumpCallback = Callable[[Dict[str, Any]], None]


# ── gdbrpc Callbacks ───────────────────────────────────────────


class _CrashCallback(gdbrpc.PostRequest):
    """Callback invoked when a crash breakpoint fires."""

    def __init__(self, monitor_id: str, location: str) -> None:
        super().__init__()
        self.monitor_id = monitor_id
        self.location = location

    def __call__(self, result: Dict[str, Any]) -> None:
        with _registry_lock:
            ref = _monitor_registry.get(self.monitor_id)
        if not ref:
            return
        monitor = ref()
        if not monitor or monitor._stopping:
            return

        logger.info("Crash callback: %s", self.location)
        with monitor._crash_lock:
            monitor._last_corefile_retrieved = False
            monitor.crash_events.append(result)
        monitor.crash_event.set()

        if result.get("success"):
            logger.info("Coredump generated: %s", result.get("coredump_path"))
            for cb in monitor._coredump_callbacks:
                try:
                    cb(result)
                except Exception as e:
                    logger.error("Coredump callback error: %s", e)


class _PoweroffCallback(gdbrpc.PostRequest):
    """Callback invoked when the poweroff breakpoint fires."""

    def __init__(self, monitor_id: str) -> None:
        super().__init__()
        self.monitor_id = monitor_id

    def __call__(self, result: Dict[str, Any]) -> None:
        with _registry_lock:
            ref = _monitor_registry.get(self.monitor_id)
        if not ref:
            return
        monitor = ref()
        if not monitor or monitor._stopping:
            return

        logger.info("Poweroff callback triggered")

        if monitor.breakpoint_locations and monitor.client is not None:
            locs = list(monitor.breakpoint_locations.keys())
            client = monitor.client

            def _cleanup() -> None:
                try:
                    client.call(DeleteCrashBreakpoints(locs), timeout=2)
                except Exception:
                    pass

            threading.Thread(target=_cleanup, daemon=True).start()

        with monitor._poweroff_lock:
            monitor.poweroff_event_data = result
        monitor.poweroff_event.set()

        if result.get("memory_leak"):
            info: Dict[str, Any] = result.get("mmleak_info", {})
            logger.warning(
                "Memory leak detected: %d blks, %d bytes",
                info.get("leaked_blks", 0),
                info.get("leaked_bytes", 0),
            )


# ── GDBRPCMonitor ──────────────────────────────────────────────


class GDBRPCMonitor:
    """Core GDB RPC monitor orchestrator.

    :param config: :class:`GDBConfig` instance.
    :param output_dir: Directory for coredump and log output.
    """

    def __init__(self, config: GDBConfig, output_dir: str = "") -> None:
        self.monitor_id = f"monitor_{id(self)}"
        with _registry_lock:
            _monitor_registry[self.monitor_id] = weakref.ref(self)

        self._config = config
        self.output_dir = output_dir
        self.gcore_cmd = config.gcore_cmd
        self.check_mmleak = config.enable_mmleak

        os.makedirs(output_dir, exist_ok=True)

        self.gdb_manager = GDBManager(config)
        self.client: Optional[gdbrpc.Client] = None
        self.heartbeat_client: Optional[gdbrpc.Client] = None

        self.breakpoint_locations: Dict[str, bool] = {}

        self.crash_events: List[Dict[str, Any]] = []
        self._crash_lock = threading.Lock()
        self.crash_event = threading.Event()
        self._coredump_callbacks: List[CoredumpCallback] = []
        self._last_corefile_retrieved = False

        self.poweroff_event_data: Optional[Dict[str, Any]] = None
        self._poweroff_lock = threading.Lock()
        self.poweroff_event = threading.Event()

        self.gdb_alive = False
        self._last_heartbeat = time.time()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_heartbeat = threading.Event()
        self._stopping = False
        self._consecutive_hb_failures = 0

        self._result_dir = config.result_dir or output_dir
        self._error_file = os.path.join(self._result_dir, ".gdb-error")

    # ── Lifecycle ──────────────────────────────────────────

    def start(self) -> bool:
        """Start GDB monitor."""
        if os.path.exists(self._error_file):
            logger.error("GDB startup blocked: previous error file exists")
            return False

        if not self.gdb_manager.start(self.output_dir):
            self._record_fail("Failed to start GDB process")
            return False

        self.client = gdbrpc.Client(
            host=self._config.rpc_host,
            port=self._config.rpc_port,
        )
        for i in range(10):
            if self.client.connect():
                self.gdb_alive = True
                break
            time.sleep(1)
        else:
            self._record_fail("Failed to connect to GDB RPC server")
            self.gdb_manager.stop()
            return False

        time.sleep(0.2)
        self.heartbeat_client = gdbrpc.Client(
            host=self._config.rpc_host,
            port=self._config.rpc_port,
        )
        for _ in range(10):
            if self.heartbeat_client.connect():
                break
            time.sleep(1)
        else:
            self.heartbeat_client = None

        if not self._setup_breakpoints():
            self._record_fail("Failed to setup breakpoints")
            self.stop()
            return False

        if self.heartbeat_client:
            self._start_heartbeat()

        logger.info("GDB RPC Monitor started successfully")
        return True

    def stop(self) -> None:
        """Stop monitor and clean up all resources."""
        self._stopping = True
        self._stop_heartbeat.set()

        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=16)

        self.gdb_alive = False

        if self.client:
            try:
                self.client._pending_requests.clear()
                time.sleep(0.5)
                self.client.disconnect()
            except Exception:
                pass

        if self.heartbeat_client:
            try:
                self.heartbeat_client._pending_requests.clear()
                self.heartbeat_client.disconnect()
            except Exception:
                pass

        try:
            self.gdb_manager.stop()
        except Exception as e:
            logger.error("Error stopping GDB manager: %s", e)

        with self._crash_lock:
            self.crash_events.clear()
        self.crash_event.clear()
        with self._poweroff_lock:
            self.poweroff_event_data = None
        self.poweroff_event.clear()

        with _registry_lock:
            _monitor_registry.pop(self.monitor_id, None)

        self.breakpoint_locations.clear()

    # ── Breakpoint Setup ──────────────────────────────────

    def _setup_breakpoints(self) -> bool:
        """Set up all crash and poweroff breakpoints."""
        assert self.client is not None
        try:
            self.client.call(InitializeGcoreConfig(self.output_dir))

            all_locations = list(self._config.crash_breakpoints)
            all_locations.append(self._config.poweroff_breakpoint)

            for location in self._config.crash_breakpoints:
                self.client.call(
                    UpdateGcorePath(location, self.output_dir),
                    timeout=5,
                )
                callback = _CrashCallback(self.monitor_id, location)
                request = CrashBreakpointRequest(
                    location, self.gcore_cmd, all_locations
                )
                self.client.call(request, post_request=callback, timeout=300)
                self.breakpoint_locations[location] = True

            self.client.call(
                UpdateGcorePath("poweroff", self.output_dir), timeout=5
            )
            poff_cb = _PoweroffCallback(self.monitor_id)
            poff_req = PoweroffBreakpointRequest(
                self.check_mmleak, self.gcore_cmd
            )
            self.client.call(poff_req, post_request=poff_cb, timeout=300)

            result = self.client.call(ContinueProgram(), timeout=10)
            if not result.get("success"):
                return False

            return True
        except Exception as e:
            logger.error("Error setting up breakpoints: %s", e)
            return False

    # ── Heartbeat ─────────────────────────────────────────

    def _start_heartbeat(self) -> None:
        """Start background heartbeat thread."""
        interval = self._config.heartbeat_interval
        hb_client = self.heartbeat_client
        assert hb_client is not None

        def _loop() -> None:
            while not self._stop_heartbeat.is_set():
                try:
                    result = hb_client.call(PingRequest(), timeout=5)
                    if result.get("status") == "ok":
                        self._last_heartbeat = time.time()
                        self.gdb_alive = True
                        self._consecutive_hb_failures = 0
                except Exception:
                    self._consecutive_hb_failures += 1
                    if self._stop_heartbeat.is_set():
                        break
                    self.gdb_alive = False
                    if self._consecutive_hb_failures >= 3:
                        if not self.gdb_manager.is_alive():
                            self._record_fail("GDB process crashed")
                            break
                        elif self._consecutive_hb_failures >= 10:
                            self._record_fail("GDB unresponsive")
                            break
                self._stop_heartbeat.wait(interval)

        self._heartbeat_thread = threading.Thread(
            target=_loop, daemon=True, name="gdb-heartbeat"
        )
        self._heartbeat_thread.start()

    # ── Callbacks ─────────────────────────────────────────

    def register_coredump_callback(self, callback: CoredumpCallback) -> None:
        """Register a callback for coredump events."""
        self._coredump_callbacks.append(callback)

    # ── Output Directory ──────────────────────────────────

    def set_output_dir(self, new_dir: str) -> bool:
        """Update coredump output directory."""
        assert self.client is not None
        try:
            os.makedirs(new_dir, exist_ok=True)
        except Exception:
            return False

        for location in self.breakpoint_locations:
            try:
                r = self.client.call(
                    UpdateGcorePath(location, new_dir), timeout=5
                )
                if not r.get("success"):
                    return False
            except Exception:
                return False

        try:
            self.client.call(UpdateGcorePath("poweroff", new_dir), timeout=5)
        except Exception:
            pass

        self.output_dir = new_dir
        return True

    # ── Crash Queries ─────────────────────────────────────

    def has_crashed(self) -> bool:
        """Check if any crash event has occurred."""
        with self._crash_lock:
            return len(self.crash_events) > 0

    def get_last_corefile(self) -> Optional[str]:
        """Get path of the last coredump (one-shot)."""
        with self._crash_lock:
            if self._last_corefile_retrieved or not self.crash_events:
                return None
            last = self.crash_events[-1]
            if not last.get("success"):
                return None
            self._last_corefile_retrieved = True
            path: Optional[str] = last.get("coredump_path")
            return path

    def wait_for_crash(self, timeout: float = 300) -> Optional[Dict[str, Any]]:
        """Wait for a crash event."""
        start = time.time()
        while True:
            with self._crash_lock:
                if self.crash_events:
                    return self.crash_events[-1]
            remaining = timeout - (time.time() - start)
            if remaining <= 0:
                return None
            if self.crash_event.wait(timeout=remaining):
                self.crash_event.clear()
                continue
            return None

    # ── Poweroff Queries ──────────────────────────────────

    def has_shutdown(self) -> bool:
        """Check if system has shut down."""
        with self._poweroff_lock:
            return self.poweroff_event_data is not None

    def wait_for_shutdown(
        self, timeout: float = 600
    ) -> Optional[Dict[str, Any]]:
        """Wait for shutdown event."""
        with self._poweroff_lock:
            if self.poweroff_event_data:
                return self.poweroff_event_data
        if self.poweroff_event.wait(timeout=timeout):
            with self._poweroff_lock:
                return self.poweroff_event_data
        return None

    # ── Health ────────────────────────────────────────────

    def is_alive(self) -> bool:
        """Check if GDB is still alive and responsive."""
        timeout = self._config.heartbeat_interval * 3
        if time.time() - self._last_heartbeat > timeout:
            return False
        return self.gdb_alive and self.gdb_manager.is_alive()

    # ── Atomic GDB Control ────────────────────────────────

    def interrupt(self, timeout_ms: int = 5000) -> bool:
        """Interrupt the running program."""
        if not self.is_alive() or self.client is None:
            return False
        try:
            result = self.client.call(InterruptProgram(), timeout=10)
            return bool(result.get("success", False))
        except Exception:
            return False

    def continue_program(self) -> bool:
        """Resume program execution."""
        if not self.is_alive() or self.client is None:
            return False
        try:
            result = self.client.call(ContinueProgram(), timeout=10)
            return bool(result.get("success", False))
        except Exception:
            return False

    def execute_gdb_command(
        self, command: str, timeout: float = 30
    ) -> Optional[str]:
        """Execute an arbitrary GDB command."""
        if not self.is_alive() or self.client is None:
            return None
        try:
            result = self.client.call(ExecuteCommand(command), timeout=timeout)
            if result.get("success"):
                return str(result.get("output", ""))
            return None
        except Exception:
            return None

    def generate_coredump(self, directory: str, prefix: str) -> Optional[str]:
        """Actively generate a coredump."""
        if not self.is_alive() or self.client is None:
            return None
        try:
            with self._crash_lock:
                self._last_corefile_retrieved = False
            result = self.client.call(
                GenerateCoredump(directory, prefix, self.gcore_cmd),
                timeout=60,
            )
            if result.get("success"):
                return str(result.get("path", ""))
            return None
        except Exception:
            return None

    # ── Busyloop Handling ─────────────────────────────────

    def handle_hang(
        self,
        sample_count: int = 10,
        sample_interval: float = 1.0,
        commands: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Handle busyloop: PC sampling then gcore."""
        if commands is None:
            commands = ["bt"]

        samples: List[Dict[str, Any]] = []

        for i in range(sample_count):
            if not self.interrupt():
                break
            time.sleep(0.3)
            results: Dict[str, Any] = {}
            for cmd in commands:
                output = self.execute_gdb_command(cmd)
                results[cmd] = output
            samples.append(results)
            if i < sample_count - 1:
                self.continue_program()
                time.sleep(sample_interval)

        if not samples or len(samples) < sample_count:
            self.interrupt()
            time.sleep(0.3)

        time_str = time.strftime("%Y%m%d_%H%M%S")
        coredump_path = os.path.join(self.output_dir, f"hang_{time_str}.core")
        self.execute_gdb_command(f"{self.gcore_cmd} {coredump_path}")

        result: Dict[str, Any] = {
            "samples": samples,
            "coredump_path": coredump_path,
        }

        for cb in self._coredump_callbacks:
            try:
                cb(
                    {
                        "success": True,
                        "coredump_path": coredump_path,
                        "location": "handle_hang",
                    }
                )
            except Exception as e:
                logger.error("Coredump callback error: %s", e)

        return result

    # ── Helpers ────────────────────────────────────────────

    def _record_fail(self, reason: str) -> None:
        """Record GDB failure to persistent file."""
        logger.error("GDB Fail: %s", reason)
        try:
            os.makedirs(os.path.dirname(self._error_file), exist_ok=True)
            with open(self._error_file, "w") as f:
                f.write(reason + "\n")
        except Exception:
            pass
