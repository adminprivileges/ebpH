"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    ebpH Copyright (C) 2019-2020  William Findlay
    pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Main ebpH daemon.

    2020-Jul-13  William Findlay  Created this.
"""

import sys
import time
import argparse
import os
import signal
import threading
from typing import NoReturn, List


from ebph.logger import get_logger
from ebph.daemon_mixin import DaemonMixin
from ebph import defs

signal.signal(signal.SIGTERM, lambda _, __: sys.exit())
signal.signal(signal.SIGINT, lambda _, __: sys.exit())

class EBPHDaemon(DaemonMixin):
    """
    EBPHDaemon

    This class provides the logic for the daemon and exposes methods for interacting with the
    underlying BPFProgram class.
    """
    def __init__(self, args: argparse.Namespace) -> 'EBPHDaemon':
        # BPF Program
        self.bpf_program = None

        self.debug = args.debug
        self.log_sequences = args.log_sequences
        self.auto_save = not args.nosave
        self.auto_load = not args.noload
        self.scope_mode = args.scope_mode
        self.bootstrap_mode = args.bootstrap_mode
        self.context_enabled = args.context_enabled
        self.scope_baseline_mature = args.scope_baseline_mature
        self.window_inactivity_timeout = args.window_inactivity_timeout
        self.window_hard_max = args.window_hard_max
        self.stage1_t_candidate = args.stage1_t_candidate
        self.stage1_t_high = args.stage1_t_high
        self.stage2_c_downgrade = args.stage2_c_downgrade
        self.adjudicator_model_enabled = args.adjudicator_model_enabled
        self.adjudicator_backend = args.adjudicator_backend
        self.ollama_base_url = args.ollama_base_url
        self.ollama_model = args.ollama_model
        self.ollama_timeout_sec = args.ollama_timeout_sec
        self.ollama_keep_alive = args.ollama_keep_alive

    def tick(self) -> None:
        """
        Invoked on every tick in the main event loop.
        """
        self.bpf_program.on_tick()

    def loop_forever(self) -> NoReturn:
        """
        Main daemon setup + event loop.
        """
        self.bind_socket()

        self._init_bpf_program()

        bpf_thread = threading.Thread(target=self._bpf_work_loop)
        bpf_thread.daemon = True
        bpf_thread.start()

        from ebph.api import API
        logger.info('Starting ebpH server...')
        API.connect_bpf_program(self.bpf_program)
        API.serve_forever()

    def stop_daemon(self, in_restart: bool = False) -> None:
        """
        Stop the daemon. Overloaded from base daemon class to print log info.
        """
        logger.info("Stopping ebpH daemon...")
        super().stop_daemon(in_restart=in_restart)

    def _init_bpf_program(self) -> None:
        assert self.bpf_program is None
        from ebph.bpf_program import BPFProgram
        self.bpf_program = BPFProgram(debug=self.debug,
                log_sequences=self.log_sequences, auto_save=self.auto_save,
                auto_load=self.auto_load, scope_mode=self.scope_mode,
                bootstrap_mode=self.bootstrap_mode,
                context_enabled=self.context_enabled,
                scope_baseline_mature=self.scope_baseline_mature,
                window_inactivity_timeout=self.window_inactivity_timeout,
                window_hard_max=self.window_hard_max,
                stage1_t_candidate=self.stage1_t_candidate,
                stage1_t_high=self.stage1_t_high,
                stage2_c_downgrade=self.stage2_c_downgrade,
                adjudicator_model_enabled=self.adjudicator_model_enabled,
                adjudicator_backend=self.adjudicator_backend,
                ollama_base_url=self.ollama_base_url,
                ollama_model=self.ollama_model,
                ollama_timeout_sec=self.ollama_timeout_sec,
                ollama_keep_alive=self.ollama_keep_alive)
        global bpf_program
        bpf_program = self.bpf_program

    def _bpf_work_loop(self) -> NoReturn:
        while 1:
            self.tick()
            time.sleep(defs.TICK_SLEEP)


OPERATIONS = ["start", "stop", "restart"]


def parse_args(args: List[str] = []) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Daemon script for ebpH.",
            prog="ebphd", #epilog="Configuration file can be found at /etc/ebpH/ebpH.cfg",
            formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('operation', metavar="Operation", type=lambda s: str(s).lower(),
            choices=OPERATIONS, nargs='?',
            help=f"Operation you want to perform. Not allowed with --nodaemon. "
            f"Choices are: {', '.join(OPERATIONS)}.")
    parser.add_argument('--nodaemon', dest='nodaemon', action='store_true',
            help=f"Run this as a foreground process instead of a daemon.")
    parser.add_argument('--nolog', dest='nolog', action='store_true',
            help=f"Write to stderr instead of logfile. In daemon mode, "
            "this will simply not write any logging information.")
    parser.add_argument('--logseq', dest='log_sequences', action='store_true',
            help=f"Log new sequences. WARNING: This option can use a lot of resources if profiles are not stable!")
    parser.add_argument('--nosave', dest='nosave', action='store_true',
            help=f"Don't save profiles on exit.")
    parser.add_argument('--noload', dest='noload', action='store_true',
            help=f"Don't load profiles.")
    parser.add_argument('--debug', action='store_true',
            help=f"Run in debug mode. Side effect: sets verbosity level to debug regardless of what is set in configuration options.")
    parser.add_argument('--scope-mode', dest='scope_mode', default='host', choices=['host', 'container'],
            help='Profiling scope mode: host (default) or container-aware.')
    parser.add_argument('--bootstrap-mode', dest='bootstrap_mode',
            default='auto', choices=['auto', 'always', 'never'],
            help='Bootstrap existing processes at startup: auto (default: host=yes, container=no), always, or never.')

    parser.add_argument('--context-enabled', dest='context_enabled', action='store_true',
            help='Enable context-stage adjudication for variable 2 pipeline.')
    parser.add_argument('--scope-baseline-mature', dest='scope_baseline_mature', default='true', choices=['true', 'false'],
            help='Run-level baseline maturity constant used for routing in candidate records.')
    parser.add_argument('--window-inactivity-timeout', dest='window_inactivity_timeout', type=float,
            default=defs.WINDOW_INACTIVITY_TIMEOUT_SEC,
            help='Process-window inactivity timeout in seconds.')
    parser.add_argument('--window-hard-max', dest='window_hard_max', type=float,
            default=defs.WINDOW_HARD_MAX_SEC,
            help='Process-window hard max duration in seconds.')
    parser.add_argument('--stage1-t-candidate', dest='stage1_t_candidate', type=float,
            default=defs.STAGE1_T_CANDIDATE,
            help='Stage-one candidate threshold.')
    parser.add_argument('--stage1-t-high', dest='stage1_t_high', type=float,
            default=defs.STAGE1_T_HIGH,
            help='Stage-one high threshold.')
    parser.add_argument('--stage2-c-downgrade', dest='stage2_c_downgrade', type=float,
            default=defs.STAGE2_C_DOWNGRADE,
            help='Minimum confidence for high-band downgrade.')
    parser.add_argument('--adjudicator-model-enabled', dest='adjudicator_model_enabled', action='store_true',
            default=defs.ADJUDICATOR_MODEL_ENABLED,
            help='Enable model-backed stage-two adjudication.')
    parser.add_argument('--adjudicator-backend', dest='adjudicator_backend',
            default=defs.ADJUDICATOR_BACKEND, choices=['ollama', 'stub'],
            help='Stage-two adjudicator backend.')
    parser.add_argument('--ollama-base-url', dest='ollama_base_url',
            default=defs.OLLAMA_BASE_URL,
            help='Local Ollama sidecar base URL.')
    parser.add_argument('--ollama-model', dest='ollama_model',
            default=defs.OLLAMA_MODEL,
            help='Ollama model name for adjudication.')
    parser.add_argument('--ollama-timeout-sec', dest='ollama_timeout_sec', type=float,
            default=defs.OLLAMA_TIMEOUT_SEC,
            help='Timeout for Ollama adjudication request in seconds.')
    parser.add_argument('--ollama-keep-alive', dest='ollama_keep_alive',
            default=defs.OLLAMA_KEEP_ALIVE,
            help='Ollama keep_alive value.')
    # Quick testing mode. This option sets --nodaemon --nolog --nosave --noload flags.
    parser.add_argument('--testing', action='store_true',
            help=argparse.SUPPRESS)

    args = parser.parse_args(args)

    # Quick and dirty testing mode
    if args.testing:
        args.nodaemon = True
        args.nolog = True
        args.nosave = True
        args.noload = True

    args.scope_mode = defs.SCOPE_MODE_HOST if args.scope_mode == 'host' else defs.SCOPE_MODE_CONTAINER
    args.scope_baseline_mature = args.scope_baseline_mature == 'true'

    # Check for root
    if not (os.geteuid() == 0):
        parser.error("This script must be run with root privileges! Exiting.")

    # Error checking
    if args.nodaemon and args.operation:
        parser.error("You cannot specify an operation with the --nodaemon flag.")
    if not (args.nodaemon or args.operation):
        parser.error("You must either specify an operation or set the --nodaemon flag.")

    return args


def main(sys_args: List[str] = sys.argv[1:]) -> NoReturn:
    args = parse_args(sys_args)
    defs.init(args)

    global logger
    logger = get_logger()

    ebphd = EBPHDaemon(args)

    if args.operation == "start":
        try:
            ebphd.start_daemon()
        except Exception as e:
            logger.error('Unable to start daemon', exc_info=e)
            sys.exit(-1)
    elif args.operation == "stop":
        try:
            ebphd.stop_daemon()
        except Exception as e:
            logger.error('Unable to stop daemon', exc_info=e)
            sys.exit(-1)
    elif args.operation == "restart":
        try:
            ebphd.restart_daemon()
        except Exception as e:
            logger.error('Unable to restart daemon', exc_info=e)
            sys.exit(-1)
    elif args.nodaemon:
        ebphd.loop_forever()
