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

    Provides several utility functions that don't really fit elsewhere.

    2020-Jul-13  William Findlay  Created this.
"""

import os
import json
import hashlib
import subprocess
import sys
from datetime import datetime, timedelta
from typing import Callable, Iterator, Union, Tuple, Set, Dict

from proc.core import find_processes
import requests
import requests_unixsocket
requests_unixsocket.monkeypatch()

def project_path(f: str) -> str:
    """
    Return the path of a file relative to the root dir of this project (parent directory of "src").
    """
    curr_dir = os.path.realpath(os.path.dirname(__file__))
    project_dir = os.path.realpath(os.path.join(curr_dir, ".."))
    path = os.path.realpath(os.path.join(project_dir, f))
    return path

def read_chunks(f: str, size: int = 1024) -> Iterator[str]:
    """
    Read a file in chunks.
    Default chunk size is 1024.
    """
    while 1:
        data = f.read(size)
        if not data:
            break
        yield data

def ns_to_str(ns: int) -> str:
    dt = datetime.fromtimestamp(ns // 1000000000)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def ns_to_delta_str(ns: int) -> str:
    td = timedelta(seconds=(ns // 1000000000))
    return str(td)

def which(program: str) -> Union[str, None]:
     import os

     def is_exe(fpath):
         return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

     fpath, _fname = os.path.split(program)
     if fpath:
         if is_exe(program):
             return program
     else:
         for path in os.environ["PATH"].split(os.pathsep):
             exe_file = os.path.join(path, program)
             if is_exe(exe_file):
                 return exe_file

     return None

def calculate_profile_key(fpath: str) -> int:
    s = os.stat(fpath)
    st_dev = s.st_dev
    st_ino = s.st_ino
    return st_dev << 32 | st_ino


def calculate_profile_key_from_stat(s: os.stat_result) -> int:
    """
    Calculate executable identity key from a stat result.
    """
    st_dev = s.st_dev
    st_ino = s.st_ino
    return st_dev << 32 | st_ino


def compose_profile_key(scope_id: int, executable_key: int) -> int:
    """
    Compose a scope-aware profile key from (scope_id, executable_key).
    In host mode, scope_id is zero and this preserves historical behavior.
    """
    return (executable_key ^ ((scope_id * 0x9e3779b97f4a7c15) & 0xFFFF_FFFF_FFFF_FFFF)) & 0xFFFF_FFFF_FFFF_FFFF


def get_process_scope_id(pid: int) -> int:
    """
    Best-effort cgroup scope identifier for @pid from cgroupfs inode.
    """
    try:
        with open(f'/proc/{pid}/cgroup', 'r') as f:
            line = f.readline().strip()
        cgroup_path = line.split(':', 2)[-1]
        full_path = os.path.join('/sys/fs/cgroup', cgroup_path.lstrip('/'))
        return os.stat(full_path).st_ino & 0xFFFF_FFFF_FFFF_FFFF
    except Exception:
        return 0


def _is_container_cgroup_path(cgroup_path: str) -> bool:
    """
    Best-effort Docker/containerd cgroup path matcher.
    """
    return (
        '/docker/' in cgroup_path or
        '/docker-' in cgroup_path or
        'docker-' in cgroup_path or
        '/containerd/' in cgroup_path or
        '/libpod-' in cgroup_path
    )


def _hash_persistent_scope_identity(identity: str) -> int:
    digest = hashlib.blake2b(identity.encode('utf-8'), digest_size=8).digest()
    return int.from_bytes(digest, byteorder='little', signed=False)


def _build_container_persistent_identity(container: Dict) -> str:
    labels = ((container.get('Config') or {}).get('Labels') or {})
    compose_project = labels.get('com.docker.compose.project')
    compose_service = labels.get('com.docker.compose.service')
    compose_number = labels.get('com.docker.compose.container-number')

    if compose_project and compose_service:
        identity = f'{compose_project}|{compose_service}'
        if compose_number:
            identity = f'{identity}|{compose_number}'
        return identity

    name = (container.get('Name') or '').strip('/')
    if name:
        return name

    return str(container.get('Id') or '')


def list_container_scope_bindings() -> Dict[int, int]:
    """
    Best-effort runtime_scope_id -> persistent_scope_key bindings for running
    docker containers.
    """
    bindings: Dict[int, int] = {}
    try:
        res = subprocess.run(
            ['docker', 'ps', '-q'],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except Exception:
        return bindings

    if res.returncode != 0:
        return bindings

    container_ids = [line.strip() for line in res.stdout.splitlines() if line.strip()]

    for container_id in container_ids:
        try:
            inspect_res = subprocess.run(
                ['docker', 'inspect', container_id],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            if inspect_res.returncode != 0:
                continue
            inspect_data = json.loads(inspect_res.stdout)
            if not inspect_data:
                continue
            container = inspect_data[0]
            pid = int(((container.get('State') or {}).get('Pid')) or 0)
            if pid <= 0:
                continue

            with open(f'/proc/{pid}/cgroup', 'r') as f:
                line = f.readline().strip()
            cgroup_path = line.split(':', 2)[-1]
            if not _is_container_cgroup_path(cgroup_path):
                continue
            runtime_scope_id = get_process_scope_id(pid)
            if runtime_scope_id == 0:
                continue

            identity = _build_container_persistent_identity(container)
            if not identity:
                identity = container_id
            bindings[runtime_scope_id] = _hash_persistent_scope_identity(identity)
        except Exception:
            continue

    return bindings


def list_container_scope_ids() -> Set[int]:
    """
    Best-effort set of known container scope IDs from running docker containers.
    Scope IDs are cgroupfs inodes and match the BPF cgroup IDs on cgroup v2 hosts.
    """
    return set(list_container_scope_bindings().keys())


def get_process_executable_path(pid: int, fallback_path: Union[str, None] = None) -> Union[str, None]:
    """
    Best-effort executable path for pid from procfs.
    """
    try:
        return os.readlink(f'/proc/{pid}/exe')
    except Exception:
        return fallback_path


def get_process_executable_key(pid: int, fallback_path: Union[str, None] = None) -> int:
    """
    Best-effort executable identity for pid.

    Primary method uses /proc/<pid>/exe stat to avoid host-path assumptions.
    Fallback method uses calculate_profile_key on fallback_path when available.
    """
    try:
        stat_res = os.stat(f'/proc/{pid}/exe')
        return calculate_profile_key_from_stat(stat_res)
    except Exception:
        if fallback_path:
            return calculate_profile_key(fallback_path)
        raise

def fail_with(err: str) -> None:
    print(err, file=sys.stderr)
    sys.exit(-1)

def request_or_die(req_method: Callable, url: str, fail_message:str = 'Operation failed',
        data=None, json=None, **kwargs) -> requests.Response:
    """
    Either make a request, or die with an error message.
    """
    from ebph.defs import EBPH_PORT, EBPH_SOCK
    sock = EBPH_SOCK.replace('/', '%2F')
    try:
        url = f'http+unix://{sock}{url}'
        res = req_method(url, data=data, json=json, **kwargs)
        if res.status_code != 200:
            try:
                fail_with(f'{fail_message}: {res.json()["detail"]}')
            except KeyError:
                fail_with(fail_message)
        return res
    except requests.ConnectTimeout:
        fail_with('Connection to ebpH daemon timed out during request!')
    except requests.ConnectionError:
        fail_with('Unable to connect to ebpH daemon!')

def running_processes(scope_mode: int = 0) -> Iterator[Tuple[int, int, int, str, int, int]]:
    """
    Returns an interator of all processes running on the
    system. Iterator contains tuples of
    [@profile_key, @scope_id, @executable_key, @exe, @pid, @tid]
    """
    scope_bindings = list_container_scope_bindings() if scope_mode != 0 else {}
    for p in find_processes():
        exe = p.exe
        pid = p.pgrp
        tid = p.pid
        if not exe:
            continue
        try:
            executable_key = get_process_executable_key(tid, exe)
        except Exception:
            continue
        exe = get_process_executable_path(tid, exe) or exe
        scope_id = 0 if scope_mode == 0 else get_process_scope_id(tid)
        persistent_scope_key = scope_id if scope_mode == 0 else scope_bindings.get(scope_id, 0)
        profile_key = compose_profile_key(persistent_scope_key, executable_key)
        yield (profile_key, scope_id, executable_key, exe, pid, tid)
