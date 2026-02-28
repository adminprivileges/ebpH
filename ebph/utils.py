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

import hashlib
import os
import re
import sys
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterator, Optional, Union, Tuple

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

def hash_to_u64(parts: Tuple[Union[str, int], ...]) -> int:
    h = hashlib.blake2b(digest_size=8)
    for part in parts:
        h.update(str(part).encode('utf-8'))
        h.update(b'\0')
    return int.from_bytes(h.digest(), byteorder='big', signed=False)


def calculate_scoped_profile_key(fpath: str, container_id: Optional[str] = None) -> int:
    if not container_id:
        return calculate_profile_key(fpath)
    s = os.stat(fpath)
    return hash_to_u64((container_id, s.st_dev, s.st_ino))


def _read_proc_file(pid: int, path: str) -> Optional[str]:
    try:
        with open(f'/proc/{pid}/{path}', 'r', encoding='utf-8') as f:
            return f.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None


def read_cgroup_namespace_inode(pid: int) -> Optional[int]:
    try:
        link = os.readlink(f'/proc/{pid}/ns/cgroup')
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None
    m = re.match(r'cgroup:\[(\d+)\]', link)
    if not m:
        return None
    return int(m.group(1))


def read_cgroup_path(pid: int) -> Optional[str]:
    content = _read_proc_file(pid, 'cgroup')
    if not content:
        return None
    for line in content.splitlines():
        parts = line.split(':', 2)
        if len(parts) != 3:
            continue
        path = parts[2].strip()
        if path:
            return path
    return None


def derive_container_id(cgroup_path: Optional[str], cgroup_ns_inode: Optional[int] = None) -> Optional[str]:
    if cgroup_path:
        matches = re.findall(r'([0-9a-f]{64}|[0-9a-f]{32}|[0-9a-f]{12})', cgroup_path, flags=re.IGNORECASE)
        if matches:
            return matches[-1].lower()

        kube_match = re.search(r'pod([0-9a-f-]{32,36})', cgroup_path, flags=re.IGNORECASE)
        if kube_match:
            return kube_match.group(1).replace('_', '-').lower()

        suffix = cgroup_path.rsplit('/', 1)[-1]
        if suffix and suffix not in ('', '/', 'user.slice', 'system.slice', 'init.scope'):
            return suffix

    if cgroup_ns_inode and cgroup_ns_inode != read_cgroup_namespace_inode(1):
        return f'cgroupns-{cgroup_ns_inode}'

    return None


def process_container_context(pid: int) -> Dict[str, Optional[Union[str, int]]]:
    cgroup_ns_inode = read_cgroup_namespace_inode(pid)
    cgroup_path = read_cgroup_path(pid)
    container_id = derive_container_id(cgroup_path, cgroup_ns_inode)
    return {
        'container_id': container_id,
        'cgroup_path': cgroup_path,
        'cgroup_ns_inode': cgroup_ns_inode,
    }

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

#def running_processes() -> Iterator[Tuple[int, str, int, int]]:
def running_processes() -> Iterator[Tuple[int, str, int, int, Dict[str, Optional[Union[str, int]]]]]:
    """
    Returns an interator of all processes running on the
    system. Iterator contains tuples of [@profile_key, @exe, @pid, @tid, @context]
    """
    for p in find_processes():
        exe = p.exe
        pid = p.pgrp
        tid = p.pid
        if not exe:
            continue
        context = process_container_context(tid)
        try:
            profile_key = calculate_profile_key(exe)
        except Exception:
            continue
        #yield (profile_key, exe, pid, tid)
        yield (profile_key, exe, pid, tid, context)
