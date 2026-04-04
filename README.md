# ebpH

## Description

ebpH stands for Extended BPF Process Homeostasis.

ebpH is a modern host-based intrusion detection system for Linux 5.8+ that
leverages the power of Extended BPF (eBPF) to monitor processes and detect anomalous behavior.
This effectively constitutes an eBPF implementation of [pH (Process Homeostasis)](https://people.scs.carleton.ca/~mvvelzen/pH/pH.html).

## Disclaimer

This product comes with no warranty, and is built as a research system. It should be perfectly safe to run on your system due to the safety guarantees of eBPF, but we make no claims about functionality.

## Papers

### ebpH

- [My thesis](https://www.cisl.carleton.ca/~will/written/coursework/undergrad-ebpH-thesis.pdf)

### pH

- [My supervisor's original dissertation on pH](https://people.scs.carleton.ca/~soma/pubs/soma-diss.pdf)
- [A Sense of Self for UNIX Processes](https://www.cs.unm.edu/~immsec/publications/ieee-sp-96-unix.pdf)
- [Lightweight Intrustion Detection for Networked Operating Systems](http://people.scs.carleton.ca/~soma/pubs/jcs1998.pdf)
- [Lookahead Pairs and Full Sequences: A Tale of Two Anomaly Detection Methods](http://people.scs.carleton.ca/~soma/pubs/inoue-albany2007.pdf)

## Requirements / Environment

1. Linux 5.8+ compiled with at least `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_TRACEPOINTS=y`, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_LSM="bpf"`. 
    - without these, your OS will not see BPF as a useable LSM
1. `pahole >= 0.16` 
    - must be installed for the kernel to be built with BTF info.
1. `bcc` version 0.16+.
    - If building from source, be sure to include `-DPYTHON_CMD=python3` (or your python virtual environment) in your the cmake flags
1. `Python 3.8`
    - Only tested on `python 3.9`, `python 3.9` and newer may work, but have a high chance of failing while building pip packages due to strict version requirements.  

## Installation

## Default Setup
The following is a bootstrap script created to install and run the tool. It has only been tested on Ubuntu 22.04.03LTS
### What it does:
- installs pyenv and a virtualenv for python 3.8,
- builds BCC into that venv,
- patches BCC --install-layout incompatibility,
- installs ebpH and systemd service.

```bash
git clone https://github.com/adminprivileges/ebpH.git
cd ebpH
bash ./scripts/bootstrap.sh
```

For CI/containerized environments (for example, where commands run as root and systemd is offline), run:

```bash
ALLOW_ROOT=1 DO_SYSTEMD=0 bash ./scripts/bootstrap.sh
```

## Advanced/Manual Setup
0. Initial Setup
    ```bash 
    git clone https://github.com/adminprivileges/ebpH.git
    cd ebpH
    sudo apt install make
    ```
1. One-time dependencies
    ```bash
    make deps-apt
    make pyenv-install
    ```

2. Open a new shell after updating your shell init for pyenv
    ```bash
    bash
    ```
3. Create Python 3.8 venv
    ```bash
    make pyenv-venv
    make venv-check
    ```
4. Build and install BCC into the venv
    ```bash
    make install-cli
    make bcc-build
    ```
5. Install ebpH into the venv
    ```bash
    make install
    ```
6. Install systemd service
    ```bash
    make systemd-install
    make status
    make logs
    ```

## How to Use / Examples

1. Run `$ sudo ebphd start` to start the daemon.
   - Host-compatible mode (default): `$ sudo ebphd start` or `$ sudo ebphd --scope-mode host start`
   - Container-aware mode: `$ sudo ebphd --scope-mode container start`
   - Bootstrap behavior:
     - `--bootstrap-mode auto` (default): host scope => bootstrap enabled, container scope => bootstrap disabled
     - `--bootstrap-mode always`: bootstrap enabled
     - `--bootstrap-mode never`: bootstrap disabled (recommended for controlled experiment replays)
1. Run `$ sudo ebph admin status` to check daemon status.
1. Run `$ sudo ebph ps` to check monitored processes.
1. Run `$ sudo ebph ps -p` to list all active profiles.

To validate container-scope behavior with two running containers:

```bash
sudo scripts/validate_container_scope_ids.sh <container_a> <container_b>
```

### Scope modes

ebpH supports two profiling scope modes:

- `host` (default): preserves historical executable-centric behavior. Profile identity remains compatible with legacy host-wide behavior.
- `container`: profile identity becomes scope-aware and is computed from `(scope_id, executable_identity)`, where `scope_id` is derived from cgroup identity in-kernel.

In container mode, the same executable can have distinct profiles across different container scopes. Profile and process output includes `scope_id` to support research comparisons and anomaly-rate analysis by scope.

In container mode, two processes running the same executable within the same container are expected to share one profile because both `scope_id` and `executable_identity` match.

For bootstrap of already-running processes, executable identity is resolved via `/proc/<pid>/exe` first (with path-based fallback) to avoid host-path assumptions for containerized filesystems.

### Variable 2 context pipeline (userspace)

The var2-context branch adds a userspace decision layer on top of existing ebpH detector signals.

- Stage 1 remains based on existing ebpH anomaly/profile/process signals.
- Process-window cases are opened from anomaly activity, aggregated in userspace, scored, and routed by a three-band policy (`low`, `candidate`, `high`).
- Replay artifacts are written for offline reproducibility and cross-condition reruns.

Useful daemon flags:

- `--context-enabled`
- `--scope-baseline-mature true|false`
- `--window-inactivity-timeout <seconds>`
- `--window-hard-max <seconds>`
- `--stage1-t-candidate <float>`
- `--stage1-t-high <float>`
- `--stage2-c-downgrade <float>`
- `--adjudicator-model-enabled`
- `--adjudicator-backend ollama|stub`
- `--ollama-base-url <url>`
- `--ollama-model <name>`
- `--ollama-timeout-sec <seconds>`
- `--ollama-keep-alive <value>`

Daemon flag reference for recent scope/context additions:

- `--scope-mode host|container`
  - Selects host-compatible profiling or container-aware profiling.
- `--bootstrap-mode auto|always|never`
  - `auto`: bootstrap host scope, skip bootstrap in container scope.
  - `always`: bootstrap regardless of scope mode.
  - `never`: skip bootstrap regardless of scope mode.
- `--context-enabled`
  - Enables the userspace variable-2 context adjudication path.
- `--scope-baseline-mature true|false`
  - Run-level maturity constant stamped into each case for routing/analysis.
- `--window-inactivity-timeout <seconds>`
  - Closes an active process-window after no anomaly activity for this duration.
- `--window-hard-max <seconds>`
  - Hard cap on process-window duration even if anomaly signals continue.
- `--stage1-t-candidate <float>`
  - Lower stage-1 threshold for entering the candidate band.
- `--stage1-t-high <float>`
  - Upper stage-1 threshold for entering the high band.
- `--stage2-c-downgrade <float>`
  - Minimum adjudicator confidence required to downgrade a high-band default detection.
- `--adjudicator-model-enabled`
  - Enables model-backed stage-2 adjudication. Defaults to disabled.
- `--adjudicator-backend ollama|stub`
  - Selects model backend (`ollama`) or deterministic local fallback (`stub`).
- `--ollama-base-url <url>`
  - Local Ollama sidecar base URL. Default: `http://127.0.0.1:11434`.
- `--ollama-model <name>`
  - Ollama model tag for stage-2 adjudication.
- `--ollama-timeout-sec <seconds>`
  - HTTP timeout for the local Ollama call.
- `--ollama-keep-alive <value>`
  - Ollama keep_alive setting forwarded in request body.

Replay/session artifacts:

- Root directory: `/var/lib/ebpH/replay`
- Each run creates `session-<timestamp>/session.json`
- Finalized cases are appended to `session-<timestamp>/cases.jsonl`
- `session.json` includes adjudicator metadata (`adjudicator_backend`, `adjudicator_model_enabled`, `ollama_model`, `ollama_base_url`) for replay reproducibility.

Example container-scope context run (foreground):

```bash
sudo ebphd --nodaemon \
  --scope-mode container \
  --bootstrap-mode never \
  --context-enabled \
  --scope-baseline-mature true \
  --window-inactivity-timeout 3.0 \
  --window-hard-max 30.0 \
  --stage1-t-candidate 2.0 \
  --stage1-t-high 8.0 \
  --stage2-c-downgrade 0.8
```

Or, with systemd:

1. Run `$ sudo systemctl start ebphd` to start the daemon if not already running.

### Ollama stage-2 adjudicator quick validation

1. Start Ollama locally and pull a model (example):
   ```bash
   ollama serve
   ollama pull tinyllama:1.1b
   ```
2. Run ebpH in foreground with model-backed adjudication:
   ```bash
   sudo ebphd --nodaemon \
     --context-enabled \
     --adjudicator-model-enabled \
     --adjudicator-backend ollama \
     --ollama-base-url http://127.0.0.1:11434 \
     --ollama-model tinyllama:1.1b \
     --ollama-timeout-sec 10 \
     --ollama-keep-alive 5m
   ```
3. Generate a test anomaly workload, then inspect replay output:
   ```bash
   latest_session="$(ls -1dt /var/lib/ebpH/replay/session-* | head -n1)"
   jq . "$latest_session/session.json"
   tail -n 5 "$latest_session/cases.jsonl" | jq .
   ```
4. Expected checks:
   - Success path: `decision.adjudicator_called=true`, `decision.adjudicator_error=""`
   - Candidate-band failure fallback: `reason_code="adjudicator_error_band2_default"` and `final_binary_decision="not_detected"`
   - High-band failure fallback: `reason_code="adjudicator_error_band3_default"` and `final_binary_decision="detected"`
