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
1. Run `$ sudo ebph admin status` to check daemon status.
1. Run `$ sudo ebph ps` to check monitored processes.
1. Run `$ sudo ebph ps -p` to list all active profiles.

Or, with systemd:

1. Run `$ sudo systemctl start ebphd` to start the daemon if not already running.
