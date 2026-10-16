from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
FIREWALL_SCRIPT = ROOT / "deploy" / "ubuntu" / "system-metrics-egress"


def load_ubuntu_compose() -> dict:
    return yaml.safe_load((ROOT / "compose.ubuntu-agent.yaml").read_text(encoding="utf-8"))


def test_public_ingress_has_stable_network_and_bridge_names():
    networks = load_ubuntu_compose()["networks"]
    network = networks["public_ingress"]
    assert network["name"] == "${PUBLIC_INGRESS_NETWORK_NAME:-system-metrics-public}"
    assert network["driver"] == "bridge"
    assert network["enable_ipv6"] is False
    assert network["driver_opts"]["com.docker.network.bridge.name"] == (
        "${PUBLIC_INGRESS_BRIDGE_NAME:-np-public}"
    )
    assert network["driver_opts"]["com.docker.network.bridge.enable_icc"] == "false"
    for logical_name, network_name, bridge_name in (
        ("low_ingress", "system-metrics-low", "np-low"),
        ("medium_ingress", "system-metrics-medium", "np-medium"),
        ("high_ingress", "system-metrics-high", "np-high"),
    ):
        internal = networks[logical_name]
        assert internal["name"] == f"${{{logical_name.upper()}_NETWORK_NAME:-{network_name}}}"
        assert internal["internal"] is True
        assert internal["enable_ipv6"] is False
        assert internal["driver_opts"]["com.docker.network.bridge.name"] == (
            f"${{{logical_name.upper()}_BRIDGE_NAME:-{bridge_name}}}"
        )


def test_ingress_and_engine_network_boundaries_are_separate():
    services = load_ubuntu_compose()["services"]
    expected = {
        "low-ingress": "low_ingress",
        "low-udp-ingress": "low_ingress",
        "medium-http-ingress": "medium_ingress",
        "medium-ssh-ingress": "medium_ingress",
        "high-http-ingress": "high_ingress",
        "high-ssh-ingress": "high_ingress",
    }
    for service_name, engine_network in expected.items():
        networks = set(services[service_name]["networks"])
        assert networks == {engine_network, "public_ingress"}
        assert "agent_egress" not in networks
    assert set(services["low-honeypot"]["networks"]) == {"low_ingress"}
    assert set(services["medium-honeypot"]["networks"]) == {"medium_ingress"}
    assert set(services["high-honeypot"]["networks"]) == {"high_ingress"}
    assert set(services["runtime-worker"]["networks"]) == {"agent_egress"}
    agent_network = load_ubuntu_compose()["networks"]["agent_egress"]
    assert agent_network["name"] == "${AGENT_EGRESS_NETWORK_NAME:-system-metrics-agent}"
    assert agent_network["driver_opts"]["com.docker.network.bridge.name"] == (
        "${AGENT_EGRESS_BRIDGE_NAME:-np-agent}"
    )
    assert agent_network["driver_opts"]["com.docker.network.bridge.enable_icc"] == "false"


def test_firewall_owns_narrow_chains_and_covers_ipv4_ipv6_conntrack():
    source = FIREWALL_SCRIPT.read_text(encoding="utf-8")
    assert 'FORWARD_CHAIN="SME_FWD"' in source
    assert 'INPUT_CHAIN="SME_INPUT"' in source
    assert "iptables ip6tables" in source
    assert "ESTABLISHED,RELATED" in source
    assert "icmp-admin-prohibited" in source
    assert "icmp6-adm-prohibited" in source
    assert "iptables-restore" not in source
    assert "192.168." not in source
    assert "172.22." not in source
    assert 'HIGH_BRIDGE_NAME="${HIGH_INGRESS_BRIDGE_NAME:-np-high}"' in source
    assert 'AGENT_BRIDGE_NAME="${AGENT_EGRESS_BRIDGE_NAME:-np-agent}"' in source
    assert '-d "$CONTROL_IP" -p tcp --dport "$CONTROL_PORT"' in source
    assert "com.docker.compose.project" in source
    assert "com.docker.compose.network" in source
    assert '-F INPUT' not in source
    assert '-F FORWARD' not in source


def test_systemd_rollback_stops_only_the_owned_service():
    service = (ROOT / "deploy/ubuntu/system-metrics-egress.service").read_text(encoding="utf-8")
    rollback = (ROOT / "deploy/ubuntu/system-metrics-egress-rollback.service").read_text(
        encoding="utf-8"
    )
    timer = (ROOT / "deploy/ubuntu/system-metrics-egress-rollback.timer").read_text(
        encoding="utf-8"
    )
    assert "ExecStart=/usr/local/libexec/system-metrics-egress apply" in service
    assert "ExecStop=/usr/local/libexec/system-metrics-egress remove" in service
    assert "PartOf=docker.service" in service
    assert "systemctl stop system-metrics-egress.service" in rollback
    assert "OnActiveSec=5min" in timer
    assert "iptables-restore" not in rollback
    manager = (ROOT / "deploy/ubuntu/manage-system-metrics-egress").read_text(encoding="utf-8")
    assert 'enable --now "$ROLLBACK_TIMER"' in manager
    assert 'disable --now "$ROLLBACK_TIMER"' in manager
    assert '"$CORE" apply' in manager
    assert '"$CORE" remove' in manager


def test_firewall_scripts_have_valid_posix_shell_syntax():
    for path in (FIREWALL_SCRIPT, ROOT / "deploy/ubuntu/manage-system-metrics-egress"):
        result = subprocess.run(["sh", "-n", str(path)], capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr


FAKE_COMMAND = r'''#!/usr/bin/env python3
import os
import pathlib
import sys

name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
log = pathlib.Path(os.environ["FAKE_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(name + " " + " ".join(args) + "\n")

if name == "docker":
    fmt = args[args.index("--format") + 1]
    network = args[-1]
    if ".Driver" in fmt:
        print("bridge")
    elif ".Internal" in fmt:
        print(os.environ.get("FAKE_INTERNAL", "true" if network.endswith(("-low", "-medium", "-high")) else "false"))
    elif "com.docker.compose.project" in fmt:
        print(os.environ.get("FAKE_PROJECT", "system-metrics"))
    elif "com.docker.compose.network" in fmt:
        print({
            "system-metrics-public": "public_ingress",
            "system-metrics-low": "low_ingress",
            "system-metrics-medium": "medium_ingress",
            "system-metrics-high": "high_ingress",
            "system-metrics-agent": "agent_egress",
        }[network])
    else:
        print({
            "system-metrics-public": "np-public",
            "system-metrics-low": "np-low",
            "system-metrics-medium": "np-medium",
            "system-metrics-high": "np-high",
            "system-metrics-agent": "np-agent",
        }[network])
    raise SystemExit(0)
if name == "ip":
    raise SystemExit(0)

state = pathlib.Path(os.environ["FAKE_STATE"])
state.mkdir(exist_ok=True)
failure = os.environ.get("FAKE_FAIL_MATCH", "")
invocation = name + " " + " ".join(args)
if failure and failure in invocation:
    raise SystemExit(2)
family = name.replace("tables", "")
def marker(kind, parent, chain=""):
    return state / f"{family}-{kind}-{parent}-{chain}"

if "-n" in args and "-L" in args:
    chain = args[args.index("-L") + 1]
    if chain in {"DOCKER-USER", "FORWARD", "INPUT"} or marker("chain", chain).exists():
        raise SystemExit(0)
    raise SystemExit(1)
if "-N" in args:
    marker("chain", args[args.index("-N") + 1]).touch()
elif "-X" in args:
    marker("chain", args[args.index("-X") + 1]).unlink(missing_ok=True)
elif "-C" in args:
    parent = args[args.index("-C") + 1]
    chain = args[args.index("-j") + 1]
    raise SystemExit(0 if marker("jump", parent, chain).exists() else 1)
elif "-I" in args:
    parent = args[args.index("-I") + 1]
    chain = args[args.index("-j") + 1]
    marker("jump", parent, chain).touch()
elif "-D" in args:
    parent = args[args.index("-D") + 1]
    chain = args[args.index("-j") + 1]
    marker("jump", parent, chain).unlink(missing_ok=True)
raise SystemExit(0)
'''


@pytest.fixture
def fake_firewall_environment(tmp_path):
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    command = binary_dir / "fake-command"
    command.write_text(FAKE_COMMAND, encoding="utf-8")
    command.chmod(0o755)
    for name in ("docker", "ip", "iptables", "ip6tables"):
        (binary_dir / name).symlink_to(command)
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{binary_dir}:{environment['PATH']}",
            "FAKE_LOG": str(tmp_path / "commands.log"),
            "FAKE_STATE": str(tmp_path / "state"),
            "CONTROL_ENDPOINT_IP": "192.0.2.10",
            "CONTROL_PORT": "8443",
        }
    )
    return environment, tmp_path / "commands.log"


def test_apply_and_remove_are_idempotent_and_touch_only_owned_chains(fake_firewall_environment):
    environment, log_path = fake_firewall_environment
    subprocess.run(["sh", str(FIREWALL_SCRIPT), "apply"], check=True, env=environment)
    subprocess.run(["sh", str(FIREWALL_SCRIPT), "apply"], check=True, env=environment)
    subprocess.run(["sh", str(FIREWALL_SCRIPT), "remove"], check=True, env=environment)
    commands = log_path.read_text(encoding="utf-8")
    assert "iptables -w 5 -I FORWARD 1 -j SME_FWD" in commands
    assert "ip6tables -w 5 -I FORWARD 1 -j SME_FWD" in commands
    assert "-I DOCKER-USER 1 -j SME_FWD" not in commands
    assert "iptables -w 5 -I INPUT 1 -j SME_INPUT" in commands
    assert "-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN" in commands
    assert "-A SME_INPUT -i np-low" in commands
    assert "-A SME_INPUT -i np-medium" in commands
    assert "-A SME_INPUT -i np-high" in commands
    assert "-A SME_INPUT -i np-agent" in commands
    for bridge in ("np-low", "np-medium", "np-high"):
        assert f"-A SME_FWD -i {bridge} -o {bridge} -j RETURN" in commands
        assert f"-A SME_FWD -i {bridge} -j REJECT" in commands
    assert "-A SME_FWD -i np-agent -d 192.0.2.10 -p tcp --dport 8443" in commands
    assert "-A SME_FWD -i np-agent -j REJECT" in commands
    assert "-D FORWARD -j SME_FWD" in commands
    assert "-D INPUT -j SME_INPUT" in commands
    assert "-X SME_FWD" in commands
    assert "-X SME_INPUT" in commands
    assert "-F INPUT" not in commands
    assert "-F FORWARD" not in commands


def test_apply_fails_before_firewall_changes_for_unexpected_network(fake_firewall_environment):
    environment, log_path = fake_firewall_environment
    environment["FAKE_INTERNAL"] = "true"
    result = subprocess.run(
        ["sh", str(FIREWALL_SCRIPT), "apply"],
        check=False,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    commands = log_path.read_text(encoding="utf-8")
    assert not any("tables " in line for line in commands.splitlines())


def test_apply_fails_closed_for_missing_center_allowlist(fake_firewall_environment):
    environment, log_path = fake_firewall_environment
    environment["CONTROL_ENDPOINT_IP"] = ""
    result = subprocess.run(
        ["sh", str(FIREWALL_SCRIPT), "apply"],
        check=False,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "explicit IPv4" in result.stderr
    assert not log_path.exists()


def test_apply_rejects_network_from_another_compose_project(fake_firewall_environment):
    environment, log_path = fake_firewall_environment
    environment["FAKE_PROJECT"] = "lookalike-project"
    result = subprocess.run(
        ["sh", str(FIREWALL_SCRIPT), "apply"],
        check=False,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    commands = log_path.read_text(encoding="utf-8")
    assert not any("tables " in line for line in commands.splitlines())


def test_partial_firewall_failure_removes_only_owned_state(fake_firewall_environment):
    environment, _ = fake_firewall_environment
    state = Path(environment["FAKE_STATE"])
    state.mkdir(exist_ok=True)
    foreign = state / "foreign-project-rule"
    foreign.touch()
    environment["FAKE_FAIL_MATCH"] = "ip6tables -w 5 -A SME_FWD"

    result = subprocess.run(
        ["sh", str(FIREWALL_SCRIPT), "apply"],
        check=False,
        env=environment,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert foreign.exists()
    assert not any(path.name.startswith(("ip-", "ip6-")) for path in state.iterdir())
