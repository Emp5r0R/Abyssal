"""Static profile gates, plus explicit optional native/offline validation modes."""
import argparse
import configparser
import hashlib
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
PROFILES = ROOT / "deploy/private-transports"
args = argparse.ArgumentParser()
args.add_argument("--tor", help="Tor executable for native config validation")
args.add_argument("--i2pd", help="i2pd executable for a temporary, network-disabled router test")
options = args.parse_args()
tor_text = (PROFILES / "torrc.example").read_text()
tor_pairs = [shlex.split(line, comments=True) for line in tor_text.splitlines()]
tor_pairs = [line for line in tor_pairs if line]
assert len({line[0] for line in tor_pairs}) == len(tor_pairs)
tor = {line[0]: line[1:] for line in tor_pairs}
for key, value in {"SocksPort": ["0"], "ControlPort": ["0"], "ClientOnly": ["1"], "SafeLogging": ["1"],
                   "HiddenServiceVersion": ["3"], "HiddenServicePort": ["80", "127.0.0.1:4020"],
                   "Log": ["err", "file", "/dev/null"], "HiddenServiceMaxStreamsCloseCircuit": ["1"]}.items():
    assert tor[key] == value, key
assert tor["DataDirectory"][0].startswith("/run/")
assert tor["HiddenServiceDir"][0].startswith("/var/lib/")

config_text = (PROFILES / "i2pd.conf.example").read_text()
config = configparser.ConfigParser(interpolation=None, strict=True)
config.read_string("[general]\n" + config_text)
for section in ["http", "httpproxy", "socksproxy", "sam", "bob", "i2cp", "i2pcontrol", "upnp", "nettime", "addressbook"]:
    assert not config.getboolean(section, "enabled"), section
assert config.get("general", "log") == "stdout"
assert config.get("general", "loglevel") == "none"
assert not config.getboolean("general", "daemon")
assert config.getboolean("general", "notransit")
assert config.getboolean("reseed", "verify")
assert not config.getboolean("reseed", "followredirect")
assert not config.getboolean("persist", "profiles")
assert not config.getboolean("persist", "addressbook")
tunnel_text = (PROFILES / "i2pd-tunnels.conf.example").read_text()
tunnels = configparser.ConfigParser(interpolation=None, strict=True)
tunnels.read_string(tunnel_text)
assert tunnels.sections() == ["abyssal"]
tunnel = tunnels["abyssal"]
assert tunnel["type"] == "server" and tunnel["host"] == "127.0.0.1"
assert tunnel.getint("port") == 4020 and tunnel.getint("inport") == 80
assert not tunnel.getboolean("enableuniquelocal") and not tunnel.getboolean("gzip")
assert tunnel["keys"] == "identity/abyssal-destination.dat"

with tempfile.TemporaryDirectory(prefix="abyssal-private-profile-") as temp:
    directory = Path(temp)
    if options.tor:
        text = tor_text.replace(tor["DataDirectory"][0], str(directory / "tor-router"))
        text = text.replace(tor["HiddenServiceDir"][0], str(directory / "tor-service"))
        path = directory / "torrc"
        path.write_text(text)
        result = subprocess.run([options.tor, "--verify-config", "-f", str(path)], capture_output=True, timeout=10)
        assert result.returncode == 0, "Tor profile validation failed"
        print("Native Tor configuration validated")
    if options.i2pd:
        config_path = directory / "i2pd.conf"
        offline_config = "ipv4 = true\nipv6 = false\n" + config_text.replace(
            "[reseed]", "[reseed]\nthreshold = 0"
        ) + "\n[ntcp2]\nenabled = true\npublished = false\n[ssu2]\nenabled = false\n"
        config_path.write_text(offline_config)
        data_dir = directory / "i2p-router"
        key = data_dir / tunnel["keys"]
        key.parent.mkdir(parents=True, mode=0o700)
        tunnel_path = directory / "tunnels.conf"
        tunnel_path.write_text(tunnel_text)
        extra = directory / "extra"
        extra.mkdir()
        # i2pd requires a transport at startup. A fresh Linux network namespace
        # provides no external interfaces or routes, without weakening its config.
        command = ["unshare", "--user", "--map-root-user", "--net", options.i2pd,
                   f"--conf={config_path}", f"--tunconf={tunnel_path}", f"--tunnelsdir={extra}",
                   f"--datadir={data_dir}"]
        previous_digest = None
        for _ in range(2):
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, umask=0o077)
            try:
                try:
                    stdout, stderr = process.communicate(timeout=5)
                    # This router has only disposable test keys, never deployment secrets.
                    detail = (stderr + stdout)[:2048].decode("utf-8", errors="replace")
                    raise AssertionError(f"i2pd profile exited ({process.returncode}): {detail}")
                except subprocess.TimeoutExpired:
                    assert key.is_file() and key.stat().st_size > 32, "i2pd did not load the configured destination"
                    assert key.stat().st_mode & 0o077 == 0, "i2pd key is not owner-only"
                    digest = hashlib.sha256(key.read_bytes()).digest()
                    assert previous_digest is None or previous_digest == digest, "i2pd identity changed on restart"
                    previous_digest = digest
            finally:
                process.terminate()
                try:
                    process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
        print("Native i2pd destination initializes and survives restart in an isolated network namespace")
print("Private transport profile checks passed")
