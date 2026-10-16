"""Create local CA and server certificate without printing key material."""

import os
import shutil
from pathlib import Path

from app.pki import ensure_local_pki


def main() -> None:
    directory = Path(os.environ.get("PKI_DIR", "secrets/pki"))
    public_directory = Path(os.environ.get("PKI_PUBLIC_DIR", "secrets/pki-public"))
    existed = (directory / "ca.crt").exists()
    ensure_local_pki(directory)
    public_directory.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(directory / "ca.crt", public_directory / "ca.crt")
    shutil.copyfile(directory / "server.pin", public_directory / "server.pin")
    Path(os.environ.get("AGENT_BOOTSTRAP_DIR", "secrets/agent")).mkdir(parents=True, exist_ok=True)
    print("Local PKI already present" if existed else "Local PKI created; key material was not printed")


if __name__ == "__main__":
    main()
