#!/usr/local/bin/python
from __future__ import annotations

import os
import sys


sys.path.insert(0, os.environ.get("RUNTIME_INSTALL_PATH", "/opt/system-metrics"))

from agent.bootstrap import main  # noqa: E402


if __name__ == "__main__":
    main()
