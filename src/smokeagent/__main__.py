"""Allow ``python -m smokeagent``."""

from smokeagent.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
