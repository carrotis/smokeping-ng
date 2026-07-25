"""Allow ``python -m smokeserver``."""

from smokeserver.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
