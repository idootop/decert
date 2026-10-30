#!/usr/bin/env python3
"""静态检查：PoC 的域名 allowlist 行为符合预期。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scope import is_lab_domain, require_lab_domain


def main() -> int:
    for ok in ("site.decert.test", "bank.decert.test"):
        assert is_lab_domain(ok)
        assert require_lab_domain(ok) == ok
    for bad in ("example.com", "decert.test.example.com", "evil.test", ""):
        try:
            require_lab_domain(bad)
        except ValueError:
            continue
        print(f"allowlist 未拒绝：{bad!r}", file=sys.stderr)
        return 1
    print("  ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
