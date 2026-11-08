#!/usr/bin/env python3
"""Create a small synthetic Keystone access log for an offline demonstration."""

from pathlib import Path


path = Path("/tmp/keystone_access_demo.log")
path.write_text(
    '192.0.2.10 - - [22/Jun/2026:12:00:00 +0200] '
    '"POST /identity/v3/auth/tokens HTTP/1.1" 201 1024\n'
    '198.51.100.7 - - [22/Jun/2026:12:01:00 +0200] '
    '"POST /identity/v3/auth/tokens HTTP/1.1" 401 256\n',
    encoding="utf-8",
)
print(path)

