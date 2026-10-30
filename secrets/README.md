# Secrets

Files here are mounted as Docker secrets and are never committed.

| File | How to create |
| --- | --- |
| `csrf_key` | `head -c 48 /dev/urandom \| base64 > secrets/csrf_key && chmod 600 secrets/csrf_key` |

Changing `csrf_key` makes every open upload page reload before it can send.
