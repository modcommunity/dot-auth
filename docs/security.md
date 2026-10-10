# Security decisions worth not undoing

- **`DotJwt` pins the algorithm at the call site.** `verify_rs256` requires `alg == "RS256"` and refuses anything else. Reading `alg` from the token and dispatching on it is the classic JWT vulnerability: you get handed `{"alg":"none"}`, or an HS256 token signed with the RSA *public* key as the HMAC secret. `examples/auth_demo.tscn` tests exactly that attack.
- **Every MAC comparison is constant-time** (`DotHash.constant_time_equal`). Early-return comparison leaks how many leading bytes were right, turning forgery into 32 rounds of 256 tries.
- **Unknown username and wrong password are indistinguishable**: same code, same message, and the hash runs either way so the timing matches too. The same holds for an unknown local-profile id against a wrong secret, and an unknown server against a wrong server key.
- **An authenticated player cannot override their display name**; only guests may name themselves. `_apply_requested_name()` enforces it, and the demo tests that "Ada" cannot connect as "Administrator".
- **Guests never get admin flags.** `DotAuthAdminSource.lookup()` refuses them outright: a guest uid is a random per-device string, so granting anything would grant it to anyone who asks.
- **`role_flags` is empty by default.** A site moderator is *not* automatically an admin on every community server running this addon. Shipping that default would hand anyone with a site role control of every server.
- **Secrets are refused from environment and argv** (`sensitive_keys()`), per the family rule.
- **`DotPkce` hashes the ASCII of the verifier**, which is what S256 specifies.

## Two things that are weaker than they look

**`DotAuthServer.hash_password` is salted SHA-256 with 4096 rounds.** That is not adequate for a public account system: passwords deserve argon2 or bcrypt, and Godot ships neither. It exists so a LAN server does not keep plaintext in a JSON file. Anything with real users belongs on the backbone, which does it properly.

**`DotAuthTokenStore` encryption is obfuscation on web.** The key derives from a per-install salt stored next to the ciphertext plus a device-stable string. Against another user on the machine, that works. Against the machine's owner, or anything running as the same user, it does not. On web everything is in one origin, so devtools recovers both halves. It still raises the cost of the common cases (synced backups, shared PCs, files in support bundles) and makes tampering detectable.
