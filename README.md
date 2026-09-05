This is the **authentication** asset for TMC's **Dot** collection. It is how a player signs in, and how a game server learns who they are without ever being handed their account.

This collection of assets provides modular building blocks for creating games and applications within the TMC ecosystem, ensuring consistency and interoperability across all `dot-*` assets. This includes core functionality, networking, authentication, cloud integration, and more.

**These assets are COMPLETELY OPEN SOURCE**. You are free to use, modify, and distribute them under the terms of the MIT license. The only thing not open source is the back-end web infrastructure. So if you opt into using your own authentication backend instead of integrating with TMC, you will need to build and integrate your own back-end infrastructure.

## From Maintainer & WARNING
This asset, along with all the others, was built initially with **Claude Code** and will continue to be maintained and extended using it. This is because I (`gamemann`) cannot build the entire TMC platform alone (I wish I could lol).

**Please treat this as partially tested.** Every asset has its own headless test suite and those suites pass, but very little of this has been in front of real players yet. Expect rough edges, and please report anything you run into.

I intend on reviewing code, testing, and editing documentation regularly. If you're interested in helping out, please let me know!

## Authentication for Games and Dedicated Servers
Open-source authentication for Godot 4 games and dedicated servers. Signs players
in against a web backbone, then proves who they are to a game server **without
handing that server a credential for their account**.

Part of the `dot-*` family alongside [dot-core](../dot-core),
[dot-server](../dot-server) and [dot-cloud](../dot-cloud).

## Install

Copy `addons/dot_core/` and `addons/dot_auth/` into your project and enable both
in *Project → Project Settings → Plugins*. Requires Godot 4.4+.

## Client

```gdscript
var auth := DotAuthClient.new()
add_child(auth)
auth.config = DotAuthConfig.new()
auth.config.backbone_url = "https://themodcommunity.com"
auth.config.client_name = "My Game"

auth.device_code_ready.connect(func(user_code, url, _expires):
    code_label.text = user_code      # for players on another device
    OS.shell_open(url))              # opens with the code pre-filled

var res := await auth.sign_in()
if res.ok:
    print("hello ", (res.value as DotAuthIdentity).display_name)
```

A device-code flow, not a password field — so the password is only ever typed on
the website, and the same code works on desktop, mobile, console and in a browser.
Returning players never see a code: `sign_in()` restores from a stored rotating
refresh token.

## Server

```gdscript
var auth := DotAuthServer.new()
add_child(auth)
auth.config.strategy = DotAuthConfig.Strategy.TICKET
auth.config.server_id = "eu-west-1"
auth.config.ticket_public_key = ISSUER_PUBLIC_KEY

var res := await auth.authenticate({"ticket": ticket_from_client}, peer_address)
if not res.ok:
    reject(res.error.message)
    return
var identity: DotAuthIdentity = res.value
```

Verification is offline — no backbone round trip per join.

## Why tickets

A community server that receives a player's account token can act as that player
on the whole site. So instead:

```
client ──(device-code + PKCE)──> backbone         who am I
client ──(access token)────────> DotAuthIssuer    first-party, publisher-run
client <──(signed ticket)─────── DotAuthIssuer    one server, a few minutes
client ──(ticket)──────────────> game server      verified offline
```

The ticket is audience-scoped, short-lived, single-use and RSA-signed. A server can
verify it but cannot mint one, and a ticket captured on one server is refused by
every other. `DotAuthIssuer` is the only component that needs the private key, and
it runs standalone with no changes to the backbone.

## Four strategies

| | |
| --- | --- |
| `TICKET` | Public servers. The above. |
| `INTROSPECT` | First-party servers only — the operator holds a live account credential. Warns at startup. |
| `LOCAL` | LAN and development. Accounts in a JSON file. |
| `ANONYMOUS` | Everyone is a guest. Bans cannot mean anything. Warns. |

Plus **local profiles**, which are a provider rather than a strategy and so work
alongside any of them — see below.

## Accounts with no cloud

Not every game wants an identity service, and not every player has an account.
`allow_local_profiles` lets a visitor make one that lives on **that server and
nowhere else** — with a profile and an avatar, persisting between visits.

```gdscript
config.allow_local_profiles = true          # server
config.local_profiles_path = "user://profiles.json"
```

```gdscript
# Client: present what we hold for this server, or ask for a new one.
var keeper := DotLocalProfileClient.at("user://local_profiles.dat")
keeper.open()

var credential := keeper.credential_for(server_id)
if credential.is_empty():
    credential = {"local_profile_new": {"name": chosen_name}}

# The server issues the secret exactly once; keep it or the profile is lost.
keeper.remember(server_id, id, secret, name)
```

It is a **provider**, not a strategy, so it composes: a server can accept backbone
tickets and local profiles at once.

**The server issues the credential — the client does not claim an identity.** That
is the difference between this and offline-mode accounts elsewhere, where the name
*is* the identity and anyone who types yours is you. A machine id is deliberately
not used: `OS.get_unique_id()` is empty on web and iOS, it is client-supplied and
so exactly as forgeable as a name, and it is shared by everyone using that
computer. It is recorded as a hint and only ever logged.

The id is a 22-character player key of the same shape everything else here uses,
so dot-user and dot-user-avatar file a local player's profile and avatar through
their ordinary local backends. **A complete platform, with no backbone.**

## Also included

- **`DotBackboneClient`** — a dedicated server reporting its own player count,
  map and roster to its site listing, with the replay protection the integration
  API requires.
- **`DotAuthAdminSource`** — maps site groups, roles and claims to dot-server
  permission flags and immunity levels, so "everyone in the site group
  `moderators` can kick here" is one rule instead of a hand-edited user list.
  Guests never receive permissions; site roles grant nothing unless you map them.

## Try it

```bash
godot --headless --path . res://examples/auth_demo.tscn
```

47 offline checks covering ticket minting and verification, audience scoping,
replay refusal, expiry and clock skew, tamper detection, JWT algorithm confusion,
PKCE derivation, local accounts (including username-enumeration resistance),
the admin mapping, and encrypted token storage.

Run an issuer with `res://examples/issuer.tscn`.

## Honest limits

`DotAuthServer.hash_password` is salted SHA-256, not argon2 — Godot ships no
password KDF. It exists so a LAN server does not store plaintext; real accounts
belong on the backbone. And on web the token store's encryption is obfuscation,
because the key and the ciphertext share one origin. Both are documented where they
matter in [CLAUDE.md](CLAUDE.md#two-things-that-are-weaker-than-they-look).

## Licence

MIT — see [LICENSE](LICENSE).
