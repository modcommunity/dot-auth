# Strategies, local profiles, and providers

## The four strategies

`DotAuthConfig.strategy` decides how `DotAuthServer.authenticate()` behaves, so one server binary covers every deployment:

| Strategy | Use | Cost |
| --- | --- | --- |
| `TICKET` | **Public servers.** | Needs a publisher-run issuer. No per-join network call. |
| `INTROSPECT` | First-party servers only. | Operator holds a live account credential; a backbone round trip per join. Warns loudly at startup. |
| `LOCAL` | LAN, development. | Accounts in a JSON file. Password hashing is salted SHA-256 × 4096; see [security.md](security.md#two-things-that-are-weaker-than-they-look). |
| `ANONYMOUS` | Open servers. | Nobody is authenticated; bans cannot mean anything. Warns. |

`allow_guests` layers a guest fallback onto any strategy, and warns, because a banned player can always return as a different guest.

## Local profiles: accounts with no cloud

`allow_local_profiles` is deliberately **not** a strategy. It is a `DotAuthProvider`, so it composes: a server can take backbone tickets *and* let a visitor with no site account make one that lives here.

**Different from `LOCAL`.** That strategy is an operator-maintained file of usernames and passwords, for a server with a known cast. This is self-service: a visitor names themselves and is the same player next week.

### The identity is a credential the server ISSUES

On first join the server mints an id and a 32-byte secret, stores only a salted hash, and hands the secret to the client once; the client keeps it **per server** and presents it next time. A session cookie, essentially.

Every alternative was worse, and each is written down in `DotLocalProfiles` because each is the one somebody will propose again:

- **A name.** An offline mode that hashes the name into the uuid means anyone who types your name is you.
- **A machine id.** `device_hint()` exists and is *not* the identity. `OS.get_unique_id()` returns **nothing at all on web and iOS**, and a browser is a first-class target. It is also just a string the client sends, so it is exactly as forgeable as a name while looking authoritative, and it is stable across *accounts* as well as installs, so two people sharing a machine are one player. It is stored on creation and compared on verify **only to log** that a profile moved machine; enforcing it would lock players out for replacing a computer.
- **A password.** Puts a login form in front of somebody who wanted to play, and lands a password store on a game server.

### Three things that are load-bearing

- **The secret travels on `profile_created`, never on the identity.** An identity is *relayed* (dot-server sends one to every player in the match so they can draw each other's names), so a secret on it would be broadcast to the lobby. The signal fires synchronously inside `authenticate()`, so the peer being admitted is unambiguous. The demo asserts the secret does not appear in `identity.to_dict()`.
- **An unknown id and a wrong secret answer identically.** Distinguishing them hands an attacker the list of ids that exist.
- **Sign-in and sign-up are separate credentials**: `local_profile` versus `local_profile_new`. Folding them into "create it if the id is unknown" turns every mistyped or lost credential into a brand new profile, and a player whose secret was lost silently becomes a stranger with their own name taken.

### The id is a player key, unchanged

22 base64url characters: the shape `DotUserScope` derives and `DotAvatarKey.is_usable` accepts. So a local profile files a profile and an avatar through exactly the same store interfaces a backbone-backed player does, and **nothing downstream branches on which kind of account it is**: point dot-user and dot-user-avatar at their `local` backends and the whole platform works with no backbone at all.

The demo restates the key-shape check as `DotAvatarKeyShape` rather than calling dot-user-avatar's, because that agreement between two addons that never import each other is the thing being tested.

## Adding an authentication method

The four strategies do not cover a store or console platform, a chat service, a publisher's own account service, a LAN token or a QA bypass, and a game needing one should not fork this. Subclass `DotAuthProvider` and register it:

```gdscript
auth_server.add_provider(PlatformProvider.new())
```

Providers are consulted **before** the configured strategy, in priority order. Three rules so they compose safely:

- **`_handles()` must be cheap and structural** ("does this dictionary contain my field"). A provider doing network work there runs it for logins meant for somebody else.
- **A provider that claims a credential owns the outcome.** If it authenticates and then refuses, the built-in strategy does *not* get a second go; otherwise a refused login walks in through another door.
- **Namespace your uids.** `uid` is what bans and admin entries key on. Two platforms' account ids are both digits; unprefixed, a ban on one applies to whoever holds the other. `DotAuthProvider.authenticate` warns when a uid has no `:` in it.

Rate limiting runs before providers, so a custom provider cannot be used to make this server hammer an external service.

## Coupling with dot-server

dot-auth and dot-server do not import each other; either works alone. `DotAuthServer` registers itself in `DotRegistry` as `dot_auth_server`, and `DotAuthAdminSource` satisfies dot-server's admin-source contract (`lookup(identity) -> DotResult{flags, immunity, source}` plus `source_name()`) by duck typing. Keep it that way: a hard dependency in either direction makes both harder to adopt.

## Deliberately not here

- **OAuth authorization-code flow.** The device flow covers desktop, mobile, console and browser with one implementation and never asks a player to type credentials into a game client. A browser build could use a redirect flow for a smoother experience.
- **Platform SSO.** The backbone has a platform provider already; linking it would mean a platform id in `identity.claims` and a provider abstraction here.
- **Ed25519.** Godot's `Crypto` has no EdDSA. The backbone's own API JWTs use it, which is one more reason the issuer indirection exists.
- **Token binding to a connection.** A ticket proves identity at join time. Binding it to the transport session would need transport cooperation.
