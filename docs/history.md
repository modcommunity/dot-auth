# History

Bugs worth recognising if they come back. The rule each left is in the topic docs.

## The default backbone was a domain nobody owned

`DotAuthConfig.backbone_url` once shipped as a name that was not TMC's site (`moddingcommunity.com`, the only name website-city has ever used) and was, when found, not registered to anybody: no A record, no NS. Every deployment that did not override it aimed its device-code grant at a name any stranger could buy. It failed loudly only because the name did not resolve; the day somebody registered it, it would have started failing quietly instead.

It had also travelled: the wrong name was in the README, CLAUDE.md, `examples/issuer.gd` and both of dot-user-avatar's, because they were all written from the default. Found by opening the browser client and reading the network tab. **Nothing in any suite looks at what URL was dialled, and a headless run never dials one.**

## The issuer's listener

- **A body in a second TCP segment was answered `400 Expected a JSON body`**, because the listener parsed whatever one poll saw. Localhost testing never shows it, because a small request is coalesced into one segment.
- **curl's `Expect: 100-continue` stalled** until the client timed out, because nothing sent the interim response.
- **A per-read size check bounded nothing**; a trickling sender never tripped it.

## One seat per account

Each rule in [tickets.md](tickets.md#one-seat-per-account) (reconnect to the same server, unconfirmed sessions, rosters moving players, lease against ticket lifetime, per-server keys, a refusal naming the server) was the answer to a hole the demo would otherwise have found; the refusal's message was lost in `DotHttp`'s generic "Not allowed." until `_issuer_refusal()` kept the body.
