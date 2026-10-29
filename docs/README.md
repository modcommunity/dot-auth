# dot-auth docs

The reasoning behind authentication, one subject per file. [CLAUDE.md](../CLAUDE.md) has the short rules; these say why.

| File | What it covers |
| --- | --- |
| [tickets.md](tickets.md) | Why tickets rather than tokens, the four properties of a ticket, one seat per account, the issuer and its HTTP listener |
| [strategies.md](strategies.md) | The four strategies, guests, local profiles, custom providers, coupling with dot-server, what is deliberately not here |
| [backbone.md](backbone.md) | The website-city endpoints this depends on, the details already handled, the backbone URL and overriding it |
| [security.md](security.md) | Decisions worth not undoing, and the two things weaker than they look |
| [history.md](history.md) | The bugs, and how each looked |
| [rationale.md](rationale.md) | Reasoning moved out of source comments, one section per file |
| [api-levels.md](api-levels.md) | What each API level added |
