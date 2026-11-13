# Cloud-delivered boot configuration for the control plane

Status: design, not implemented. Owner: TBD. Last updated: 2026-11-13.

## Why

Vercel held the control plane's environment directly. When the free tier ran
out, two things broke at once: the deployment moved to Render without those
values, and the values became unreadable in the Vercel dashboard. The result
was a healthy-looking container where every login returned 503.

The fix is not "copy the values to Render". It is to make Render a bootstrap
target and make AgentSecrets the source of truth for the configuration itself.
Dogfooding is the right call because it exercises the exact path customers
use. That said, the control plane is the one workload that cannot be a pure
cloud consumer without care. This document is the plan and the constraints.

## What is live today

Probed against `api.agentsecrets.tech` on 2026-11-13:

| Probe | Result |
|---|---|
| `GET /api/status/health/` | 200 healthy |
| `POST /api/auth/opaque/login/start/` (existing account) | 503 `opaque_unavailable` |
| `entrypoint.sh` with no OPAQUE env | boots silently, no warning |
| `entrypoint.sh` with token + key material | sidecar ready, `/healthz` 200 |

`OPAQUE_SIDECAR_URL` is not a credential. `entrypoint.sh` exports
`http://127.0.0.1:8790` when the token and key material are present. It does
not need to be stored anywhere.

The complete set for the server is 12 names, already present in the
`secretsapi` project's `development` environment: `ALLOWED_HOSTS`,
`ENCRYPTION_KEY`, `OPAQUE_SERVER_KEY_MATERIAL`, `OPAQUE_SIDECAR_TOKEN`,
`POSTGRES_DB`, `POSTGRES_HOST`, `POSTGRES_PASSWORD`, `POSTGRES_PORT`,
`POSTGRES_USER`, `SECRET_KEY`, `SETTINGS`, `TESTAGENTRECKEY`. The
`OPAQUE_SERVER_KEY_MATERIAL` value there is confirmed to be the Vercel
production key set. It must never be rotated.

## The credential count question

A normal deployment needs **one** credential in its host environment: the
workload token in `AGENTSECRETS_TOKEN`. This was true before CLI commit
`6996470`. Tokens minted before that commit carry no `cnf_key` and still work
with one value. Tokens minted after it are proof-of-possession bound.

The resolver's rule is in `internal/server/pop.go`:

```
if len(cap.ConfirmationKey) == 0 { return nil }   // skip PoP
```

No confirmation key means no proof is demanded. `agentsecrets env --cloud`
reads `AGENTSECRETS_TOKEN`, calls `POST /v1/workloads/env`, and gets a sealed
environment back. No second value.

Commit `6996470` made proof-of-possession the default for `agent create`. A
default token now carries `cnf_key`, and its private seed is stored only in
the OS keychain of the machine that minted it. On a server with just the
token, `pop.AttachProof` finds no seed and sends no proof, so
`internal/server/env.go` returns `proof of possession failed`. The token is
refused.

So the accurate statement is:

| Token | Values needed on the host | Works today |
|---|---|---|
| Pre-`6996470` (no `cnf_key`) | `AGENTSECRETS_TOKEN` | yes |
| PoP-bound (default since `6996470`) | `AGENTSECRETS_TOKEN` + `AGENTSECRETS_POP_SEED` | yes |
| PoP-bound | `AGENTSECRETS_TOKEN` alone | **no, 401** |

The `--no-pop` escape hatch was removed. `agent create` now always binds the
token and prints `AGENTSECRETS_POP_SEED` next to the token; the host copies that
seed into its platform secret manager beside the token. The seed cannot be
fetched from AgentSecrets because fetching it already requires the proof, so a
static second secret on the host is the current delivery mechanism. One value
is enough only for legacy unbound tokens.

### Regression (closed)

Default-on PoP broke the raw-injection path: mint an agent on a laptop, put
`AGENTSECRETS_TOKEN` in CI or a server, run `env --cloud`. With no seed on the
host, `pop.AttachProof` sent no proof and the resolver returned 401. The fix is
the printed seed: the host holds the token and `AGENTSECRETS_POP_SEED`, and
`LoadSignerFromEnvironment` makes `AttachProof` use it. This is option A from the
original discussion, now shipped. Locked by `TestSeedEnvReproducesProofKey` (CLI)
and `TestWorkloadEnv_PoPBoundTokenRequiresProof` (resolver).

Remaining open work (option 1): key transport that avoids a static second
secret entirely, binding the proof key to the workload's platform identity
(open ADR `1cf67af8`) so a leaked token alone is still useless without a host
identity. Until then, the control-plane bootstrap uses a PoP-bound token with
its seed in `AGENTSECRETS_POP_SEED`.

## Design

### Bootstrap set

Render keeps a small, fixed set. Everything else comes from AgentSecrets.

| Keep in Render | Reason |
|---|---|
| `AGENTSECRETS_TOKEN` | The one identity credential. Cannot be self-delivered. |
| `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | Django cannot start without a database connection. |
| `SECRET_KEY`, `ENCRYPTION_KEY` | Needed to boot Django and serve the token-verify endpoint. |
| `OPAQUE_SERVER_KEY_MATERIAL`, `OPAQUE_SIDECAR_TOKEN` | The sidecar must start before the app serves login. Stable, never rotated. |

Delivered from AgentSecrets: `ALLOWED_HOSTS`, `SETTINGS`, `TESTAGENTRECKEY`,
OAuth and Brevo keys, Polar keys, and every other non-boot value.

This is not zero credentials. It is a reduction from a Vercel-managed list to
one identity token plus the boot-critical set, and it puts the rest under
rotation and audit.

### Two-stage entrypoint

`ENTRYPOINT` stays `/app/entrypoint.sh`. It becomes stage one:

1. `exec agentsecrets env --cloud -- /app/entrypoint-boot.sh`.
2. Stage two runs the current body: wait for Postgres, migrations, start the
   OPAQUE sidecar, then `exec gunicorn ...`.

The CLI binary is added to the image in a build stage pinned to a CLI ref,
the same pattern the Dockerfile already uses for the OPAQUE sidecar.

A resolution failure must fail closed with a clear message naming the token
and the project. Render will show it as a failed deploy. A silent fallback to
stale or empty configuration is not acceptable.

### Cold-start dependency

`internal/state/store.go` is a volatile in-memory capability cache. On a cold
start, `internal/server/env.go` re-verifies a workload token against the
Django control plane at `verifyTokenWithControlPlaneOn`. If the control plane
is waiting on the resolver for its secrets, neither service can start.

The bootstrap set is what breaks the cycle: Django starts with just the
database and signing keys, serves the verify endpoint, and the resolver can
warm its cache. The full environment arrives before gunicorn serves traffic.

This must be proven with a both-cold test, not assumed. Three cases:

- resolver warm, control plane cold: normal deploy.
- both cold from a clean restart: the cycle case.
- resolver unreachable: entrypoint fails closed with a named error.

Ordering the two Render services so the resolver is healthy first reduces the
window but is not a fix.

### PoP on the bootstrap token

The bootstrap token is minted with `--no-pop`. That reintroduces a bearer-only
credential, which is the downgrade the operator already flagged. Mitigations
that do not require cloud changes:

- Scope it to one project, one environment, read-only, with the shortest
  usable expiry and rotation on a schedule.
- Never reuse it for anything else.
- Add `require_pop` as a per-agent policy in the resolver once key transport
  lands, then migrate the bootstrap token to a bound one.

The second static secret is not the risk on its own. The real risk is the
resolver accepting tokens with no `cnf_key` at all, which a server-side
policy must close. A leaked token alone is useless because it cannot prove
possession without the seed.

## Phases

Each phase ends in a check that can fail.

1. **Unblock login.** Put `OPAQUE_SERVER_KEY_MATERIAL` and
   `OPAQUE_SIDECAR_TOKEN` from `secretsapi/development` into Render and
   redeploy. Check: `POST /auth/opaque/login/start/` for an existing account
   returns something other than 503, and `agentsecrets login` completes.
2. **Make misconfiguration visible.** Ship the startup warning and the
   advisory `components.opaque` health field. Check: `GET
   /api/status/health/` reports `{"configured": true}` on the live host.
3. **Complete the inventory.** Compare the 12 names in `secretsapi` with the
   Render environment. Add any missing values to AgentSecrets, then verify
   every boot-critical key has a recoverable copy outside Render.
4. **Transfer the project.** `agentsecrets project transfer secretsapi --to
   "The Seventeen Engineering"`. Only after phase 1, because the transfer
   re-encrypts the only copy of the OPAQUE key material.
5. **Prove raw delivery.** Mint a scoped agent, copy the printed
   `AGENTSECRETS_POP_SEED` beside `AGENTSECRETS_TOKEN` in a scratch container,
   run `agentsecrets env --cloud -- env`, and confirm the delivered names
   match. Check: no credential values in logs or in the resolver response body.
6. **Implement the two-stage entrypoint** with the bootstrap set. Check all
   three cold-start cases above, plus the live health probe.
7. **Close the PoP gap.** Land ADR `1cf67af8` key transport and the
   `require_pop` policy, so a host needs no static seed and a leaked token
   alone is still useless without a platform identity.

## Open decisions

- Where the bootstrap workload token is created and who can rotate it.
- Whether the resolver capability cache should be persisted, which would
  remove the control-plane verify dependency on a cold start.
- Whether `OPAQUE_SERVER_KEY_MATERIAL` should live in a KMS rather than any
  environment at all. It is the one value that cannot be rotated without
  re-enrolling every account.
- Moving the dashboard off Vercel. That is independent of this work. The CLI
  and the MCP read plane do not need the website.
