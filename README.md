# vea-challenger

An independent challenger bot for the [Vea](https://vea.ninja) optimistic bridge.

It watches `Claimed` events on a Vea outbox, independently verifies every claimed
state root against the Vea inbox snapshot on the origin chain (quorum reads over
multiple RPCs, at the `finalized` tag), and **challenges any claim whose root does
not match** — then drives the challenge through the canonical bridge to resolution
and withdraws the reward.

Built in Python from the Vea contracts and public docs only; it shares no code or
design with the TypeScript `validator-cli`.

## How it decides (safety rules)

- A verdict is only issued from inbox state that can no longer change:
  - the **finalized** L2 block once its timestamp passes the claimed epoch's end, or
  - the **latest** tag only once it is `sequencerDelayLimit` past the epoch end
    (before that a malicious sequencer could still backdate a `saveSnapshot`).
- `snapshots(epoch) == 0x0` (no snapshot saved) makes **any** claim fraudulent.
- Every configured RPC must agree on the snapshot value; splits raise a CRITICAL
  alert instead of a (deposit-forfeiting) blind challenge — override with
  `VEA_CHALLENGE_ON_AMBIGUITY=true`.
- The Claim struct is reconstructed from events and kept byte-identical to the
  on-chain `claimHashes[epoch]` preimage, including hash-probing for the two
  transitions the contracts don't emit events for (the `Verified` winner and the
  escape-hatch mutations).

## Quick start

```bash
uv sync
cp .env.example .env   # add VEA_CHALLENGE_PRIVATE_KEY (funded EOA), pick a route

uv run vea-challenger scan      # one read-only detection pass
uv run vea-challenger run       # the real thing (challenges cost `deposit`!)
uv run vea-challenger --dry-run run   # detect + alert, never spend
uv run vea-challenger status    # tracked claims + balances
```

Manual lifecycle commands (normally automated by `run`):

```bash
uv run vea-challenger challenge --epoch 246810
uv run vea-challenger resolve  --epoch 246810   # sendSnapshot / execute L2->L1
uv run vea-challenger withdraw --epoch 246810
```

## Routes

Built-in: `arb-sepolia-to-sepolia-testnet` (default), `arb-sepolia-to-sepolia-devnet`,
`arb-sepolia-to-chiado-testnet`, `arb-sepolia-to-chiado-devnet`.
Custom routes (e.g. mainnet): copy a block from `config.py` into a TOML file and
set `VEA_ROUTE_FILE`. ArbToGnosis routes take the deposit in **WETH** on Gnosis
(the bot manages the allowance; keep the challenge account funded with WETH plus
native gas).

## Funding & risk

| | |
|---|---|
| Challenge deposit | `outbox.deposit()` — 1 ETH on the ArbToEth testnet route |
| Winning a challenge | +0.5 × deposit (plus your deposit back) |
| Losing a challenge | −1.0 × deposit (half burned, half to the claimer) |
| Resolution round trip | days (Arbitrum assertion confirmation), fully automated |

Use a **plain EOA** for both keys: several contract payouts use `.send()` with a
2300-gas stipend and will silently burn funds sent to contracts. Never overpay
the deposit (the bot always sends exactly `deposit`).

One honest, funded challenger is what keeps an optimistic bridge honest. If the
bot ever logs `INSUFFICIENT FUNDS to challenge`, treat it as an incident.

## Operations

- State lives in a per-route SQLite file; the process is crash-safe and restartable
  at any point (tx intents are journaled before broadcast).
- Two key lanes: challenges never share a nonce sequence with slow resolution txs.
- `VEA_WEBHOOK_URL` gets Slack/Discord-compatible JSON alerts; `CRITICAL` means a
  fraud was found (or the bot cannot act — page someone).
- Startup self-checks fail fast: chain-id match, genuine `finalized` tag support,
  local `hashClaim` parity against the deployed contract, funding.

## Docker

```bash
# Build locally
docker build -t vea-challenger .

# Or pull the pre-built image from GitHub Container Registry
docker pull ghcr.io/kleros/vea-validator3:latest

# state (SQLite db) persists under ./data on the host, mapped to /data in the container
# the container runs as uid 1000, so the host dir must be writable by that uid
mkdir -p data
chown 1000:1000 data
docker run -d --name vea-challenger \
  --env-file .env \
  -v "$(pwd)/data:/data" \
  vea-challenger              # runs `vea-challenger run`

# other subcommands override CMD, entrypoint is fixed to the `vea-challenger` binary
docker run --rm --env-file .env -v "$(pwd)/data:/data" vea-challenger status
docker run --rm --env-file .env -v "$(pwd)/data:/data" vea-challenger scan
docker run --rm --env-file .env -v "$(pwd)/data:/data" vea-challenger challenge --epoch 246810
```

Or use docker-compose:

```bash
docker compose up -d
```

See [`docker-compose.yml`](docker-compose.yml) for the pre-configured setup pointing to `ghcr.io/kleros/vea-validator3`.

`VEA_DB_PATH` defaults to `/data/vea-challenger.db` in the image. For a custom
route (`VEA_ROUTE_FILE`), also mount the TOML file under `/data` and point the
env var at it, e.g. `-v $(pwd)/route.toml:/data/route.toml -e VEA_ROUTE_FILE=/data/route.toml`.

## Development

```bash
uv run pytest            # unit tests (no network)
uv run pytest -m live    # read-only smoke tests against public testnet RPCs
```

Design doc and threat analysis: [docs/design.md](docs/design.md).
