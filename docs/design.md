# Vea Challenger Bot — Design

Date: 2026-07-07
Status: v3 — after two adversarial red-team passes in separate Opus sessions:
design review (22 findings; all HIGH adopted) and implementation review
(10 findings; all fixed, regression-tested in tests/test_redteam_fixes.py)

## Mission

An independent watcher/challenger for the Vea optimistic bridge. It watches `Claimed`
events on a Vea outbox, independently verifies each claimed state root against the
Vea inbox snapshot on the origin chain, and challenges any claim whose state root
does not match. It then drives the challenge to resolution (send snapshot through the
canonical bridge, execute the L2→L1 message, withdraw the reward).

Built from the contracts and public docs only — deliberately shares no code or design
with `validator-cli` / `relayer-cli` (never read).

## Protocol facts the design relies on (from contracts)

- **Inbox (origin chain, e.g. Arbitrum)** — `VeaInboxArbToEth` / `VeaInboxArbToGnosis`:
  - `snapshots(epoch) → bytes32`: state root of the inbox merkle tree, saved by anyone
    calling `saveSnapshot()` during that epoch (L2 clock: `epoch = block.timestamp / epochPeriod`).
    May be overwritten within the epoch; immutable once the L2 clock passes the epoch end.
    `snapshots(epoch) == 0x0` if nobody saved a snapshot in that epoch.
  - `sendSnapshot(epoch, claim)`: permissionless; sends `resolveDisputedClaim(epoch, snapshots[epoch], claim)`
    through the canonical bridge (ArbSys L2→L1 message). Emits `SnapshotSent(epoch, ticketId)`.
- **Outbox (destination chain, e.g. Ethereum / Gnosis)** — `VeaOutboxArbToEth` / `VeaOutboxArbToGnosis`:
  - `claim(epoch, stateRoot)`: requires `epoch == block.timestamp/epochPeriod - 1` (L1 clock),
    nonzero root, deposit (native ETH for ArbToEth; WETH `transferFrom` for ArbToGnosis).
    Stores `claimHashes[epoch] = hashClaim(Claim{...})`, emits `Claimed(claimer, epoch, stateRoot)`.
  - `challenge(epoch, claim)` (+ ArbToEth-only overload with withdrawal address): requires the
    exact current preimage of `claimHashes[epoch]`, a deposit, `claim.challenger == 0`,
    `claim.honest == None`. Sets `challenger`, emits `Challenged(epoch, challenger)`.
    **Permissionless in all variants including devnet.**
  - `startVerification(epoch, claim)`: only after `now - timestampClaimed >= sequencerDelayLimit + epochPeriod`
    (devnet variant: no delay). Stamps `timestampVerification`/`blocknumberVerification`.
  - `verifySnapshot(epoch, claim)`: only if unchallenged and censorship test passed
    (`now - timestampVerification >= minChallengePeriod` and few missing blocks). Sets `honest = Claimer`.
  - `resolveDisputedClaim(epoch, trueRoot, claim)`: only from the canonical bridge; sets
    `honest = Challenger` if `claim.stateRoot != trueRoot` and a challenger exists; else `honest = Claimer`.
  - `withdrawChallengeDeposit(epoch, claim)`: pays challenger `depositPlusReward = 1.5 × deposit`, burns half the claimer deposit.
  - `hashClaim` = `keccak256(abi.encodePacked(stateRoot, claimer, uint32 timestampClaimed, uint32 timestampVerification, uint32 blocknumberVerification, uint8 honest, address challenger))`.
- The Claim struct is never stored, only its hash. A challenger must **reconstruct the
  struct from events + block headers** and keep it current across `startVerification` /
  `challenge` transitions, or the challenge tx reverts with "Invalid claim.".
- **Challenge window** (non-devnet): from claim until `verifySnapshot` succeeds, i.e. at least
  `epochPeriod + sequencerDelayLimit + minChallengePeriod` after `timestampClaimed`
  (testnet ArbToEth: 2h + 24h + 3h ≥ 29h). Devnet: operator can verify immediately after
  claiming, so the window is effectively unbounded only if the operator idles — treat devnet
  challenges as best-effort.
- **Resolution flow (ArbToEth)**: challenge → `sendSnapshot(epoch, claim)` on Arbitrum →
  ArbSys `L2ToL1Tx` → wait for the assertion to confirm on L1 → `Outbox.executeTransaction`
  with a proof from `NodeInterface.constructOutboxProof` → outbox `resolveDisputedClaim`
  runs → `Verified` → `withdrawChallengeDeposit`.
  - `sendSnapshot` does **not** validate the claim struct; it must be the exact
    **post-challenge** struct (challenger set, honest=None) or L1 resolution emits
    `FailedResolution` and the multi-day round trip is wasted. `sendSnapshot` is
    permissionless and repeatable → the bot watches `FailedResolution` and re-sends.
    `FailedResolution(epoch)` names only the epoch, so anyone's stale message can emit it:
    the bot resets to `CHALLENGED` only when its own pending message is not provably current
    (no/undecodable `l2tol1_json`, or its struct's hash ≠ `claimHashes(E)` read at the event's
    block, or at `latest` out of window); otherwise it keeps its round trip and WARNs.
  - A third party's `SnapshotSent` ticket is adopted only from the receipt's `L2ToL1Tx`
    whose `caller` is the inbox and `destination` the route's L1 target (outbox, or router
    for ArbToGnosis), never the first ArbSys log: a wrapper contract can emit its own
    message carrying our struct before calling `sendSnapshot` with a wrong one. The
    message must also be for the row's epoch (a wrapper can send our struct for another epoch).
- **Resolution flow (ArbToGnosis)**: `sendSnapshot(epoch, gasLimit, claim)` (extra AMB
  gas-limit arg, clamped to `amb.maxGasPerTx()`); the L2→L1 message targets
  `RouterArbToGnosis.route(...)` on Ethereum, which forwards through the AMB to the Gnosis
  outbox (AMB oracles relay; the bot monitors delivery and alerts if it stalls).
- If the bridge shuts down (`timeoutEpochs` without progress) before resolution lands,
  `resolveDisputedClaim` reverts (`OnlyBridgeRunning`); the deposit is recovered via
  `withdrawChallengerEscapeHatch` (no reward).

## Decisions (made autonomously)

1. **Scope**: full challenger lifecycle — detect, challenge, resolve, withdraw. Oracle
   (claiming) and relaying are out of scope.
2. **Routes**: route-config-driven. Ships with built-in configs for
   `arb-sepolia→sepolia` (testnet + devnet) and `arb-sepolia→chiado` (testnet + devnet).
   Mainnet routes addable via TOML without code changes. Two deposit models:
   `native` (ETH) and `weth` (approve/transferFrom).
3. **Stack**: Python ≥3.12, `uv` project. `web3` v7 (only hard dependency),
   `pydantic`/`pydantic-settings` for config, `typer`-free — plain `argparse` (fewer deps),
   stdlib `sqlite3` for state, stdlib `logging` with JSON option. Tests: `pytest`.
4. **Independence from RPC trust**: every verdict read uses the Arbitrum `finalized` block
   tag; optional N-of-M cross-check across multiple RPC URLs per chain. The verdict value
   (`inbox.snapshots(epoch)`) is exactly the value `resolveDisputedClaim` will receive, so
   agreement between finalized reads on independent RPCs is the strongest check available
   without running a node.
5. **Verdict rule** for claim on epoch E with root C (`epochEnd = (E+1) × epochPeriod`):
   - **Primary**: wait until the **finalized** L2 block timestamp ≥ `epochEnd` (snapshot then
     immutable — finalized history cannot be backdated into). Read `T = inbox.snapshots(E)`
     at `finalized` on **all** configured L2 RPCs; they must agree. `T != C` (incl. `T == 0`)
     → **challenge**. `T == C` → HONEST (terminal; requires the full N-of-N agreement since
     it is irreversible).
   - **Fallback** (finality stalled): decide from the `latest` tag **only when** the latest
     L2 timestamp ≥ `epochEnd + outbox.sequencerDelayLimit()` — before that, a malicious
     sequencer can still backdate a `saveSnapshot` into epoch E and N-of-M RPC agreement is
     worthless (all RPCs mirror one sequencer feed). This still leaves ≥ `minChallengePeriod`
     of challenge window, because `startVerification` waits for the same delay.
   - On RPC disagreement or undecidable-by-deadline: CRITICAL alert. Auto-challenge in that
     situation is **opt-in** (`challenge_on_ambiguity`, default off): a wrong challenge loses
     the **entire** deposit (0.5·d burned + 0.5·d awarded to the claimer), risk/reward 2:1
     against, so it is a human decision by default.
   - Deadlines use `outbox.sequencerDelayLimit()` read each tick (that value gates
     `startVerification`, not the live sequencer-inbox value).
6. **Claim reconstruction**: maintain claim state machine per epoch from logs
   (`Claimed`, `VerificationStarted` [timestamp/blocknumber from the log's block header],
   `Challenged`) — the struct is never stored on-chain, only its hash. Before any tx,
   recompute `hashClaim` locally and require it to equal `claimHashes(epoch)` on-chain.
   Two contract quirks require **hash probing** (try candidate structs until one matches
   `claimHashes(epoch)`):
   - `Verified` does not say who won: probe `honest ∈ {Claimer, Challenger}`. Never assume
     victory; `withdrawChallengeDeposit` only after the Challenger-variant hash matches.
   - Escape-hatch functions (bridge shutdown) zero `claimer`/`challenger` **without events**:
     on any unexplained `claimHashes` change, probe the bounded mutation set
     ({claimer, 0} × {challenger, 0} × {honest values}) and alert.
   `hashClaim` parity: `abi.encodePacked(bytes32, address, uint32, uint32, uint32, uint8, address)`
   — 85 bytes, uint32 truncation, enum as one byte. Verified at startup against a live
   `claimHashes` read whenever a claim exists (golden-vector unit tests too).
7. **Concurrency/liquidity**: capital-bounded, not constant-bounded — a challenge locks a
   full deposit for the entire resolution round-trip (days). Challenge while
   `balance - gas_reserve ≥ deposit`; when a fraudulent claim must be skipped for lack of
   funds that is a CRITICAL page (an unchallenged fraud verifies and the bridge relays a
   false root), not an info log.
8. **Reorg safety**: event scanning lags the head by `confirmations` blocks (default 3
   Ethereum, 12 Gnosis); a challenge counts as durable only after confirmations **and**
   `claimHashes(epoch)` matching the challenged struct; cursor + dedupe in SQLite; all
   writes idempotent, safe to restart at any point. Tx intent is journaled **before**
   broadcast (nonce, params) so a crash mid-send is recoverable from the journal + mempool
   + `SnapshotSent`/`Challenged` event scans.
9. **Gas policy**: EIP-1559; the challenge tx escalates fees as the hard deadline
   (earliest possible `verifySnapshot`) approaches and is replaceable by nonce (the lowest
   unmined nonce of any earlier attempt for the epoch, including one whose broadcast failed;
   both fee caps at least 10% + 1 wei over the highest broadcast attempt journaled at that
   nonce, as nodes require; a failed broadcast counts up to one bump over that attempt or the current
   market quote, whichever is higher, so an RPC outage cannot compound fees every tick); resolution txs use normal fees. Always send **exactly** `deposit` (the
   overpayment-refund path uses `.send()` with a 2300 gas stipend — worthless to contracts). The bot requires its
   addresses to be EOAs for the same reason.
10. **Two tx lanes**: the deadline-critical challenge lane and the slow resolve/withdraw
    lane use separate keys (`VEA_CHALLENGE_PRIVATE_KEY`, `VEA_OPS_PRIVATE_KEY`; if only one
    is set it is used for both, with a warning) so a stuck resolution tx can never
    head-of-line-block a challenge on the shared nonce sequence.
11. **Ops**: single long-running process per route (`run` command), plus one-shot
    subcommands (`status`, `scan`, `challenge`, `resolve`, `withdraw`) for manual control;
    optional generic webhook notifications (Slack/Discord-compatible JSON) on every
    important event; `--dry-run` mode that detects and alerts but never spends. Startup
    self-checks: `finalized` tag genuinely supported (finalized < latest and advancing),
    hash parity, route pairing (the inbox's `veaOutboxArbToEth`/`routerArbToGnosis` is the
    configured outbox/router, the outbox's `veaInboxArbToEth`/`routerArbToGnosis` is the
    configured inbox/router, ArbToGnosis: the router's `veaInboxArbToGnosis`/
    `veaOutboxArbToGnosis` are the configured pair, read on L1; inbox and outbox
    `epochPeriod` equal; L1 RPC chain id matches `l1_chain`; the manual `challenge`/`resolve`/
    `withdraw` commands run the chain-id and pairing checks too), key balances, WETH allowance
    (Gnosis routes: one-time max approve, sent by `run` only, never by the read-only `scan`;
    balance monitored separately from gas).

## Architecture

```
src/vea_challenger/
  cli.py         argparse CLI: run | status | scan | challenge | resolve | withdraw
  config.py      RouteConfig / Settings (TOML + env), builtin route registry
  abi.py         hand-written minimal ABIs (inbox, outbox, WETH, ArbSys, Outbox, NodeInterface, Rollup)
  chain.py       ChainClient: multi-RPC Web3 pool, finalized/latest reads, tx send+wait, fee logic
  claims.py      Claim dataclass, hash_claim() (parity w/ Solidity), event→state reconstruction
  detector.py    scans Claimed logs, tracks claim lifecycle, produces verdicts
  challenger.py  submits challenge txs (native + WETH deposit models), pre-flight checks
  resolver.py    sendSnapshot on L2, L2→L1 message execution on L1, withdraw
  arbitrum.py    NodeInterface.constructOutboxProof, L2ToL1Tx event parsing, Outbox.executeTransaction
  store.py       SQLite: claims table (state machine), tx journal, scan cursors
  watcher.py     orchestration loop: scan → verdict → act → resolve → withdraw
  notify.py      webhook notifier (fire-and-forget, never blocks the loop)
```

Loop cadence: one tick every `poll_interval` (default 30s): advance cursors, update claim
states, evaluate verdicts, fire due actions. Every action re-validates on-chain state first.

### Claim state machine (SQLite `claims.status`)

```
SEEN → HONEST                       (our evaluate() ruled the root matches on a complete leg; terminal)
SEEN → UNDECIDED                    (waiting for L2 finality / quorum; reason in row.note)
SEEN/UNDECIDED → CHALLENGE_PENDING  (mismatch with >= min_challenge_agreement agreeing reads; tx being sent)
SEEN/UNDECIDED → VERIFIED_UNDECIDED (verified honest == Claimer before we decided; terminal, CRITICAL)
SEEN/UNDECIDED → VERIFIED_UNDECIDED (withdrawn before processing: claim hash already deleted at Verified; CRITICAL)
SEEN/UNDECIDED (fraud: note) → MISSED (verified, or verified and withdrawn, before our challenge landed; CRITICAL)
CHALLENGE_PENDING → CHALLENGED      (our tx's Challenged event)
CHALLENGE_PENDING → CHALLENGED_BY_OTHER (someone else's Challenged event; still reconciled every tick)
CHALLENGE_PENDING → MISSED          (verified honest == Claimer with a challenger that is not ours, or hash deleted:
                                     our challenge never landed; CRITICAL "fraud verified before our challenge landed")
CHALLENGED/SNAPSHOT_SENT/L1_EXECUTED → CHALLENGE_PENDING (our challenge reorged out: confirmed-height hash back to
                                     challenger == 0, honest == None, no successful receipt for challenge_tx; CRITICAL;
                                     SNAPSHOT_SENT/L1_EXECUTED also clear snapshot_tx, l2tol1_json, execute_tx)
CHALLENGED/CHALLENGED_BY_OTHER/SNAPSHOT_SENT/L1_EXECUTED → WITHDRAWN (escape hatch: the bridge is shut down and
                                     withdrawChallengerEscapeHatch zeroed `challenger`; deposit refunded, WARNING)
CHALLENGED_BY_OTHER → UNDECIDED     (their challenge reorged out; re-evaluated, WARNING)
CHALLENGED_BY_OTHER → MISSED        (verified honest == Challenger, or claim hash deleted: withdrawn)
CHALLENGED_BY_OTHER → HONEST        (verified honest == Claimer and our evaluate() had stored true_root == claimed root)
CHALLENGED_BY_OTHER → VERIFIED_UNDECIDED (verified honest == Claimer otherwise; CRITICAL)
CHALLENGED → SNAPSHOT_SENT          (sendSnapshot confirmed on L2)
SNAPSHOT_SENT → L1_EXECUTED         (outbox executeTransaction confirmed; ArbToGnosis: router routed)
L1_EXECUTED → RESOLVED              (Verified event, honest == Challenger)
RESOLVED → WITHDRAWN                (withdrawChallengeDeposit confirmed; terminal)
CHALLENGED/SNAPSHOT_SENT/L1_EXECUTED → WITHDRAWN (verified and withdrawn before processing; WARNING, check balances)
any → MISSED / LOST / DESYNC        (verified before we acted / our own challenge lost / hash unreconstructable)
```

`HONEST` is reserved for rows `evaluate()` ruled honest, and only from a leg that every configured
provider answered. A `SEEN`/`UNDECIDED` row that the claimer gets verified without our verdict is
`VERIFIED_UNDECIDED` (terminal) and always pages CRITICAL: it means a claim we could not evaluate was
accepted. A row whose note starts `fraud:` (we judged it fraudulent but no challenge landed) is
`MISSED` instead, with CRITICAL "fraud verified before our challenge landed"; `LOST` is only for a
matched challenger that is ours. `CHALLENGED_BY_OTHER` stays in the active set and is reconciled each
tick (nothing else acts on it) until `Verified` or the claim hash is deleted.

### Challenge safety rules added in challenger-v1-fixes

- **Deadline alerts and override (1.1).** For each `SEEN`/`UNDECIDED`/`CHALLENGE_PENDING` row on a non-devnet route the
  tick computes `deadline = earliest_verification_ts(...)` (`timestampClaimed + epochPeriod +
  sequencerDelayLimit + minChallengePeriod`) from the outbox chain clock (`outbox.now()`). It sends
  WARNING at `deadline - 4h` and CRITICAL at `deadline - 1h` (alert keys `deadline:<E>:4h` / `:1h`,
  stored in SQLite so a restart does not repeat them), naming the epoch, the undecided reason (the
  `undecided: <reason>` note `evaluate` writes) and the seconds left. A row whose note starts
  `fraud:` (the bot judged it fraudulent but the challenge has not landed, e.g. watch-only, dry-run
  or unfunded) is worded "FRAUD for epoch E not challenged yet: <note>; <s> s left"; a later WAIT
  keeps the `fraud:` prefix and appends the current reason. A `CHALLENGE_PENDING` row (a detected
  fraud whose challenge send is failing or stuck) is worded "FRAUD for epoch E not challenged yet
  (challenge pending): <note>; <s> s left". With `challenge_on_ambiguity`
  set, a row still undecided (`SEEN`/`UNDECIDED` only) at `deadline - 15 min` is challenged when any provider's read at an
  immutable point (finalized past `(E+1)·P`, or latest past `(E+1)·P + sequencerDelayLimit`) differs
  from the claimed root; with no such read, or all matching, nothing is challenged and CRITICAL is
  sent. The override CHALLENGE page names the deciding immutable leg and lists only reads of
  immutable legs; it is sent at most once per epoch per hour (`override-challenge:<E>`). With the
  flag off (default) the bot only pages. Devnet routes never get deadline alerts or
  the override (their deadline is `timestampClaimed`; challenges there are best-effort).
- **HONEST needs a complete leg (f9) and the WAIT reasons.** `decide_detail()` returns HONEST from a
  leg only when every configured provider answered that leg. An incomplete matching leg does not
  decide: evaluation goes on to the next leg and then to the override. With no decision the reason
  is the first that applies: `quorum split on <leg>: <label>=<root>, ...`, then `insufficient
  agreement for epoch E: <n> provider(s) (<labels>) agree on a mismatch, fewer than <min>`, then
  `incomplete: <answered> of <total> providers answered`, then "no immutable read past the epoch end
  yet" (wrapped in `override declined: ...` by a declined override). The `incomplete:` reason sends
  the WARNING "looks honest but not all RPCs answered; withholding the terminal verdict" once per
  key (`incomplete:<E>`).
- **`min_challenge_agreement` (1.2).** `CHALLENGE` needs at least this many inbox RPCs agreeing on
  the root (default 2); fewer gives `WAIT` plus a WARNING "insufficient agreement for epoch E: <n>
  provider(s) (<labels>) agree on a mismatch, fewer than <min>" (alert key `single-source:<E>`). Only the 1.1 override may challenge on fewer answers. Startup refuses a value
  below 1 or above the number of configured inbox RPCs, and still refuses fewer than 2 inbox RPCs.
- **Pinned quorum block (1.3).** The tag (`finalized`/`latest`) is resolved on every provider; the
  lowest block number among those that answered is used, `snapshots(E)` is read at that block on
  every provider, and that block's timestamp feeds the `(E+1)·P` checks. A provider that cannot
  serve the block counts as not answering. Providers are therefore answering the same question.
- **`latest` depth (1.4).** The `latest` leg reads at `latest - inbox_chain.confirmations`. The
  built-in inbox configs use 3 confirmations, which on Arbitrum's ~250 ms blocks is under one
  second of depth: the real protection of the `latest` leg is the `epoch_end + sequencerDelayLimit`
  rule, not the depth.
- **Confirmed-height claim reads.** `reconcile` reads `claimHashes(E)` at the block the event scan
  has reached (the `outbox_events` cursor; `confirmed_head()` before the first scan) and
  `_apply_verified` reads it at the `Verified` event's block, so the event handlers and reconcile see
  one chain state: an event not scanned yet (including during an event-scan outage) cannot turn a
  row into `DESYNC`, and a provider that cannot serve the block fails over instead of answering
  stale. A pinned read is used only while its block is within 64 blocks of `confirmed_head()` (state a
  non-archive node holds); otherwise, on a first-run replay, a restart after downtime or an event-scan
  outage, the read is at `latest` as before. Out of window, `reconcile` takes no `DESYNC` and no
  revert transition (the row is returned unchanged, logged once per epoch per hour, and `evaluate`
  still runs); `_apply_verified` reads at `latest` and applies the deleted-hash mapping, and never
  raises into `sync_events` (a failed `latest` read applies nothing). A pinned read that fails on every provider counts as out of window. A `Verified`
  the scan consumed without applying is applied later by `reconcile`, from the hash it read at the
  scan block (no second read, never `latest`), once that hash shows a verified struct. When a
  `sync_events` stopped partway through a block (flag `scan-partial`), `reconcile` takes no
  transition at all until a later scan completes, or fails at a later block (the flagged block is then
  complete).
- **Deleted claim hash at `Verified` (G1/G2).** The mapping depends on the row's status:
  `SEEN`/`UNDECIDED` → `VERIFIED_UNDECIDED` (CRITICAL, "withdrawn before processing");
  `CHALLENGED_BY_OTHER` → `MISSED`; `HONEST` → `WITHDRAWN`; `CHALLENGE_PENDING` or a
  `SEEN`/`UNDECIDED` row with a `fraud:` note → `MISSED` (CRITICAL "fraud verified before our
  challenge landed"); `CHALLENGED`/`SNAPSHOT_SENT`/`L1_EXECUTED` → `WITHDRAWN` with a WARNING to
  check balances. It is the fallback for a verify and withdraw in one block.
- **Reorg recovery (2.1).** A revert is when the confirmed-height hash matches the stored struct's
  variant with `challenger == 0` and `honest == None`, for a row in `CHALLENGED`, `SNAPSHOT_SENT`,
  `L1_EXECUTED` or `CHALLENGED_BY_OTHER`; it is checked every tick. First, for our own states, a
  successful receipt for our `challenge_tx` mined above the block the scan has reached means "not
  scanned yet": no transition. This comes before the shutdown branch, because the outbox accepts a
  challenge during a shutdown too. Then the bridge-shutdown branch: after a shutdown the escape hatch
  zeroed `challenger` (deposit refunded), so the zeroed struct is written and the row goes to
  `WITHDRAWN` with a WARNING (no re-challenge). Otherwise, for our own states the transition also
  needs our `challenge_tx`, when known, to have no successful receipt (none found, or status 0).
  Until the transition is taken `row.claim` is not overwritten; the matched struct and
  the new status are written together, so an exception changes nothing and the next tick retries.
  Our `CHALLENGED`, `SNAPSHOT_SENT` and `L1_EXECUTED` rows go back to `CHALLENGE_PENDING` (for the
  latter two `snapshot_tx`, `l2tol1_json` and `execute_tx` are cleared; CRITICAL) and the same tick
  re-challenges. A revert held by the receipt gate for at least 10 minutes (first seen under alert key
  `reorg-suspect:<E>`, cleared when the hash matches the stored struct again) sends CRITICAL naming
  the gate, at most once per hour (`reorg-stuck:<E>`).
- **`CHALLENGED_BY_OTHER` reconciled (2.2).** If their challenge is reverted (same signature, no
  receipt gate) the
  row returns to `UNDECIDED` with a WARNING and is evaluated again. If verified: `honest ==
  Challenger` → `MISSED`; `honest == Claimer` → `HONEST` only when our own `evaluate()` had stored a
  `true_root` equal to the claimed root, otherwise `VERIFIED_UNDECIDED` with CRITICAL. A deleted
  claim hash → `MISSED`.
- **Event-scan guard (G5).** `tick()` wraps `sync_events()`: an exception is logged and sends CRITICAL
  "event scan failing: <redacted error>" at most once per hour (`sync-failed`), and the tick still
  processes the tracked rows, the deadline, shutdown and liveness checks and the resolver.
- **Hourly fraud pages (C2).** "FRAUDULENT CLAIM epoch E ..." (`fraud:<E>`) and "watch-only mode:
  CANNOT challenge" (`watch-only:<E>`) are sent at most once per epoch per hour, as are the dry-run
  and insufficient-funds pages of the challenger (`dry-run:<E>`, `unfunded:<E>`) and its
  failed-send page "CHALLENGE FAILED for fraudulent claim epoch E ..." (`challenge-failed:<E>`).
- **Derived lookback (2.4).** On the first run the outbox scan starts `epochPeriod +
  sequencerDelayLimit + minChallengePeriod + epochPeriod` plus 2 h behind the head (read from the
  contract, converted to blocks from the observed block time). `genesis_lookback_blocks` can only
  widen it. This covers claims on the normal verification schedule only: a claim whose
  `startVerification`/`verifySnapshot` is delayed stays challengeable beyond any fixed window, so a
  cursor reset can miss it.
- **Per-row isolation (2.3).** Each row's reconcile/evaluate/challenge runs in its own `try`; an
  exception is logged and sends CRITICAL at most once per epoch per hour (`row-error:<E>`).
  Later rows are still processed in the same tick.

### Operations

- **Endpoint labels and redaction (3.1).** Each RPC endpoint has a label `<chain>#<index> (<host>)`
  (or `label=https://...` in the configured list for operator labels, hiding the host). Logs and
  alerts name the label, never the URL: `cli` installs log redaction right after logging setup and
  `Notifier.send` redacts every message before logging or posting. Per-provider `failures`,
  `quorum_disagreements` and `last_error_ts` (process lifetime) are written by `run` each tick to
  `<db path>.providers.json` (atomic replace, with a timestamp) and printed by `status` with their
  age, or "no provider stats yet (is run active?)". The pin-spread warning (a provider far behind the
  others) is a log line once per provider per hour and is not counted as a failure. `status` prints
  notes through the same redaction; a challenge-failure note is redacted when it is stored.
- **SIGTERM (3.2).** For `run` only (the one-shot commands keep the default SIGTERM action), `main`
  installs a SIGTERM handler that sets a stop event; the loop finishes or
  abandons its wait, checks the event only between ticks and between rows (never between journaling
  and broadcast of a tx), sends INFO "watcher stopping (SIGTERM)", closes the store and exits 0.
  Docker's PID-1 SIGTERM delivery is not verified by this repository's tests (subprocess test only).
- **Liveness and shutdown alarms (3.3), every mode (watch-only too).** The bridge shuts down when
  `now_epoch - latestVerifiedEpoch > timeoutEpochs`. Each tick: WARNING at 50 %, CRITICAL at 75 %
  and 90 % of `timeoutEpochs` since the last verified epoch, once per `latestVerifiedEpoch` value
  (keys `shutdown:<latestVerifiedEpoch>:<pct>`, cleared when it advances), saying how many epochs and
  how much time are left and that a claim must be made and verified before then. The bot does not
  claim, so this only ensures a shutdown is never a surprise. Separately, with `liveness_epochs`
  set (default 12; never on devnet), WARNING "no claim for N epochs — quiet bridge, stale address or
  wrong route" at most once a day (`liveness:no-claim`); the last claim time is the newest tracked
  `timestamp_claimed`, or the first tick's time (`liveness:start`). `status` prints both values.

### Error handling

- RPC failures: rotate through the pool with backoff; the loop never dies on transient errors.
- Tx failures: journal every attempt (nonce, hash, gas); recover in-flight txs on restart by
  checking receipt before re-sending; never double-challenge (re-check `claimHashes` +
  reconstructed `challenger == 0` immediately before send).
- Clock skew: all deadlines computed from chain timestamps, never local time.

### Testing

- Unit: `hash_claim` golden vectors (recomputed keccak of `encodePacked`), claim
  reconstruction from synthetic logs, verdict logic (match/mismatch/zero-snapshot/finality-lag),
  store idempotency, deadline math.
- Integration (opt-in, `-m live`): read-only against public Sepolia/ArbSepolia RPCs —
  resolves current epoch, reads `claimHashes`, verifies ABI correctness.
- No fork-based e2e in v1 (needs funded keys and hours of wall-clock; manual runbook instead).

## Config surface (env + TOML)

- `VEA_PRIVATE_KEY` (env only), `VEA_ROUTE` (builtin name or path to TOML),
  per-chain `rpc_urls` lists, `poll_interval`, `confirmations`, `max_concurrent_challenges`,
  `safety_margin_hours`, `challenge_on_disagreement`, `dry_run`, `webhook_url`,
  `db_path`.

## Known limitations (documented, accepted for v1)

- Trusts RPC N-of-M consensus rather than running a light client/full node.
- Devnet routes: operator can insta-verify, so devnet challenges are best-effort.
- Does not perform the oracle (honest-claim) role; a fully idle bridge stays idle.
- AMB relay on ArbToGnosis assumed live (oracle-operated); bot only monitors it.
