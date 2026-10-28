"""Route and runtime configuration.

Routes are data, not code: a route names the inbox chain (Arbitrum), the outbox
chain (Ethereum or Gnosis), the L1 chain where the Arbitrum rollup lives (equal
to the outbox chain for ArbToEth), contract addresses, and the deposit model.
Built-in routes cover the public Sepolia/Chiado deployments; custom routes load
from a TOML file so mainnet needs no code change.

Secrets and overrides come from the environment (``VEA_``-prefixed) or ``.env``.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ChainCfg(BaseModel):
    name: str
    chain_id: int
    rpc_urls: list[str]
    confirmations: int = 3


class RouteCfg(BaseModel):
    name: str
    kind: Literal["arb_to_eth", "arb_to_gnosis"]
    devnet: bool = False
    inbox_chain: ChainCfg
    outbox_chain: ChainCfg
    # Chain hosting the Arbitrum rollup contracts (== outbox_chain for arb_to_eth).
    l1_chain: ChainCfg
    inbox_address: str
    outbox_address: str
    arb_bridge_address: str  # Arbitrum IBridge on the L1 chain
    weth_address: str | None = None  # arb_to_gnosis deposit token
    router_address: str | None = None  # arb_to_gnosis L1 router (L2->L1 destination)
    arb_outbox_address: str | None = None  # optional override; else resolved via rollup
    amb_gas_limit: int = 2_000_000  # arb_to_gnosis sendSnapshot gas limit (router clamps)


_SEPOLIA = ChainCfg(
    name="sepolia",
    chain_id=11155111,
    rpc_urls=[
        "https://ethereum-sepolia-rpc.publicnode.com",
        "https://sepolia.drpc.org",
    ],
    confirmations=3,
)

_ARB_SEPOLIA = ChainCfg(
    name="arbitrum-sepolia",
    chain_id=421614,
    rpc_urls=[
        "https://sepolia-rollup.arbitrum.io/rpc",
        "https://arbitrum-sepolia-rpc.publicnode.com",
    ],
    confirmations=3,
)

_CHIADO = ChainCfg(
    name="chiado",
    chain_id=10200,
    rpc_urls=[
        "https://rpc.chiadochain.net",
        "https://gnosis-chiado-rpc.publicnode.com",
    ],
    confirmations=12,
)

# Addresses from vea/contracts/deployments (dev branch).
_ARB_SEPOLIA_BRIDGE = "0x38f918D0E9F1b721EDaA41302E399fa1B79333a9"

BUILTIN_ROUTES: dict[str, RouteCfg] = {
    "arb-sepolia-to-sepolia-testnet": RouteCfg(
        name="arb-sepolia-to-sepolia-testnet",
        kind="arb_to_eth",
        inbox_chain=_ARB_SEPOLIA,
        outbox_chain=_SEPOLIA,
        l1_chain=_SEPOLIA,
        inbox_address="0xfB77B955B74B4441da5D595dF07236cf513A4B9b",
        outbox_address="0x219aA6d151a1DafAF5a35A9c017Ff0B5a8900014",
        arb_bridge_address=_ARB_SEPOLIA_BRIDGE,
    ),
    "arb-sepolia-to-sepolia-devnet": RouteCfg(
        name="arb-sepolia-to-sepolia-devnet",
        kind="arb_to_eth",
        devnet=True,
        inbox_chain=_ARB_SEPOLIA,
        outbox_chain=_SEPOLIA,
        l1_chain=_SEPOLIA,
        inbox_address="0x45138BC4E364A16919C4571699171d774A7590BD",
        outbox_address="0x60af9Fc1dd7d5bce69a66A8AEf456952b03A39C7",
        arb_bridge_address=_ARB_SEPOLIA_BRIDGE,
    ),
    "arb-sepolia-to-chiado-testnet": RouteCfg(
        name="arb-sepolia-to-chiado-testnet",
        kind="arb_to_gnosis",
        inbox_chain=_ARB_SEPOLIA,
        outbox_chain=_CHIADO,
        l1_chain=_SEPOLIA,
        inbox_address="0x162f826E18380567CE0548395a3Ad2A54EA87B96",
        outbox_address="0x15aC29269b044E1d9042F597513B27Ffa4A7f257",
        arb_bridge_address=_ARB_SEPOLIA_BRIDGE,
        weth_address="0x8d74e5e4DA11629537C4575cB0f33b4F0Dfa42EB",
        router_address="0xd7C54E4cA686a8C51D44534AC6b756676961Fccf",
    ),
    "arb-sepolia-to-chiado-devnet": RouteCfg(
        name="arb-sepolia-to-chiado-devnet",
        kind="arb_to_gnosis",
        devnet=True,
        inbox_chain=_ARB_SEPOLIA,
        outbox_chain=_CHIADO,
        l1_chain=_SEPOLIA,
        inbox_address="0x2E973e20B24088bc74755a7A5cd1A37Dcb53E061",
        outbox_address="0x879A9F4476D4445A1deCf40175a700C4c829824D",
        arb_bridge_address=_ARB_SEPOLIA_BRIDGE,
        weth_address="0x8d74e5e4DA11629537C4575cB0f33b4F0Dfa42EB",
        router_address="0xfA08cfe2530c01045D953f824b836f6757670cD0",
    ),
}


class Settings(BaseSettings):
    """Runtime settings; every field can be set as VEA_<NAME> or in .env."""

    model_config = SettingsConfigDict(
        env_prefix="VEA_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    route: str = "arb-sepolia-to-sepolia-testnet"
    route_file: Path | None = None  # TOML file defining a custom route

    # Deadline-critical lane (challenge txs). Required to challenge.
    challenge_private_key: SecretStr | None = None
    # Slow lane (sendSnapshot / execute / withdraw). Falls back to challenge key.
    ops_private_key: SecretStr | None = None

    # Comma-separated RPC overrides.
    inbox_rpc_urls: str | None = None
    outbox_rpc_urls: str | None = None
    l1_rpc_urls: str | None = None

    db_path: Path | None = None  # default: ./vea-challenger-<route>.db
    poll_interval: float = 30.0
    log_scan_chunk: int = 5_000
    # First-run scan window on the outbox chain, in blocks. None: derived from
    # the challenge budget (PRD 2.4); a value only ever widens that window.
    genesis_lookback_blocks: int | None = None

    dry_run: bool = False
    # Challenge when the verdict is ambiguous at the deadline (RPC disagreement /
    # stalled finality). Losing a challenge costs the entire deposit; default off.
    challenge_on_ambiguity: bool = False
    # CHALLENGE needs at least this many inbox RPCs agreeing on the root; may not
    # exceed the number of configured inbox RPCs (PRD 1.2).
    min_challenge_agreement: int = 2
    # Warn when no Claimed event was seen for this many epochs; None disables.
    # Never applies on devnet routes (PRD 3.3).
    liveness_epochs: int | None = 12
    # Wei kept aside for gas; never spent on deposits.
    gas_reserve_wei: int = 10**16
    webhook_url: str | None = None
    log_json: bool = False

    def resolve_route(self) -> RouteCfg:
        if self.route_file is not None:
            data = tomllib.loads(self.route_file.read_text())
            route = RouteCfg.model_validate(data)
        else:
            try:
                route = BUILTIN_ROUTES[self.route].model_copy(deep=True)
            except KeyError:
                raise SystemExit(
                    f"Unknown route '{self.route}'. Built-ins: "
                    f"{', '.join(sorted(BUILTIN_ROUTES))}, or set VEA_ROUTE_FILE."
                )
        if self.inbox_rpc_urls:
            route.inbox_chain.rpc_urls = _split(self.inbox_rpc_urls)
        if self.outbox_rpc_urls:
            route.outbox_chain.rpc_urls = _split(self.outbox_rpc_urls)
        if self.l1_rpc_urls:
            route.l1_chain.rpc_urls = _split(self.l1_rpc_urls)
        if route.kind == "arb_to_eth":
            # Same chain object so RPC overrides apply consistently.
            route.l1_chain = route.outbox_chain
        return route

    def resolve_db_path(self) -> Path:
        if self.db_path is not None:
            return self.db_path
        return Path(f"vea-challenger-{self.route}.db")


def _split(csv: str) -> list[str]:
    return [u.strip() for u in csv.split(",") if u.strip()]
