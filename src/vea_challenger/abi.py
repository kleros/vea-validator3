"""Minimal hand-written ABIs for the contracts the challenger touches.

Written from the Solidity sources in the Vea repo (contracts/src) and the
canonical Arbitrum Nitro contracts. Only the fragments the bot uses.
"""

CLAIM_COMPONENTS = [
    {"name": "stateRoot", "type": "bytes32"},
    {"name": "claimer", "type": "address"},
    {"name": "timestampClaimed", "type": "uint32"},
    {"name": "timestampVerification", "type": "uint32"},
    {"name": "blocknumberVerification", "type": "uint32"},
    {"name": "honest", "type": "uint8"},
    {"name": "challenger", "type": "address"},
]

_CLAIM_PARAM = {"name": "_claim", "type": "tuple", "components": CLAIM_COMPONENTS}


def _view(name, inputs, outputs):
    return {
        "type": "function",
        "stateMutability": "view",
        "name": name,
        "inputs": inputs,
        "outputs": outputs,
    }


def _fn(name, inputs, payable=False):
    return {
        "type": "function",
        "stateMutability": "payable" if payable else "nonpayable",
        "name": name,
        "inputs": inputs,
        "outputs": [],
    }


def _arg(name, type_):
    return {"name": name, "type": type_}


# Shared by VeaOutboxArbToEth and VeaOutboxArbToGnosis (superset; WETH bits are
# Gnosis-only, the payable challenge is Eth-only — callers pick per route).
OUTBOX_ABI = [
    _view("claimHashes", [_arg("epoch", "uint256")], [_arg("", "bytes32")]),
    _view("deposit", [], [_arg("", "uint256")]),
    _view("burn", [], [_arg("", "uint256")]),
    _view("depositPlusReward", [], [_arg("", "uint256")]),
    _view("epochPeriod", [], [_arg("", "uint256")]),
    _view("minChallengePeriod", [], [_arg("", "uint256")]),
    _view("sequencerDelayLimit", [], [_arg("", "uint256")]),
    _view("timeoutEpochs", [], [_arg("", "uint256")]),
    _view("latestVerifiedEpoch", [], [_arg("", "uint256")]),
    _view("stateRoot", [], [_arg("", "bytes32")]),
    _view("epochNow", [], [_arg("epoch", "uint256")]),
    # Pairing getters (startup check): ArbToEth names the inbox, ArbToGnosis the router.
    _view("veaInboxArbToEth", [], [_arg("", "address")]),
    _view("routerArbToGnosis", [], [_arg("", "address")]),
    _view(
        "hashClaim",
        [_CLAIM_PARAM],
        [_arg("hashedClaim", "bytes32")],
    ),
    _fn("challenge", [_arg("_epoch", "uint256"), _CLAIM_PARAM], payable=True),
    _fn("startVerification", [_arg("_epoch", "uint256"), _CLAIM_PARAM]),
    _fn("verifySnapshot", [_arg("_epoch", "uint256"), _CLAIM_PARAM]),
    _fn("withdrawChallengeDeposit", [_arg("_epoch", "uint256"), _CLAIM_PARAM]),
    _fn("withdrawChallengerEscapeHatch", [_arg("_epoch", "uint256"), _CLAIM_PARAM]),
    {
        "type": "event",
        "name": "Claimed",
        "inputs": [
            {"name": "_claimer", "type": "address", "indexed": True},
            {"name": "_epoch", "type": "uint256", "indexed": True},
            {"name": "_stateRoot", "type": "bytes32", "indexed": False},
        ],
        "anonymous": False,
    },
    {
        "type": "event",
        "name": "Challenged",
        "inputs": [
            {"name": "_epoch", "type": "uint256", "indexed": True},
            {"name": "_challenger", "type": "address", "indexed": True},
        ],
        "anonymous": False,
    },
    {
        "type": "event",
        "name": "VerificationStarted",
        "inputs": [{"name": "_epoch", "type": "uint256", "indexed": True}],
        "anonymous": False,
    },
    {
        "type": "event",
        "name": "Verified",
        "inputs": [{"name": "_epoch", "type": "uint256", "indexed": False}],
        "anonymous": False,
    },
    {
        "type": "event",
        "name": "FailedResolution",
        "inputs": [{"name": "_epoch", "type": "uint256", "indexed": False}],
        "anonymous": False,
    },
]

INBOX_ABI = [
    _view("snapshots", [_arg("epoch", "uint256")], [_arg("", "bytes32")]),
    _view("epochPeriod", [], [_arg("", "uint256")]),
    _view("count", [], [_arg("", "uint64")]),
    _view("epochNow", [], [_arg("epoch", "uint256")]),
    # Pairing getters (startup check): ArbToEth names the outbox, ArbToGnosis the router.
    _view("veaOutboxArbToEth", [], [_arg("", "address")]),
    _view("routerArbToGnosis", [], [_arg("", "address")]),
    _fn("saveSnapshot", []),
    # ArbToEth signature
    _fn("sendSnapshot", [_arg("_epoch", "uint256"), _CLAIM_PARAM]),
    {
        "type": "event",
        "name": "SnapshotSaved",
        "inputs": [
            {"name": "_snapshot", "type": "bytes32", "indexed": False},
            {"name": "_epoch", "type": "uint256", "indexed": False},
            {"name": "_count", "type": "uint64", "indexed": False},
        ],
        "anonymous": False,
    },
    {
        "type": "event",
        "name": "SnapshotSent",
        "inputs": [
            {"name": "_epochSent", "type": "uint256", "indexed": True},
            {"name": "_ticketId", "type": "bytes32", "indexed": False},
        ],
        "anonymous": False,
    },
]

# ArbToGnosis inbox has an extra AMB gas-limit argument.
INBOX_GNOSIS_SEND_SNAPSHOT_ABI = [
    _fn(
        "sendSnapshot",
        [_arg("_epoch", "uint256"), _arg("_gasLimit", "uint256"), _CLAIM_PARAM],
    ),
]

# RouterArbToGnosis on the L1 chain: only the pairing getters.
ROUTER_ABI = [
    _view("veaInboxArbToGnosis", [], [_arg("", "address")]),
    _view("veaOutboxArbToGnosis", [], [_arg("", "address")]),
]

WETH_ABI = [
    _view("balanceOf", [_arg("owner", "address")], [_arg("", "uint256")]),
    _view(
        "allowance",
        [_arg("owner", "address"), _arg("spender", "address")],
        [_arg("", "uint256")],
    ),
    {
        "type": "function",
        "stateMutability": "nonpayable",
        "name": "approve",
        "inputs": [_arg("spender", "address"), _arg("amount", "uint256")],
        "outputs": [_arg("", "bool")],
    },
]

# Arbitrum canonical contracts ------------------------------------------------

ARBSYS_ADDRESS = "0x0000000000000000000000000000000000000064"
NODE_INTERFACE_ADDRESS = "0x00000000000000000000000000000000000000C8"

ARBSYS_ABI = [
    {
        "type": "event",
        "name": "L2ToL1Tx",
        "inputs": [
            {"name": "caller", "type": "address", "indexed": False},
            {"name": "destination", "type": "address", "indexed": True},
            {"name": "hash", "type": "uint256", "indexed": True},
            {"name": "position", "type": "uint256", "indexed": True},
            {"name": "arbBlockNum", "type": "uint256", "indexed": False},
            {"name": "ethBlockNum", "type": "uint256", "indexed": False},
            {"name": "timestamp", "type": "uint256", "indexed": False},
            {"name": "callvalue", "type": "uint256", "indexed": False},
            {"name": "data", "type": "bytes", "indexed": False},
        ],
        "anonymous": False,
    },
]

NODE_INTERFACE_ABI = [
    _view(
        "constructOutboxProof",
        [_arg("size", "uint64"), _arg("leaf", "uint64")],
        [
            _arg("send", "bytes32"),
            _arg("root", "bytes32"),
            {"name": "proof", "type": "bytes32[]"},
        ],
    ),
]

ARB_BRIDGE_ABI = [
    _view("rollup", [], [_arg("", "address")]),
    _view("sequencerInbox", [], [_arg("", "address")]),
]

ARB_ROLLUP_ABI = [
    _view("outbox", [], [_arg("", "address")]),
]

ARB_OUTBOX_ABI = [
    _view("isSpent", [_arg("index", "uint256")], [_arg("", "bool")]),
    _view("roots", [_arg("root", "bytes32")], [_arg("", "bytes32")]),
    _fn(
        "executeTransaction",
        [
            {"name": "proof", "type": "bytes32[]"},
            _arg("index", "uint256"),
            _arg("l2Sender", "address"),
            _arg("to", "address"),
            _arg("l2Block", "uint256"),
            _arg("l1Block", "uint256"),
            _arg("l2Timestamp", "uint256"),
            _arg("value", "uint256"),
            {"name": "data", "type": "bytes"},
        ],
    ),
    {
        "type": "event",
        "name": "SendRootUpdated",
        "inputs": [
            {"name": "outputRoot", "type": "bytes32", "indexed": True},
            {"name": "l2BlockHash", "type": "bytes32", "indexed": True},
        ],
        "anonymous": False,
    },
]
