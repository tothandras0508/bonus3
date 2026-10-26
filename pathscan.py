#!/usr/bin/env python3
"""pathscan - "path-mismatch detective" for Ethereum HD wallets.

Given a BIP-39 mnemonic (and optional passphrase), print the addresses that the common
wallet path conventions would show, demonstrate the passphrase effect, and show how a
gap-limit scanner misses funds that sit beyond a run of empty addresses.

All derivation is delegated to Lab 02 (`lab02.hdwallet`, `lab02.address`); this file only
chooses paths and reports. Use BIP-39 TEST VECTORS only - never type a real mnemonic.

    python pathscan.py table                       # MetaMask vs Ledger Live, i = 0..4
    python pathscan.py passphrase "correct horse" "correct horse "
    python pathscan.py gap --funded 0,3,24 --gap-limit 20
    python pathscan.py all                         # everything (used for README.md)
    python pathscan.py --mnemonic - table          # read the mnemonic from a hidden prompt
"""
from __future__ import annotations

import argparse
import getpass
import sys
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from lab02.address import public_key_to_address, to_checksum_address
from lab02.hdwallet import (
    ExtendedKey, derive_child, derive_path, format_path, master_key_from_seed,
    mnemonic_to_seed, parse_path,
)

TEST_MNEMONIC = "abandon " * 11 + "about"
TEST_MNEMONIC = TEST_MNEMONIC.strip()

#: path templates; {i} is the varying index
CONVENTIONS: dict[str, str] = {
    "MetaMask": "m/44'/60'/0'/0/{i}",       # vary the address index
    "Ledger Live": "m/44'/60'/{i}'/0/0",    # vary the (hardened) account index
}


# --------------------------------------------------------------------------- derivation helpers


def root_from_mnemonic(mnemonic: str, passphrase: str = "") -> ExtendedKey:
    return master_key_from_seed(mnemonic_to_seed(mnemonic, passphrase))


def checksum_address(node: ExtendedKey) -> str:
    return to_checksum_address(public_key_to_address(node.public_point))


def path_for(convention: str, i: int) -> str:
    """Normalised path string (round-tripped through Lab 02's parse_path/format_path)."""
    return format_path(parse_path(CONVENTIONS[convention].format(i=i)))


def address_at(root: ExtendedKey, path: str) -> str:
    return checksum_address(derive_path(root, path))


@dataclass(frozen=True)
class Row:
    i: int
    paths: dict[str, str]
    addresses: dict[str, str]


def convention_table(root: ExtendedKey, count: int = 5) -> list[Row]:
    rows = []
    for i in range(count):
        paths = {c: path_for(c, i) for c in CONVENTIONS}
        rows.append(Row(i, paths, {c: address_at(root, p) for c, p in paths.items()}))
    return rows


def passphrase_addresses(mnemonic: str, passphrases: Sequence[str],
                         path: str = "m/44'/60'/0'/0/0") -> list[tuple[str, str]]:
    return [(pp, address_at(root_from_mnemonic(mnemonic, pp), path)) for pp in passphrases]


def receive_addresses(root: ExtendedKey, count: int,
                      chain_path: str = "m/44'/60'/0'/0") -> list[str]:
    """Addresses chain_path/0 .. chain_path/count-1 (the hardened prefix is derived once)."""
    parent = derive_path(root, chain_path)
    return [checksum_address(derive_child(parent, i)) for i in range(count)]


# --------------------------------------------------------------------------- gap-limit scanner


@dataclass(frozen=True)
class ScanResult:
    found: tuple[int, ...]  # indices the scanner reported as used
    last_checked: int  # highest index it looked at before giving up


def gap_limit_scan(address_of: Callable[[int], str], is_used: Callable[[str], bool],
                   gap_limit: int = 20) -> ScanResult:
    """BIP-44 style discovery: walk indices upward, stop after `gap_limit` consecutive unused."""
    found, gap, i = [], 0, 0
    while True:
        if is_used(address_of(i)):
            found.append(i)
            gap = 0
        else:
            gap += 1
            if gap == gap_limit:
                return ScanResult(tuple(found), i)
        i += 1


# --------------------------------------------------------------------------- reporting


def md_table(header: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    rows = [[str(c) for c in r] for r in rows]
    widths = [max(len(h), *(len(r[j]) for r in rows)) for j, h in enumerate(header)]
    line = lambda cells: "| " + " | ".join(c.ljust(w) for c, w in zip(cells, widths)) + " |"  # noqa: E731
    return "\n".join([line(header), "|" + "|".join("-" * (w + 2) for w in widths) + "|",
                      *(line(r) for r in rows)])


def report_table(root: ExtendedKey, count: int) -> str:
    rows = convention_table(root, count)
    body = []
    for r in rows:
        same = r.addresses["MetaMask"] == r.addresses["Ledger Live"]
        body.append([r.i, f"`{r.paths['MetaMask']}`", f"`{r.addresses['MetaMask']}`",
                     f"`{r.paths['Ledger Live']}`", f"`{r.addresses['Ledger Live']}`",
                     "same" if same else "differs"])
    return md_table(["i", "MetaMask path", "address", "Ledger Live path", "address", ""], body)


def report_passphrase(mnemonic: str, passphrases: Sequence[str]) -> str:
    rows = passphrase_addresses(mnemonic, ["", *passphrases])
    return md_table(["passphrase", "m/44'/60'/0'/0/0"],
                    [[repr(pp) if pp else "(none)", f"`{a}`"] for pp, a in rows])


def report_gap(root: ExtendedKey, funded: Sequence[int], gap_limit: int) -> str:
    upto = max([*funded, gap_limit]) + 3
    addrs = receive_addresses(root, upto + gap_limit)
    funded_addrs = {addrs[i] for i in funded}
    scan = gap_limit_scan(lambda i: addrs[i], funded_addrs.__contains__, gap_limit)
    missed = [i for i in funded if i not in scan.found]
    show = sorted({0, 1, *funded, scan.last_checked, scan.last_checked + 1,
                   *(i for i in range(len(addrs)) if i in funded)})
    rows, prev = [], -1
    for i in show:
        if i > upto:
            continue
        if i > prev + 1:
            rows.append(["…", "…", "", ""])
        status = "funded" if i in funded else "empty"
        seen = "yes" if i <= scan.last_checked else "**never looked**"
        rows.append([i, f"`{addrs[i]}`", status, seen])
        prev = i
    text = md_table(["index", "m/44'/60'/0'/0/index", "simulated balance", "scanner checked?"], rows)
    text += (f"\n\nGap-limit {gap_limit} scanner found {list(scan.found)}, gave up after index "
             f"{scan.last_checked} ({gap_limit} empty in a row). Missed: {missed}. "
             f"A full scan to index {upto} finds {sorted(funded)}.")
    return text


# --------------------------------------------------------------------------- CLI


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mnemonic", default=TEST_MNEMONIC,
                    help="BIP-39 mnemonic (default: the 'abandon ... about' test vector); "
                         "'-' prompts without echo")
    ap.add_argument("--passphrase", default="", help="BIP-39 passphrase (default: none)")
    sub = ap.add_subparsers(dest="cmd")
    t = sub.add_parser("table", help="MetaMask vs Ledger Live addresses")
    t.add_argument("--count", type=int, default=5)
    p = sub.add_parser("passphrase", help="same mnemonic, different passphrases")
    p.add_argument("passphrases", nargs="*", default=["correct horse", "correct horse "])
    g = sub.add_parser("gap", help="gap-limit scanner demo on simulated balances")
    g.add_argument("--funded", default="0,3,24", help="comma-separated funded indices")
    g.add_argument("--gap-limit", type=int, default=20)
    sub.add_parser("all", help="table + passphrase + gap (README output)")
    args = ap.parse_args(argv)

    mnemonic = getpass.getpass("mnemonic: ") if args.mnemonic == "-" else args.mnemonic
    mnemonic = " ".join(mnemonic.split())
    if mnemonic != TEST_MNEMONIC:
        print("WARNING: not the standard test vector - only ever use test mnemonics here.",
              file=sys.stderr)
    root = root_from_mnemonic(mnemonic, args.passphrase)
    cmd = args.cmd or "table"
    out = []
    if cmd in ("table", "all"):
        out.append(f"### Path conventions (passphrase: {repr(args.passphrase) if args.passphrase else 'none'})\n\n"
                   + report_table(root, getattr(args, "count", 5)))
    if cmd in ("passphrase", "all"):
        pps = getattr(args, "passphrases", ["correct horse", "correct horse "])
        out.append("### Passphrase effect\n\n" + report_passphrase(mnemonic, pps))
    if cmd in ("gap", "all"):
        funded = [int(x) for x in getattr(args, "funded", "0,3,24").split(",") if x.strip()]
        out.append("### Gap limit\n\n" + report_gap(root, funded, getattr(args, "gap_limit", 20)))
    print("\n\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
