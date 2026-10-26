import ast
import pathlib
import sys

import pytest

import pathscan as ps
from lab02.hdwallet import derive_path

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def root():
    return ps.root_from_mnemonic(ps.TEST_MNEMONIC)


def test_metamask_vectors_letter_for_letter(root):
    expected = [
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
        "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A",
    ]
    got = [ps.address_at(root, ps.path_for("MetaMask", i)) for i in range(3)]
    assert got == expected  # exact string compare, so EIP-55 casing must match too


def test_conventions_coincide_at_0_and_differ_after(root):
    rows = ps.convention_table(root, 5)
    # i = 0: both templates collapse to the very same path, hence the same key
    assert rows[0].paths["MetaMask"] == rows[0].paths["Ledger Live"] == "m/44'/60'/0'/0/0"
    assert rows[0].addresses["MetaMask"] == rows[0].addresses["Ledger Live"]
    for r in rows[1:]:
        assert r.paths["MetaMask"] != r.paths["Ledger Live"]
        assert r.addresses["MetaMask"] != r.addresses["Ledger Live"]
    # and no Ledger address for i >= 1 shows up anywhere in the MetaMask list
    mm = {r.addresses["MetaMask"] for r in rows}
    assert all(r.addresses["Ledger Live"] not in mm for r in rows[1:])


def test_passphrase_trailing_space_gives_unrelated_wallet():
    got = dict(ps.passphrase_addresses(ps.TEST_MNEMONIC, ["", "correct horse", "correct horse "]))
    # values cross-checked against an independent implementation (eth-account), not used at runtime
    assert got["correct horse"] == "0xFf0Bdf99513306994d4aF9949BA7cfA60204D285"
    assert got["correct horse "] == "0x67dA015b6A80F19822e5d270A7788F72f018a724"
    assert len(set(got.values())) == 3


def test_mnemonic_whitespace_is_normalised_but_passphrase_is_not():
    messy = "  " + ps.TEST_MNEMONIC.replace(" ", "   ") + "\n"
    a = ps.address_at(ps.root_from_mnemonic(messy), "m/44'/60'/0'/0/0")
    assert a == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"


def test_receive_addresses_match_full_path_derivation(root):
    fast = ps.receive_addresses(root, 26)
    for i in (0, 1, 20, 25):
        assert fast[i] == ps.checksum_address(derive_path(root, f"m/44'/60'/0'/0/{i}"))


def test_gap_limit_scanner_misses_funds_beyond_the_gap(root):
    addrs = ps.receive_addresses(root, 60)
    funded = {addrs[0], addrs[3], addrs[24]}
    scan = ps.gap_limit_scan(lambda i: addrs[i], funded.__contains__, gap_limit=20)
    assert scan.found == (0, 3)
    assert scan.last_checked == 23  # 4..23 = 20 empties -> stop
    assert 24 > scan.last_checked  # the funded address at index 24 is never even looked at
    wider = ps.gap_limit_scan(lambda i: addrs[i], funded.__contains__, gap_limit=21)
    assert wider.found == (0, 3, 24)


def test_gap_limit_scan_on_synthetic_oracle():
    def scan(used):
        return ps.gap_limit_scan(lambda i: str(i), lambda a: int(a) in used, gap_limit=20)

    # 19 empties (20..38) are tolerated, 20 (20..39) are not: off-by-one boundary on both sides
    assert scan({0, 19, 39}) == ps.ScanResult((0, 19, 39), 59)
    assert scan({0, 19, 40}) == ps.ScanResult((0, 19), 39)
    assert ps.gap_limit_scan(lambda i: str(i), lambda a: False, 20).last_checked == 19


def test_cli_all_output(capsys):
    assert ps.main(["all"]) == 0
    out = capsys.readouterr().out
    assert "0x78839F6054d7ed13918bAe0473BA31b1Ca9D7265" in out  # Ledger Live i = 1
    assert "Missed: [24]" in out and "**never looked**" in out


BANNED = {"bip_utils", "eth_keys", "eth_account", "eth_utils", "web3", "hdwallet", "mnemonic",
          "bip32", "bip32utils", "pycoin", "coincurve", "ecdsa"}


def _imports(path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split(".")[0]


def test_no_external_wallet_libraries():
    files = [ROOT_DIR / "pathscan.py", *(ROOT_DIR / "lab02").glob("*.py")]
    for f in files:
        assert not set(_imports(f)) & BANNED, f
    assert not BANNED & set(sys.modules)
