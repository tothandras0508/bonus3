# pathscan: path-mismatch detective

`pathscan.py` takes a BIP-39 mnemonic and optional passphrase and prints the Ethereum addresses that common wallets would show. All derivation is done by Lab 02's `hdwallet.py` (`derive_path`, `derive_child`, `parse_path`/`format_path`) and `address.py`; no wallet libraries are used. **Use test vectors only.** `--mnemonic -` reads the phrase from a hidden prompt, so it never lands in shell history.

```
python pathscan.py all          # all three tables below; also: table | passphrase | gap
python -m pytest tests          # 9 tests
```

Output for `abandon abandon … about` (no passphrase):

| i | MetaMask `m/44'/60'/0'/0/i` | Ledger Live `m/44'/60'/i'/0/0` | |
|---|---|---|---|
| 0 | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` | same |
| 1 | `0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0` | `0x78839F6054d7ed13918bAe0473BA31b1Ca9D7265` | differs |
| 2 | `0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A` | `0x07B5FdfEB4E11826D233403Fe8Db0611CCF4c231` | differs |
| 3 | `0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E` | `0x8559A4270Db933caC30830f2be9D099fD477A51D` | differs |
| 4 | `0x51cA8ff9f1C0a99f88E86B8112eA3237F55374cA` | `0xB9506F020318c2ECA294e0557222511f1e5333CB` | differs |

**Index 0 matches because it is literally the same path.** Setting i = 0 in either template gives `m/44'/60'/0'/0/0`, so the two conventions produce the same key. For i ≥ 1 one convention changes the last (non-hardened) index and the other changes the hardened account index. Those are different nodes of the tree, so the addresses are unrelated. This is why a user who switches wallets sees the first address and then "loses" everything after it.

**Passphrase effect** at `m/44'/60'/0'/0/0`: none → `0x9858…Eda94`, `"correct horse"` → `0xFf0Bdf99513306994d4aF9949BA7cfA60204D285`, `"correct horse "` (trailing space) → `0x67dA015b6A80F19822e5d270A7788F72f018a724`. The passphrase goes into the PBKDF2 salt. Any passphrase is "valid", and a single space opens an entirely different wallet.

**Gap limit**: the simulated balances sit at indices 0, 3 and 24 on `m/44'/60'/0'/0/*`. A scanner with a gap limit of 20 finds 0 and 3. It then sees 4–23 empty (20 in a row) and stops at 23, so it never looks at index 24 (`0xb5D33De8c31B9d2ceFbA9176d00C69769ffBEFf0`). A gap limit of 21, or a direct derivation of index 24, finds the funds.

## Why these "missing funds" are recoverable

The funds were never moved; they sit at an address the wallet simply didn't display. Every key is a deterministic function of **(mnemonic, passphrase, path)**. The blockchain doesn't know about paths or gap limits: those are only the wallet's search strategy for deciding which addresses to show. Recovery is therefore a search over that small space:

- **Path:** try the other convention, e.g. account index vs. address index, or legacy `m/44'/60'/0'/i`.
- **Gap:** derive further indices or raise the scanner's gap limit.
- **Passphrase:** try plausible variants such as a trailing space, capitalisation or the keyboard layout.

The keys can be re-derived offline from the mnemonic as often as needed, then checked against chain balances. Funds are truly lost only if the mnemonic itself, or a passphrase you can't reconstruct, is lost.

*Setup notes:* the Lab 02 package's `curve.py` wasn't available, so `lab02/curve.py` is a drop-in secp256k1 stand-in with the same interface; replace it with the original. `address.py` needs `pycryptodome` for Keccak-256. All addresses above were cross-checked against eth-account, which is used only for that check and is not a dependency.
