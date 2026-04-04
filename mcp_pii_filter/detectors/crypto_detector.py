"""
Cryptocurrency wallet address detectors.
Critical for Zepz/Sendwave which runs on Solana/USDC stablecoin rails.
"""

import re
import hashlib
from typing import List, Tuple
from .base import DetectorBase


class BitcoinDetector(DetectorBase):
    """
    Detects Bitcoin addresses:
    - Legacy (P2PKH): starts with 1, 25-34 chars Base58
    - P2SH: starts with 3, 25-34 chars Base58
    - Bech32 (SegWit): starts with bc1, 39-62 chars
    """
    pii_types = ["CRYPTO_BTC"]

    _legacy = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{24,33}\b')
    _bech32 = re.compile(r'\bbc1[a-z0-9]{6,87}\b', re.IGNORECASE)

    def scan(self, text: str) -> List[Tuple[str, str]]:
        results = []
        seen = set()
        for m in self._legacy.finditer(text):
            addr = m.group()
            if addr not in seen and self._valid_base58_length(addr):
                seen.add(addr)
                results.append((addr, "CRYPTO_BTC"))
        for m in self._bech32.finditer(text):
            addr = m.group()
            if addr not in seen:
                seen.add(addr)
                results.append((addr, "CRYPTO_BTC"))
        return results

    @staticmethod
    def _valid_base58_length(addr: str) -> bool:
        return 25 <= len(addr) <= 34


class EthereumDetector(DetectorBase):
    """
    Detects Ethereum addresses: 0x followed by exactly 40 hex chars.
    Also catches ERC-20 token contract addresses.
    """
    pii_types = ["CRYPTO_ETH"]
    _pattern = re.compile(r'\b0x[0-9a-fA-F]{40}\b')

    def scan(self, text: str) -> List[Tuple[str, str]]:
        return [(m.group(), "CRYPTO_ETH") for m in self._pattern.finditer(text)]


class SolanaDetector(DetectorBase):
    """
    Detects Solana addresses: 32-44 char Base58 strings.
    Solana is the chain underlying Zepz's Sendwave Wallet (USDC).

    Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    Solana addresses are 32 bytes encoded as Base58, resulting in 32-44 characters.
    We use contextual signals to reduce false positives.
    """
    pii_types = ["CRYPTO_SOL"]

    # Strict Base58 pattern for Solana-length addresses
    _pattern = re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b')

    # Context keywords that indicate a Solana address is nearby
    _context = re.compile(
        r'(?:solana|sol|usdc|wallet|address|pubkey|public.?key|'
        r'from_address|to_address|sender_wallet|recipient_wallet)',
        re.IGNORECASE
    )

    def scan(self, text: str) -> List[Tuple[str, str]]:
        results = []
        # Only flag Base58 strings that appear near Solana context keywords
        for m in self._pattern.finditer(text):
            addr = m.group()
            start = max(0, m.start() - 100)
            end = min(len(text), m.end() + 100)
            context_window = text[start:end]
            if self._context.search(context_window):
                results.append((addr, "CRYPTO_SOL"))
        return results
