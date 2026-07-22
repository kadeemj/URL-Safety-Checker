"""Confusable-character map: visually deceptive Unicode -> ASCII skeleton.

A tiny, curated subset of Unicode TR39's confusables: Cyrillic and Greek
letters that render (near-)identically to Latin in common fonts. Combined
with NFKD accent-stripping this turns 'pаypаl' (Cyrillic а) into the
skeleton 'paypal' for brand comparison.
"""

CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
    "і": "i", "ї": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ԛ": "q",
    "ғ": "f", "ѡ": "w", "ь": "b", "г": "r",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "ω": "w", "μ": "u", "σ": "o",
    # Latin lookalikes
    "ı": "i", "ɡ": "g", "ł": "l", "đ": "d", "ħ": "h", "ø": "o",
}
