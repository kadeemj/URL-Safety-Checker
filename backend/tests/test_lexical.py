from app.checks.base import CheckStatus
from app.checks.lexical import (
    check_keyword_bait,
    check_punycode_homoglyph,
    check_suspicious_tld,
    check_typosquatting,
    check_url_shortener,
    levenshtein,
)
from app.validation import validate_url_syntax


def v(url: str):
    return validate_url_syntax(url)


class TestLevenshtein:
    def test_identical(self) -> None:
        assert levenshtein("paypal", "paypal") == 0

    def test_single_substitution(self) -> None:
        assert levenshtein("paypa1", "paypal") == 1

    def test_insert_and_substitute(self) -> None:
        assert levenshtein("arnazon", "amazon") == 2

    def test_empty_string(self) -> None:
        assert levenshtein("", "abc") == 3


class TestPunycodeHomoglyph:
    def test_cyrillic_lookalike_of_brand_triggers_max(self) -> None:
        # 'paypаl' with U+0430 CYRILLIC SMALL LETTER A
        host = "xn--" + "paypаl".encode("punycode").decode("ascii")
        result = check_punycode_homoglyph(v(f"https://{host}.com/"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 25
        assert "paypal" in (result.evidence or "").lower()

    def test_unicode_host_lookalike_triggers(self) -> None:
        result = check_punycode_homoglyph(v("https://gооgle.com/"))  # Cyrillic о
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 25

    def test_punycode_without_brand_match_passes(self) -> None:
        host = "xn--" + "übung".encode("punycode").decode("ascii")
        result = check_punycode_homoglyph(v(f"https://{host}.de/"))
        assert result.status == CheckStatus.PASSED
        assert result.points == 0

    def test_plain_ascii_passes(self) -> None:
        assert check_punycode_homoglyph(v("https://example.com/")).status == CheckStatus.PASSED

    def test_cyrillic_brand_in_subdomain_triggers_20(self) -> None:
        result = check_punycode_homoglyph(v("https://pаypаl.com.evil.tk/"))  # Cyrillic а
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 20
        assert "paypal" in (result.evidence or "").lower()


class TestTyposquatting:
    def test_one_edit_from_brand_triggers_25(self) -> None:
        result = check_typosquatting(v("http://paypa1.com/login"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 25

    def test_two_edits_from_brand_triggers_15(self) -> None:
        result = check_typosquatting(v("https://arnazon.com/"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 15

    def test_brand_in_subdomain_triggers_20(self) -> None:
        result = check_typosquatting(v("http://paypal.com.evil.tk/"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 20

    def test_brand_substring_in_subdomain_does_not_trigger(self) -> None:
        # 'notpaypal.com' contains 'paypal.com' as a substring, but not on a
        # label boundary; substring matching was a false-positive source.
        result = check_typosquatting(v("http://notpaypal.com.evil.tk/"))
        assert result.status == CheckStatus.PASSED

    def test_exact_brand_passes(self) -> None:
        result = check_typosquatting(v("https://www.paypal.com/"))
        assert result.status == CheckStatus.PASSED
        assert result.points == 0

    def test_unrelated_domain_passes(self) -> None:
        assert check_typosquatting(v("https://kadeemjeffery.dev/")).status == CheckStatus.PASSED


class TestSuspiciousTld:
    def test_abuse_heavy_tld_triggers(self) -> None:
        result = check_suspicious_tld(v("http://free-prizes.tk/"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 10

    def test_dot_zip_triggers(self) -> None:
        assert check_suspicious_tld(v("https://attachment.zip/")).status == CheckStatus.TRIGGERED

    def test_com_passes(self) -> None:
        assert check_suspicious_tld(v("https://example.com/")).status == CheckStatus.PASSED


class TestUrlShortener:
    def test_shortener_triggers(self) -> None:
        result = check_url_shortener(v("https://bit.ly/3xYzAbC"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 12

    def test_normal_domain_passes(self) -> None:
        assert check_url_shortener(v("https://example.com/")).status == CheckStatus.PASSED


class TestKeywordBait:
    def test_bait_plus_foreign_brand_triggers_12(self) -> None:
        result = check_keyword_bait(v("http://evil-site.com/paypal/login"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 12

    def test_bait_alone_triggers_6(self) -> None:
        result = check_keyword_bait(v("http://random-site.com/secure/login"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 6

    def test_bait_on_the_brands_own_domain_passes(self) -> None:
        result = check_keyword_bait(v("https://www.paypal.com/signin/login"))
        assert result.status == CheckStatus.PASSED

    def test_no_bait_passes(self) -> None:
        assert check_keyword_bait(v("https://example.com/blog/post")).status == CheckStatus.PASSED
