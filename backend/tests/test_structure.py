import pytest

from app.checks.base import CheckStatus
from app.checks.structure import (
    check_domain_lexical,
    check_excessive_subdomains,
    check_https_scheme,
    check_ip_address_host,
    check_nonstandard_port,
    check_url_length_entropy,
    check_userinfo_trick,
)
from app.validation import validate_url_syntax


def v(url: str):
    return validate_url_syntax(url)


class TestHttpsScheme:
    def test_http_triggers(self) -> None:
        result = check_https_scheme(v("http://example.com/"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 10

    def test_https_passes(self) -> None:
        result = check_https_scheme(v("https://example.com/"))
        assert result.status == CheckStatus.PASSED
        assert result.points == 0


class TestUserinfoTrick:
    def test_embedded_credentials_trigger(self) -> None:
        result = check_userinfo_trick(v("https://paypal.com@evil.example/login"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 25
        assert "paypal.com" in (result.evidence or "")

    def test_plain_url_passes(self) -> None:
        assert check_userinfo_trick(v("https://example.com/")).status == CheckStatus.PASSED


class TestIpAddressHost:
    def test_public_literal_ip_triggers(self) -> None:
        result = check_ip_address_host(v("http://8.8.8.8/download"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 20

    def test_domain_passes(self) -> None:
        assert check_ip_address_host(v("https://example.com/")).status == CheckStatus.PASSED


class TestNonstandardPort:
    def test_unusual_port_triggers(self) -> None:
        result = check_nonstandard_port(v("https://example.com:8443/"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 8

    @pytest.mark.parametrize("url", ["https://example.com:443/", "http://example.com:80/", "https://example.com/"])
    def test_standard_or_absent_port_passes(self, url: str) -> None:
        assert check_nonstandard_port(v(url)).status == CheckStatus.PASSED


class TestExcessiveSubdomains:
    def test_deep_nesting_triggers(self) -> None:
        result = check_excessive_subdomains(v("http://login.secure.account.verify.example.com/"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 8

    def test_www_passes(self) -> None:
        result = check_excessive_subdomains(v("https://www.example.com/"))
        assert result.status == CheckStatus.PASSED


class TestUrlLengthEntropy:
    def test_short_clean_url_passes(self) -> None:
        result = check_url_length_entropy(v("https://example.com/about"))
        assert result.status == CheckStatus.PASSED
        assert result.points == 0

    def test_moderately_long_url_scores_4(self) -> None:
        url = "https://example.com/" + "a/" * 30  # ~80 chars, low entropy
        assert check_url_length_entropy(v(url)).points == 4

    def test_very_long_url_scores_8(self) -> None:
        url = "https://example.com/" + "a/" * 45  # ~110 chars, low entropy
        assert check_url_length_entropy(v(url)).points == 8

    def test_high_entropy_query_adds_4(self) -> None:
        url = "https://example.com/x?tok=Zq9vR2mK8pL4wXnE7yT3bH6cJ1dF5gA0sU"
        result = check_url_length_entropy(v(url))
        assert result.points >= 4
        assert result.status == CheckStatus.TRIGGERED


class TestDomainLexical:
    def test_many_hyphens_trigger(self) -> None:
        result = check_domain_lexical(v("http://secure-login-verify.com/"))
        assert result.status == CheckStatus.TRIGGERED
        assert result.points == 8

    def test_digit_heavy_domain_triggers(self) -> None:
        result = check_domain_lexical(v("http://a3859302911.com/"))
        assert result.status == CheckStatus.TRIGGERED

    def test_normal_domain_passes(self) -> None:
        assert check_domain_lexical(v("https://github.com/")).status == CheckStatus.PASSED

    def test_ip_host_does_not_double_count(self) -> None:
        # ip_address_host already penalizes literal IPs; the digit-ratio
        # heuristic must not pile on for the same fact
        assert check_domain_lexical(v("http://93.184.216.34/")).status == CheckStatus.PASSED
