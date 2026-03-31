"""Tests for N8 Group branding constants module."""

import gh_audit.branding as branding


class TestBrandingConstantsDefined:
    def test_company_name_defined(self):
        assert hasattr(branding, "COMPANY_NAME")
        assert branding.COMPANY_NAME == "N8 Group"

    def test_tagline_defined(self):
        assert hasattr(branding, "TAGLINE")
        assert isinstance(branding.TAGLINE, str)
        assert len(branding.TAGLINE) > 0

    def test_website_defined(self):
        assert hasattr(branding, "WEBSITE")
        assert branding.WEBSITE.startswith("https://")

    def test_contact_email_defined(self):
        assert hasattr(branding, "CONTACT_EMAIL")
        assert "@" in branding.CONTACT_EMAIL

    def test_sales_email_defined(self):
        assert hasattr(branding, "SALES_EMAIL")
        assert "@" in branding.SALES_EMAIL

    def test_phone_defined(self):
        assert hasattr(branding, "PHONE")
        assert isinstance(branding.PHONE, str)
        assert len(branding.PHONE) > 0

    def test_linkedin_defined(self):
        assert hasattr(branding, "LINKEDIN")
        assert branding.LINKEDIN.startswith("https://")

    def test_youtube_defined(self):
        assert hasattr(branding, "YOUTUBE")
        assert branding.YOUTUBE.startswith("https://")

    def test_about_text_defined(self):
        assert hasattr(branding, "ABOUT_TEXT")

    def test_services_defined(self):
        assert hasattr(branding, "SERVICES")

    def test_cli_banner_defined(self):
        assert hasattr(branding, "CLI_BANNER")


class TestAboutText:
    def test_about_text_is_substantial(self):
        assert len(branding.ABOUT_TEXT) > 50

    def test_about_text_is_string(self):
        assert isinstance(branding.ABOUT_TEXT, str)


class TestServices:
    def test_services_is_list(self):
        assert isinstance(branding.SERVICES, list)

    def test_services_has_at_least_four_items(self):
        assert len(branding.SERVICES) >= 4

    def test_services_items_are_strings(self):
        for service in branding.SERVICES:
            assert isinstance(service, str)
            assert len(service) > 0


class TestCliBanner:
    def test_cli_banner_contains_product_name(self):
        assert "gh-audit" in branding.CLI_BANNER

    def test_cli_banner_is_ascii_only(self):
        assert branding.CLI_BANNER.isascii()

    def test_cli_banner_contains_website(self):
        assert "n8-group.com" in branding.CLI_BANNER

    def test_cli_banner_contains_email(self):
        assert "@" in branding.CLI_BANNER
        assert "n8-group.com" in branding.CLI_BANNER

    def test_cli_banner_is_string(self):
        assert isinstance(branding.CLI_BANNER, str)

    def test_cli_banner_is_multiline(self):
        assert "\n" in branding.CLI_BANNER
