"""N8 Group branding constants.

All customer-facing N8 Group text lives here. Update this single file
to change messaging across CLI output, HTML reports, and Excel exports.
"""

COMPANY_NAME = "N8 Group"
TAGLINE = "DevOps Transformation. Executed with Precision."
WEBSITE = "https://n8-group.com"
CONTACT_EMAIL = "contact@n8-group.com"
SALES_EMAIL = "sales@n8-group.com"
PHONE = "+48 12 300 25 80"
LINKEDIN = "https://www.linkedin.com/company/n8-group/"
YOUTUBE = "https://www.youtube.com/@N8-Group"

ABOUT_TEXT = (
    "N8 Group is a European leader in AI-powered DevOps solutions. "
    "We deliver expert GitHub Copilot training, Atlassian Rovo workshops, "
    "and enterprise platform migrations across Europe."
)

SERVICES = [
    "GitHub Enterprise Governance",
    "Azure DevOps to GitHub Migration",
    "GitHub Advanced Security",
    "GitHub Copilot Workshop",
    "DevOps Strategy Consulting",
    "Platform Migration Services",
]

CLI_BANNER = (
    "------------------------------------------------------------------------\n"
    "  gh-audit is a free tool by N8 Group | https://n8-group.com\n"
    "  Need help with GitHub governance, migration, or DevOps transformation?\n"
    "  Contact: sales@n8-group.com | +48 12 300 25 80\n"
    "------------------------------------------------------------------------"
)


def get_template_context() -> dict[str, object]:
    """Return branding values as a dict for Jinja2 template rendering."""
    return {
        "company_name": COMPANY_NAME,
        "tagline": TAGLINE,
        "website": WEBSITE,
        "sales_email": SALES_EMAIL,
        "contact_email": CONTACT_EMAIL,
        "phone": PHONE,
        "linkedin": LINKEDIN,
        "youtube": YOUTUBE,
        "about_text": ABOUT_TEXT,
        "services": SERVICES,
    }
