"""Null Meridian's SaaS estate: what each application is and how its access grew.

Application names are generic product categories ("CRM", "Team Chat"), never vendor or
product names, so nothing implies that the fictional company is any vendor's customer.

Each entry records when the company adopted the application, when it moved behind Okta
(never before 2021-10-01), which entitlement tiers it has and who holds them, and how its
access groups evolved: legacy groups from before Okta, transitional Okta-era groups, and
(for standardized applications) the ``sg-okta-<app>-<tier>`` groups and what became of the
older groups when those arrived.

Audience tokens: ``all`` (everyone), ``d:<dept>,..`` (departments), ``t:<dept>/<team>,..``
(teams), ``managers`` (people managers), ``p:<n>:<dept or dept/team>,..`` (n named people,
direct members), ``none`` (no one).
"""

from dataclasses import dataclass, field
from datetime import date

# What became of an application's older groups once sg-okta-* groups existed:
#   retired  - deleted from AD and Okta
#   nested   - kept, nested inside the new group (still the real source of membership)
#   retained - kept, no longer assigned, still populated or empty (stale)
#   assigned - kept AND still assigned next to the new group (a duplicate route)
#   current  - no sg-okta-* groups yet; the older groups are the assignment
FATES = ("retired", "nested", "retained", "assigned", "current")


@dataclass(frozen=True)
class AppSpec:
    slug: str
    label: str
    token: str  # how older group names spell the application
    category: str
    sso: str
    provisioning: str
    adopted: date
    tiers: dict[str, str]
    owner_department: str
    admin_departments: tuple[str, ...]
    modern: date | None = None
    fate: str = "current"
    transition: str = "import"  # import: legacy groups assigned as-is; okta: transitional groups created
    legacy_tiers: tuple[str, ...] = ("user", "admin")
    model: str = "GROUP"  # GROUP, DIRECT, MIXED
    direct_users: str | None = None  # audience of direct user assignments
    status: str = "ACTIVE"
    retired: date | None = None
    activity: float = 0.7  # share of entitled people active in the last 90 days
    events_per_user: int = 25
    okta_integrated: date | None = None
    everyone: bool = False  # Okta's built-in Everyone group is assigned too
    notes: tuple[str, ...] = field(default_factory=tuple)


def _d(y: int, m: int, d: int = 1) -> date:
    return date(y, m, d)


ENG_ALL = "d:engineering"
TECH = "d:engineering,data,security,it"

CATALOG: tuple[AppSpec, ...] = (
    # --- collaboration and productivity ------------------------------------------------
    AppSpec("mail", "Email and Calendar", "Mail", "collaboration", "SAML_2_0", "SCIM", _d(2016, 10, 3),
            {"user": "all", "admin": "p:3:it/corp-systems"}, "it", ("it",), _d(2024, 2, 12), "retired",
            events_per_user=180, activity=0.98),
    AppSpec("chat", "Team Chat", "Chat", "collaboration", "SAML_2_0", "SCIM", _d(2017, 2, 6),
            {"user": "all", "admin": "p:3:it/corp-systems"}, "it", ("it",), _d(2023, 11, 6), "nested",
            transition="okta", events_per_user=150, activity=0.97),
    AppSpec("video", "Video Meetings", "Video", "collaboration", "SAML_2_0", "SCIM", _d(2018, 3, 5),
            {"user": "all", "admin": "p:2:it/corp-systems"}, "it", ("it",), _d(2024, 1, 15), "retired",
            events_per_user=90, activity=0.95),
    AppSpec("wiki", "Team Wiki", "Wiki", "collaboration", "SAML_2_0", "SCIM", _d(2017, 5, 8),
            {"user": "all", "admin": "p:3:it/corp-systems,operations/pmo"}, "it", ("it", "operations"),
            _d(2024, 5, 20), "assigned", events_per_user=40, activity=0.85),
    AppSpec("file-sync", "Cloud File Sync", "FileSync", "collaboration", "SAML_2_0", "SCIM", _d(2018, 8, 13),
            {"user": "all", "admin": "p:2:it/corp-systems"}, "it", ("it",), _d(2024, 9, 9), "retained",
            events_per_user=60, activity=0.9),
    AppSpec("intranet", "NM Intranet", "Intranet", "collaboration", "BOOKMARK", "NONE", _d(2017, 9, 4),
            {"user": "all"}, "people", ("people",), legacy_tiers=("user",), events_per_user=3, activity=0.4,
            everyone=True),
    AppSpec("project-mgmt", "Project Management", "Projects", "productivity", "SAML_2_0", "SCIM", _d(2019, 9, 9),
            {"user": "d:operations,marketing,product,design,people", "admin": "p:2:operations/pmo"}, "operations",
            ("operations",), _d(2025, 3, 3), "nested", events_per_user=45),
    AppSpec("desk-booking", "Desk and Room Booking", "Desks", "productivity", "OPENID_CONNECT", "SCIM",
            _d(2022, 4, 4), {"user": "all", "admin": "p:2:operations/workplace"}, "operations", ("operations",),
            _d(2024, 7, 1), "retained", transition="okta", legacy_tiers=(), events_per_user=6, activity=0.55),
    AppSpec("esign", "E-Signature", "ESign", "legal", "SAML_2_0", "MANUAL", _d(2018, 5, 14),
            {"user": "d:legal,sales,finance,people", "admin": "p:2:legal/legal-ops"}, "legal", ("legal",),
            _d(2024, 10, 14), "assigned", events_per_user=15),
    # --- engineering, source control, CI/CD, cloud ---------------------------------------
    AppSpec("git", "Git Hosting", "Git", "source control", "SAML_2_0", "SCIM", _d(2016, 10, 10),
            {"developer": "d:engineering,data", "readonly": "d:security,product", "admin": "p:4:engineering/devprod"},
            "engineering", ("engineering",), _d(2023, 10, 16), "nested", legacy_tiers=("developer", "admin"),
            transition="okta", events_per_user=220, activity=0.9),
    AppSpec("ci", "CI Pipelines", "CI", "CI/CD", "OPENID_CONNECT", "MANUAL", _d(2017, 3, 13),
            {"developer": ENG_ALL, "admin": "p:3:engineering/devprod"}, "engineering", ("engineering",),
            _d(2023, 12, 4), "retired", legacy_tiers=("developer", "admin"), events_per_user=60, activity=0.8),
    AppSpec("artifacts", "Artifact Registry", "Artifacts", "CI/CD", "SAML_2_0", "MANUAL", _d(2019, 11, 4),
            {"developer": ENG_ALL, "admin": "p:2:engineering/devprod"}, "engineering", ("engineering",),
            _d(2024, 3, 11), "retired", legacy_tiers=("developer", "admin"), events_per_user=20, activity=0.6),
    AppSpec("issues", "Issue Tracker", "Issues", "engineering", "SAML_2_0", "SCIM", _d(2016, 11, 7),
            {"user": "d:engineering,product,design,data,security,it,customer-success", "admin": "p:3:engineering/devprod"},
            "engineering", ("engineering",), _d(2024, 4, 8), "nested", events_per_user=120, activity=0.9),
    AppSpec("observability", "Observability Platform", "Observability", "engineering", "SAML_2_0", "SCIM",
            _d(2023, 11, 13), {"user": "d:engineering", "admin": "p:5:engineering/sre"}, "engineering",
            ("engineering",), _d(2023, 11, 13), "retired", legacy_tiers=(), events_per_user=70, activity=0.75,
            notes=("portfolio:healthy",)),
    AppSpec("logs", "Log Analytics", "Logs", "engineering", "SAML_2_0", "MANUAL", _d(2018, 4, 9),
            {"user": "d:engineering", "power": "t:engineering/sre,security/secops", "admin": "p:2:engineering/sre"},
            "engineering", ("engineering", "security"), _d(2025, 1, 13), "assigned", events_per_user=35),
    AppSpec("errors", "Error Tracking", "Errors", "engineering", "OPENID_CONNECT", "SCIM", _d(2019, 7, 15),
            {"user": ENG_ALL, "admin": "p:2:engineering/sre"}, "engineering", ("engineering",),
            _d(2024, 6, 3), "retired", events_per_user=30),
    AppSpec("feature-flags", "Feature Flags", "Flags", "engineering", "SAML_2_0", "SCIM", _d(2021, 6, 7),
            {"user": "d:engineering,product", "admin": "p:2:engineering/devprod"}, "engineering", ("engineering",),
            _d(2024, 8, 19), "retained", transition="okta", events_per_user=25),
    AppSpec("oncall", "On-Call Paging", "OnCall", "engineering", "SAML_2_0", "SCIM", _d(2018, 6, 18),
            {"user": "t:engineering/sre,engineering/platform,engineering/core-api,engineering/infrastructure,it/endpoint,security/secops",
             "admin": "p:2:engineering/sre"}, "engineering", ("engineering",), _d(2024, 2, 26), "retired",
            events_per_user=18),
    AppSpec("status-page", "Status Page", "StatusPage", "engineering", "BROWSER_PLUGIN", "NONE", _d(2020, 3, 2),
            {"user": "t:engineering/sre,customer-success/support-ops", "admin": "none"}, "engineering",
            ("engineering",), _d(2024, 2, 5), "retained", legacy_tiers=("user",), events_per_user=6,
            notes=("portfolio:empty-assigned",)),
    AppSpec("code-scanning", "Code Quality Scanner", "CodeScan", "security", "SAML_2_0", "MANUAL", _d(2021, 2, 1),
            {"developer": ENG_ALL, "admin": "p:2:security/appsec"}, "security", ("security",), _d(2024, 11, 4),
            "retired", legacy_tiers=("developer",), events_per_user=10, activity=0.5),
    AppSpec("cloud-prod", "Cloud Console (Production)", "CloudProd", "cloud", "SAML_2_0", "NONE", _d(2017, 1, 16),
            {"readonly": "t:engineering/sre,engineering/infrastructure,engineering/platform,security/secops",
             "power": "t:engineering/sre,engineering/infrastructure", "admin": "p:3:engineering/infrastructure"},
            "engineering", ("engineering",), _d(2023, 10, 2), "nested", legacy_tiers=("power", "admin"),
            transition="okta", events_per_user=40, notes=("broad-power",)),
    AppSpec("cloud-nonprod", "Cloud Console (Non-Production)", "CloudDev", "cloud", "SAML_2_0", "NONE",
            _d(2017, 1, 16), {"developer": "d:engineering,data", "admin": "p:3:engineering/infrastructure"},
            "engineering", ("engineering",), _d(2023, 10, 2), "assigned", legacy_tiers=("developer", "admin"),
            events_per_user=35),
    AppSpec("containers", "Container Platform", "K8s", "cloud", "OPENID_CONNECT", "NONE", _d(2020, 5, 11),
            {"developer": ENG_ALL, "admin": "p:3:engineering/platform"}, "engineering", ("engineering",),
            _d(2024, 1, 22), "retired", legacy_tiers=("developer", "admin"), events_per_user=30),
    AppSpec("dns", "DNS Management", "DNS", "identity/infrastructure", "BROWSER_PLUGIN", "NONE", _d(2017, 4, 3),
            {"admin": "p:3:engineering/infrastructure,it/corp-systems"}, "it", ("engineering", "it"),
            legacy_tiers=("admin",), events_per_user=5, activity=0.6),
    # --- security and identity/infrastructure ------------------------------------------
    AppSpec("vault", "Secrets Vault", "Vault", "security", "OPENID_CONNECT", "NONE", _d(2020, 7, 6),
            {"developer": ENG_ALL, "admin": "p:3:security/appsec,engineering/platform"}, "security",
            ("security", "engineering"), _d(2023, 10, 23), "retired", legacy_tiers=("admin",), events_per_user=45),
    AppSpec("password-manager", "Password Manager", "Passwords", "security", "SAML_2_0", "SCIM", _d(2019, 4, 1),
            {"user": "all", "admin": "p:2:security/secops,it/iam"}, "security", ("security", "it"),
            _d(2024, 4, 22), "retired", events_per_user=30, activity=0.85),
    AppSpec("edr", "Endpoint Detection Console", "EDR", "security", "SAML_2_0", "NONE", _d(2020, 9, 21),
            {"readonly": "t:it/endpoint", "admin": "p:3:security/secops"}, "security", ("security",),
            _d(2024, 6, 17), "retained", legacy_tiers=("admin",), events_per_user=40),
    AppSpec("siem", "SIEM", "SIEM", "security", "SAML_2_0", "NONE", _d(2021, 11, 15),
            {"user": "t:security/secops,security/appsec", "admin": "p:2:security/secops"}, "security", ("security",),
            _d(2023, 10, 30), "retired", transition="okta", legacy_tiers=(), events_per_user=80),
    AppSpec("vuln-scanner", "Vulnerability Scanner", "VulnScan", "security", "SAML_2_0", "NONE", _d(2020, 8, 3),
            {"user": "t:security/appsec,security/secops,it/endpoint,engineering/sre", "admin": "p:2:security/appsec"},
            "security", ("security",), _d(2025, 2, 10), "nested", events_per_user=20),
    AppSpec("pam", "Privileged Access Manager", "PAM", "security", "SAML_2_0", "NONE", _d(2022, 9, 12),
            {"user": "t:engineering/infrastructure,engineering/sre,it/corp-systems", "approver": "p:3:security/secops",
             "admin": "p:2:it/iam"}, "security", ("security", "it"), _d(2024, 3, 25), "retained",
            transition="okta", legacy_tiers=(), events_per_user=25),
    AppSpec("security-training", "Security Awareness Training", "SecTraining", "security", "SAML_2_0", "SCIM",
            _d(2020, 10, 19), {"user": "all", "admin": "p:2:security/grc"}, "security", ("security",),
            _d(2024, 12, 2), "retired", events_per_user=4, activity=0.8),
    AppSpec("vpn", "Remote Access VPN", "VPN", "identity/infrastructure", "SAML_2_0", "NONE", _d(2017, 2, 13),
            {"user": "d:engineering,it,security,data,operations", "admin": "p:2:it/endpoint"}, "it", ("it",),
            _d(2023, 10, 2), "retained", events_per_user=50, notes=("normalized-case",)),
    AppSpec("mdm", "Device Management", "MDM", "identity/infrastructure", "SAML_2_0", "NONE", _d(2018, 7, 9),
            {"readonly": "t:it/service-desk", "admin": "p:3:it/endpoint"}, "it", ("it",), _d(2023, 10, 9),
            "retired", legacy_tiers=("admin",), events_per_user=30, notes=("normalized-case",)),
    AppSpec("service-desk", "IT Service Desk", "ServiceDesk", "identity/infrastructure", "SAML_2_0", "SCIM",
            _d(2018, 9, 10), {"user": "all", "power": "t:it/service-desk,it/endpoint", "admin": "p:2:it/corp-systems"},
            "it", ("it",), _d(2024, 1, 8), "nested", legacy_tiers=("power", "admin"), events_per_user=6,
            activity=0.6),
    AppSpec("asset-mgmt", "IT Asset Management", "Assets", "identity/infrastructure", "SAML_2_0", "MANUAL",
            _d(2019, 6, 17), {"user": "t:it/service-desk,it/endpoint", "admin": "p:2:it/endpoint"}, "it", ("it",),
            events_per_user=15),
    # --- HR ----------------------------------------------------------------------------
    AppSpec("hris", "HR Information System", "HRIS", "HR", "SAML_2_0", "SCIM", _d(2018, 1, 15),
            {"user": "all", "power": "t:people/people-partners,people/people-ops", "admin": "p:3:people/people-ops"},
            "people", ("people",), _d(2024, 5, 6), "nested", events_per_user=5, activity=0.7),
    AppSpec("payroll", "Payroll", "Payroll", "HR", "SAML_2_0", "MANUAL", _d(2017, 3, 6),
            {"user": "t:people/total-rewards,finance/accounting", "approver": "p:3:finance/accounting",
             "admin": "p:2:people/total-rewards"}, "people", ("people", "finance"), _d(2024, 2, 19), "current",
            notes=("push-linked",), events_per_user=12),
    AppSpec("ats", "Applicant Tracking", "ATS", "HR", "SAML_2_0", "SCIM", _d(2018, 2, 19),
            {"user": "t:people/talent", "standard": "managers", "admin": "p:2:people/talent"}, "people", ("people",),
            _d(2025, 4, 14), "assigned", events_per_user=20, notes=("broad-managers",)),
    AppSpec("benefits", "Benefits Portal", "Benefits", "HR", "BOOKMARK", "NONE", _d(2017, 1, 9), {"user": "all"},
            "people", ("people",), legacy_tiers=(), events_per_user=1, activity=0.2, everyone=True),
    AppSpec("learning", "Learning Platform", "LMS", "HR", "SAML_2_0", "SCIM", _d(2020, 11, 2),
            {"user": "all", "admin": "p:2:people/learning"}, "people", ("people",), _d(2025, 6, 2), "retired",
            events_per_user=4, activity=0.6),
    AppSpec("performance", "Performance Reviews", "Perf", "HR", "SAML_2_0", "SCIM", _d(2021, 5, 3),
            {"user": "all", "admin": "p:2:people/people-ops"}, "people", ("people",), _d(2024, 9, 23), "retained",
            transition="okta", events_per_user=3, activity=0.7),
    AppSpec("org-chart", "Org Chart", "OrgChart", "HR", "OPENID_CONNECT", "SCIM", _d(2022, 3, 7), {"user": "all"},
            "people", ("people",), transition="import", legacy_tiers=(), events_per_user=2, activity=0.5,
            everyone=True),
    # --- finance and expense/travel ------------------------------------------------------
    AppSpec("erp", "ERP and General Ledger", "ERP", "finance", "SAML_2_0", "MANUAL", _d(2019, 3, 4),
            {"user": "d:finance", "approver": "p:4:finance/accounting", "admin": "p:2:finance/accounting"},
            "finance", ("finance",), _d(2025, 7, 7), "assigned", legacy_tiers=("user", "admin"),
            events_per_user=60, activity=0.9),
    AppSpec("expense", "Expense Management", "Expense", "expense/travel", "SAML_2_0", "SCIM", _d(2017, 6, 5),
            {"user": "all", "approver": "managers", "admin": "p:2:finance/accounting"}, "finance", ("finance",),
            legacy_tiers=("user", "admin"), transition="okta", events_per_user=8, activity=0.65,
            notes=("portfolio:legacy-transitional",)),
    AppSpec("travel", "Travel Booking", "Travel", "expense/travel", "SAML_2_0", "SCIM", _d(2018, 10, 1),
            {"user": "all", "admin": "p:2:operations/workplace"}, "operations", ("operations",), _d(2024, 7, 15),
            "retained", transition="okta", events_per_user=3, activity=0.35),
    AppSpec("corporate-card", "Corporate Card Portal", "Card", "finance", "SAML_2_0", "SCIM", _d(2021, 4, 12),
            {"user": "managers", "admin": "p:2:finance/accounting"}, "finance", ("finance",), _d(2024, 10, 28),
            "retired", transition="okta", legacy_tiers=(), events_per_user=6),
    AppSpec("procurement", "Procurement", "Procurement", "finance", "SAML_2_0", "MANUAL", _d(2022, 6, 20),
            {"user": "t:operations/vendor,finance/accounting", "approver": "p:4:finance/fpa,operations/vendor",
             "admin": "p:2:operations/vendor"}, "operations", ("operations", "finance"), _d(2024, 12, 9),
            "retired", transition="okta", legacy_tiers=(), events_per_user=15),
    AppSpec("fpa-planning", "FP&A Planning", "Planning", "finance", "SAML_2_0", "MANUAL", _d(2021, 1, 18),
            {"user": "t:finance/fpa", "readonly": "d:executive", "admin": "p:2:finance/fpa"}, "finance",
            ("finance",), legacy_tiers=("user",), transition="okta", events_per_user=40,
            notes=("ambiguous-finance",)),
    AppSpec("tax-portal", "Tax Compliance Portal", "Tax", "finance", "BROWSER_PLUGIN", "NONE", _d(2019, 12, 2),
            {"user": "t:finance/tax"}, "finance", ("finance",), legacy_tiers=("user",), events_per_user=5,
            activity=0.6),
    AppSpec("billing", "Subscription Billing", "Billing", "finance", "SAML_2_0", "MANUAL", _d(2019, 1, 21),
            {"user": "t:finance/billing,customer-success/renewals", "billing": "t:finance/billing",
             "admin": "p:2:finance/billing"}, "finance", ("finance",), _d(2025, 5, 12), "nested",
            legacy_tiers=("user", "admin"), events_per_user=50),
    # --- CRM, sales, support ---------------------------------------------------------------
    AppSpec("crm", "CRM", "CRM", "CRM", "SAML_2_0", "MANUAL", _d(2017, 5, 1),
            {"user": "d:sales,customer-success", "readonly": "d:marketing,finance",
             "power": "t:operations/revops", "admin": "p:3:operations/revops"}, "operations", ("operations",),
            _d(2023, 11, 20), "assigned", legacy_tiers=("user", "admin"), transition="okta", model="MIXED",
            direct_users="p:23:marketing,operations/bizops,product/growth", events_per_user=140, activity=0.92,
            notes=("portfolio:overlap", "stray-admin")),
    AppSpec("cpq", "CPQ and Quoting", "CPQ", "CRM", "SAML_2_0", "MANUAL", _d(2020, 1, 13),
            {"user": "t:sales/enterprise,sales/mid-market,sales/solutions", "approver": "p:4:sales,finance/billing",
             "admin": "p:2:operations/revops"}, "operations", ("operations",), _d(2025, 8, 4), "assigned",
            legacy_tiers=("user",), events_per_user=50),
    AppSpec("sales-engagement", "Sales Engagement", "SalesEng", "CRM", "SAML_2_0", "SCIM", _d(2019, 9, 23),
            {"user": "t:sales/sdr,sales/enterprise,sales/mid-market", "admin": "p:2:operations/revops"},
            "sales", ("operations",), legacy_tiers=("user",), events_per_user=200),
    AppSpec("conversation-intel", "Conversation Intelligence", "Calls", "CRM", "SAML_2_0", "SCIM", _d(2021, 3, 8),
            {"user": "d:sales,customer-success", "admin": "p:2:sales/enablement"}, "sales", ("sales",),
            _d(2024, 4, 1), "retained", transition="okta", events_per_user=35, notes=("stray-admin",), model="MIXED",
            direct_users="p:4:customer-success/csm"),
    AppSpec("prospect-data", "Prospect Data", "Prospects", "CRM", "BROWSER_PLUGIN", "NONE", _d(2019, 5, 6),
            {"user": "none"}, "sales", ("sales",), legacy_tiers=(), model="DIRECT", direct_users="p:6:sales/sdr",
            events_per_user=1, activity=0.3, notes=("low-use",)),
    AppSpec("support-desk", "Customer Support Desk", "Support", "support", "SAML_2_0", "SCIM", _d(2018, 1, 22),
            {"standard": "t:customer-success/support-t1,customer-success/support-t2",
             "power": "t:customer-success/support-ops", "readonly": "d:product,engineering",
             "admin": "p:3:customer-success/support-ops"}, "customer-success", ("customer-success",),
            _d(2024, 8, 5), "nested", legacy_tiers=("standard", "admin"), events_per_user=300,
            notes=("broad-readonly",)),
    AppSpec("cs-platform", "Customer Success Platform", "CSP", "support", "SAML_2_0", "MANUAL", _d(2020, 6, 29),
            {"user": "t:customer-success/csm,customer-success/onboarding,customer-success/renewals",
             "admin": "p:2:customer-success/support-ops"}, "customer-success", ("customer-success",),
            _d(2025, 1, 27), "retired", events_per_user=80),
    AppSpec("knowledge-base", "Knowledge Base", "KB", "support", "SAML_2_0", "SCIM", _d(2019, 2, 25),
            {"user": "d:customer-success,product", "admin": "p:2:customer-success/support-ops"}, "customer-success",
            ("customer-success",), events_per_user=25),
    AppSpec("live-chat", "Live Chat Widget", "LiveChat", "support", "BROWSER_PLUGIN", "NONE", _d(2019, 10, 21),
            {"user": "t:customer-success/support-t1", "admin": "p:1:customer-success/support-ops"},
            "customer-success", ("customer-success",), events_per_user=60),
    # --- marketing, analytics, design --------------------------------------------------------
    AppSpec("marketing-automation", "Marketing Automation", "MarketingAuto", "marketing", "SAML_2_0", "MANUAL",
            _d(2018, 2, 5), {"user": "d:marketing", "admin": "p:2:marketing/marketing-ops"}, "marketing",
            ("marketing",), _d(2024, 11, 18), "retired", events_per_user=70),
    AppSpec("cms", "Web CMS", "CMS", "marketing", "SAML_2_0", "MANUAL", _d(2017, 7, 10),
            {"user": "t:marketing/content,marketing/brand,marketing/product-marketing,design/product-design",
             "admin": "p:2:marketing/marketing-ops"}, "marketing", ("marketing",), events_per_user=30,
            notes=("stray-admin",)),
    AppSpec("social", "Social Scheduler", "Social", "marketing", "BROWSER_PLUGIN", "NONE", _d(2019, 3, 18),
            {"user": "t:marketing/content,marketing/brand"}, "marketing", ("marketing",), legacy_tiers=("user",),
            events_per_user=15),
    AppSpec("webinar", "Webinar Platform", "Webinar", "marketing", "SAML_2_0", "MANUAL", _d(2020, 4, 6),
            {"user": "t:marketing/events,marketing/demand-gen,customer-success/onboarding", "admin": "p:1:marketing/events"},
            "marketing", ("marketing",), _d(2025, 2, 24), "retired", events_per_user=10),
    AppSpec("ad-analytics", "Ad Analytics", "AdAnalytics", "marketing", "BOOKMARK", "NONE", _d(2020, 9, 7),
            {"user": "none"}, "marketing", ("marketing",), legacy_tiers=(), model="DIRECT",
            direct_users="p:5:marketing/demand-gen", events_per_user=0, activity=0.0),
    AppSpec("warehouse", "Data Warehouse", "Warehouse", "analytics", "SAML_2_0", "NONE", _d(2019, 3, 25),
            {"readonly": "d:data", "developer": "t:data/data-engineering,data/analytics-engineering",
             "admin": "p:2:data/data-engineering"}, "data", ("data",), _d(2024, 6, 10), "nested",
            legacy_tiers=("readonly", "admin"), transition="okta", events_per_user=150,
            notes=("portfolio:deep",)),
    AppSpec("bi", "BI Dashboards", "BI", "analytics", "SAML_2_0", "SCIM", _d(2019, 5, 20),
            {"user": "all", "power": "d:data,finance", "admin": "p:2:data/analytics"}, "data", ("data",),
            legacy_tiers=("user", "admin"), transition="okta", events_per_user=30, activity=0.55, model="MIXED",
            direct_users="p:9:executive,finance/fpa"),
    AppSpec("product-analytics", "Product Analytics", "ProductAnalytics", "analytics", "SAML_2_0", "SCIM",
            _d(2020, 2, 24), {"user": "d:product,design,engineering,marketing", "admin": "p:2:product/product-ops"},
            "product", ("product",), _d(2024, 9, 2), "retired", events_per_user=40),
    AppSpec("notebooks", "Notebook Workspace", "Notebooks", "analytics", "OPENID_CONNECT", "NONE", _d(2021, 7, 19),
            {"developer": "t:data/data-science,data/analytics", "admin": "p:2:data/data-engineering"}, "data",
            ("data",), _d(2023, 10, 9), "retired", legacy_tiers=("developer",), events_per_user=90),
    AppSpec("etl", "ETL Orchestrator", "ETL", "analytics", "OPENID_CONNECT", "NONE", _d(2021, 12, 6),
            {"developer": "t:data/data-engineering,data/analytics-engineering", "admin": "p:2:data/data-engineering"},
            "data", ("data",), _d(2026, 7, 13), "retired", transition="okta", legacy_tiers=(), events_per_user=120,
            notes=("unreviewed",)),
    AppSpec("design-studio", "Design Studio", "Design", "design", "SAML_2_0", "SCIM", _d(2018, 4, 16),
            {"standard": "d:design", "readonly": "d:product,marketing,engineering", "admin": "p:2:design/design-systems"},
            "design", ("design",), _d(2024, 3, 4), "nested", legacy_tiers=("standard", "admin"), events_per_user=90),
    AppSpec("prototyping", "Prototyping Tool", "Proto", "design", "BROWSER_PLUGIN", "NONE", _d(2019, 6, 3),
            {"user": "t:design/product-design,design/ux-research"}, "design", ("design",), legacy_tiers=("user",),
            events_per_user=20, activity=0.5),
    AppSpec("brand-assets", "Brand Asset Library", "BrandAssets", "design", "SAML_2_0", "SCIM", _d(2021, 9, 13),
            {"user": "d:design,marketing", "admin": "p:1:marketing/brand"}, "marketing", ("marketing",),
            _d(2025, 9, 15), "retired", transition="okta", events_per_user=8),
    AppSpec("roadmapping", "Product Roadmapping", "Roadmap", "productivity", "SAML_2_0", "MANUAL", _d(2020, 7, 27),
            {"user": "d:product", "readonly": "d:engineering,design,customer-success", "admin": "p:1:product/product-ops"},
            "product", ("product",), _d(2026, 8, 3), "retired", events_per_user=30, notes=("unreviewed",)),
    # --- legal ---------------------------------------------------------------------------
    AppSpec("contracts", "Contract Lifecycle", "CLM", "legal", "SAML_2_0", "MANUAL", _d(2020, 5, 4),
            {"user": "d:legal", "standard": "t:sales/enterprise,finance/accounting", "approver": "p:3:legal/commercial",
             "admin": "p:1:legal/legal-ops"}, "legal", ("legal",), _d(2024, 12, 16), "retired",
            legacy_tiers=("user",), events_per_user=25),
    AppSpec("matter-mgmt", "Legal Matter Management", "Matters", "legal", "SAML_2_0", "MANUAL", _d(2022, 11, 7),
            {"user": "d:legal", "admin": "p:1:legal/legal-ops"}, "legal", ("legal",), transition="okta",
            legacy_tiers=(), events_per_user=40),
    AppSpec("board-portal", "Board Portal", "Board", "legal", "SAML_2_0", "NONE", _d(2021, 10, 25), {},
            "legal", ("legal",), transition="okta", legacy_tiers=(), model="DIRECT",
            direct_users="p:14:executive,legal/commercial", events_per_user=6),
    # --- retired applications, still in Okta as INACTIVE --------------------------------------
    AppSpec("timesheets", "Legacy Timesheets", "Timesheets", "HR", "BROWSER_PLUGIN", "NONE", _d(2017, 2, 20),
            {"user": "none"}, "operations", ("operations",), legacy_tiers=("user",), status="INACTIVE",
            retired=_d(2025, 3, 31), events_per_user=0, activity=0.0, notes=("portfolio:clean-candidate",)),
    AppSpec("fax-gateway", "Fax Gateway", "Fax", "productivity", "BROWSER_PLUGIN", "NONE", _d(2018, 3, 12),
            {"user": "none"}, "operations", ("operations",), legacy_tiers=("user",), status="INACTIVE",
            retired=_d(2024, 11, 29), transition="okta", events_per_user=0, activity=0.0,
            notes=("hold-candidate", "push-broken")),
    AppSpec("legacy-cloud", "Cloud Console (2017 account)", "CloudLegacy", "cloud", "SAML_2_0", "NONE",
            _d(2017, 1, 16), {"admin": "p:2:engineering/infrastructure"}, "engineering", ("engineering",),
            legacy_tiers=("admin",), status="INACTIVE", retired=_d(2025, 6, 30), events_per_user=0, activity=0.0,
            notes=("protected-candidate",)),
    AppSpec("old-wiki", "Team Wiki (v1)", "WikiV1", "collaboration", "SAML_2_0", "NONE", _d(2016, 11, 14),
            {"user": "none"}, "it", ("it",), legacy_tiers=("user",), status="INACTIVE", retired=_d(2023, 4, 28),
            events_per_user=0, activity=0.0, notes=("name-only-candidate",)),
    AppSpec("print-release", "Print Release", "Print", "identity/infrastructure", "BROWSER_PLUGIN", "NONE",
            _d(2018, 11, 5), {"user": "none"}, "it", ("it",), legacy_tiers=("user",), status="INACTIVE",
            retired=_d(2025, 9, 1), events_per_user=0, activity=0.0),
)
