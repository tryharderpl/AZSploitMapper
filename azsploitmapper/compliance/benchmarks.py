"""
Full benchmark control definitions for compliance mapping.

Contains the complete set of controls from:
- CIS Microsoft Azure Foundations Benchmark v2.1.0
- NIST SP 800-53 Rev. 5 (Azure-relevant subset)

Controls that are NOT matched by any scan finding are reported as PASS.
Controls matched by one or more findings are reported as FAIL.
"""

# ---------------------------------------------------------------------------
# CIS Microsoft Azure Foundations Benchmark v2.1.0
# At least 40 controls covering the major categories.
# ---------------------------------------------------------------------------
CIS_AZURE_CONTROLS: dict[str, dict] = {
    # ── Identity and Access Management ────────────────────────────────────
    "1.1": {
        "title": "Ensure Security Defaults is enabled on Azure AD",
        "category": "Identity and Access Management",
        "description": (
            "Security Defaults in Azure AD provide baseline identity "
            "security such as MFA registration, blocking legacy auth, "
            "and protecting privileged actions."
        ),
    },
    "1.2": {
        "title": "Ensure Multi-Factor Authentication is enabled for all privileged users",
        "category": "Identity and Access Management",
        "description": (
            "MFA should be enabled for all users with administrative "
            "roles to reduce the risk of credential compromise."
        ),
    },
    "1.3": {
        "title": "Ensure Multi-Factor Authentication is enabled for all non-privileged users",
        "category": "Identity and Access Management",
        "description": (
            "Requiring MFA for all users prevents unauthorized access "
            "even when passwords are compromised."
        ),
    },
    "1.4": {
        "title": "Ensure guest users are reviewed on a regular basis",
        "category": "Identity and Access Management",
        "description": (
            "Guest user accounts should be reviewed periodically to "
            "ensure they still require access and have appropriate "
            "permissions."
        ),
    },
    "1.5": {
        "title": "Ensure that 'Number of methods required to reset' is set to '2'",
        "category": "Identity and Access Management",
        "description": (
            "Self-service password reset should require two "
            "authentication methods to prevent unauthorised resets."
        ),
    },
    "1.10": {
        "title": "Ensure that 'Users can consent to apps accessing company data on their behalf' is set to 'No'",
        "category": "Identity and Access Management",
        "description": (
            "Preventing user consent to third-party apps reduces the "
            "risk of malicious OAuth applications accessing "
            "organisational data."
        ),
    },
    "1.22": {
        "title": "Ensure that RBAC role assignments are scoped to resource groups or resources",
        "category": "Identity and Access Management",
        "description": (
            "Role assignments at the subscription level grant broad "
            "access. Scope them to resource groups or individual "
            "resources to follow least privilege."
        ),
    },
    "1.23": {
        "title": "Ensure custom RBAC roles are reviewed and follow least privilege",
        "category": "Identity and Access Management",
        "description": (
            "Managed identities and custom roles should not have "
            "Contributor or Owner assignments unless strictly required."
        ),
    },
    "1.24": {
        "title": "Ensure unused managed identities are removed",
        "category": "Identity and Access Management",
        "description": (
            "Managed identities with no recent sign-in activity "
            "increase the attack surface and should be removed."
        ),
    },

    # ── Microsoft Defender ────────────────────────────────────────────────
    "2.1": {
        "title": "Ensure Microsoft Defender for Servers is set to 'On'",
        "category": "Microsoft Defender",
        "description": (
            "Microsoft Defender for Servers provides threat detection "
            "and advanced defences for Azure and hybrid VMs."
        ),
    },
    "2.2": {
        "title": "Ensure Microsoft Defender for App Service is set to 'On'",
        "category": "Microsoft Defender",
        "description": (
            "Defender for App Service detects attacks targeting web "
            "applications hosted on Azure App Service."
        ),
    },
    "2.3": {
        "title": "Ensure Microsoft Defender for Azure SQL Databases is set to 'On'",
        "category": "Microsoft Defender",
        "description": (
            "Defender for SQL surfaces database vulnerabilities and "
            "detects anomalous activities such as SQL injection."
        ),
    },
    "2.4": {
        "title": "Ensure Microsoft Defender for SQL servers on machines is set to 'On'",
        "category": "Microsoft Defender",
        "description": (
            "Extends SQL threat protection to SQL Server instances "
            "running on Azure VMs and Arc-enabled servers."
        ),
    },
    "2.5": {
        "title": "Ensure Microsoft Defender for Storage is set to 'On'",
        "category": "Microsoft Defender",
        "description": (
            "Defender for Storage detects unusual and potentially "
            "harmful attempts to access or exploit storage accounts."
        ),
    },
    "2.6": {
        "title": "Ensure Microsoft Defender for Key Vault is set to 'On'",
        "category": "Microsoft Defender",
        "description": (
            "Defender for Key Vault detects unusual and potentially "
            "harmful attempts to access or exploit Key Vault accounts."
        ),
    },

    # ── Storage Accounts ──────────────────────────────────────────────────
    "3.1": {
        "title": "Ensure that 'Secure transfer required' is set to 'Enabled'",
        "category": "Storage Accounts",
        "description": (
            "Enforcing HTTPS ensures data in transit between clients "
            "and storage accounts is encrypted."
        ),
    },
    "3.2": {
        "title": "Ensure that storage account access keys are periodically regenerated",
        "category": "Storage Accounts",
        "description": (
            "Storage access keys should be rotated regularly to limit "
            "the window of exposure if a key is compromised."
        ),
    },
    "3.7": {
        "title": "Ensure that public access level is disabled for storage accounts",
        "category": "Storage Accounts",
        "description": (
            "Disabling public blob access prevents anonymous users "
            "from reading container and blob data."
        ),
    },
    "3.8": {
        "title": "Ensure default network access rule for Storage Accounts is set to deny",
        "category": "Storage Accounts",
        "description": (
            "Deny-by-default network rules force explicit "
            "allow-listing of trusted networks and services."
        ),
    },
    "3.9": {
        "title": "Ensure storage for critical data is encrypted with Customer Managed Key",
        "category": "Storage Accounts",
        "description": (
            "Customer-managed keys (CMK) provide an additional layer "
            "of control over data encryption at rest."
        ),
    },
    "3.10": {
        "title": "Ensure Storage logging is enabled for Blob service for read, write, and delete requests",
        "category": "Storage Accounts",
        "description": (
            "Storage Analytics logging captures read, write, and "
            "delete operations for audit and forensics."
        ),
    },
    "3.11": {
        "title": "Ensure soft delete is enabled for Azure Storage blobs",
        "category": "Storage Accounts",
        "description": (
            "Soft delete retains deleted blobs for a configurable "
            "period, protecting against accidental or malicious "
            "deletion."
        ),
    },

    # ── Database Services ─────────────────────────────────────────────────
    "4.1": {
        "title": "Ensure that 'Auditing' is set to 'On' for SQL servers",
        "category": "Database Services",
        "description": (
            "Database auditing tracks events and writes them to an "
            "audit log for analysis and regulatory compliance."
        ),
    },
    "4.2": {
        "title": "Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)",
        "category": "Database Services",
        "description": (
            "Allowing all Azure services and any IP to connect to "
            "SQL servers vastly increases the attack surface."
        ),
    },
    "4.3": {
        "title": "Ensure SQL server's TDE protector is encrypted with Customer-managed key",
        "category": "Database Services",
        "description": (
            "Using CMK for Transparent Data Encryption gives "
            "organisations control over the encryption lifecycle."
        ),
    },
    "4.4": {
        "title": "Ensure that Azure Active Directory Admin is configured for SQL servers",
        "category": "Database Services",
        "description": (
            "Configuring an Azure AD administrator for SQL Server "
            "enables centralised identity management and MFA."
        ),
    },

    # ── Logging and Monitoring ────────────────────────────────────────────
    "5.1": {
        "title": "Ensure that a 'Diagnostic Setting' exists for subscription activity logs",
        "category": "Logging and Monitoring",
        "description": (
            "Diagnostic settings export the Activity Log to a "
            "destination where it can be queried and retained."
        ),
    },
    "5.2": {
        "title": "Ensure Diagnostic Setting captures appropriate categories",
        "category": "Logging and Monitoring",
        "description": (
            "Diagnostic settings should capture Administrative, "
            "Security, Alert, and Policy categories at minimum."
        ),
    },
    "5.3": {
        "title": "Ensure the storage account containing Activity Log data is encrypted with BYOK",
        "category": "Logging and Monitoring",
        "description": (
            "Encrypting the log storage account with a "
            "customer-managed key ensures audit data confidentiality."
        ),
    },
    "5.4": {
        "title": "Ensure that Activity Log Alert exists for Create or Update Network Security Group",
        "category": "Logging and Monitoring",
        "description": (
            "Alert rules on NSG changes help detect unexpected "
            "network exposure in near real-time."
        ),
    },

    # ── Networking ────────────────────────────────────────────────────────
    "6.1": {
        "title": "Ensure that RDP access is restricted from the internet",
        "category": "Networking",
        "description": (
            "NSG rules should not allow inbound RDP (3389) or SSH (22) "
            "from 0.0.0.0/0 or the Internet service tag."
        ),
    },
    "6.2": {
        "title": "Ensure that SSH access is restricted from the internet",
        "category": "Networking",
        "description": (
            "Unrestricted SSH access exposes VMs to brute-force "
            "and credential-stuffing attacks."
        ),
    },
    "6.3": {
        "title": "Ensure no SQL Databases allow ingress from 0.0.0.0/0",
        "category": "Networking",
        "description": (
            "Database firewall rules should not permit connections "
            "from any IP address."
        ),
    },
    "6.4": {
        "title": "Ensure that public IP addresses are evaluated on a regular basis",
        "category": "Networking",
        "description": (
            "Public IPs increase the attack surface. They should be "
            "reviewed and removed when not required."
        ),
    },
    "6.5": {
        "title": "Ensure that Network Watcher is enabled",
        "category": "Networking",
        "description": (
            "Network Watcher provides monitoring, diagnostics, and "
            "analytics for Azure virtual networks."
        ),
    },

    # ── Virtual Machines ──────────────────────────────────────────────────
    "7.1": {
        "title": "Ensure Virtual Machines are utilizing managed disks",
        "category": "Virtual Machines",
        "description": (
            "Managed disks provide built-in encryption, RBAC, and "
            "higher availability compared to unmanaged disks."
        ),
    },
    "7.2": {
        "title": "Ensure that OS and Data disks are encrypted with CMK",
        "category": "Virtual Machines",
        "description": (
            "Customer-managed keys for disk encryption give full "
            "control over the encryption key lifecycle."
        ),
    },
    "7.3": {
        "title": "Ensure that 'Unattached disks' are encrypted with CMK",
        "category": "Virtual Machines",
        "description": (
            "Unattached disks still contain data and should be "
            "encrypted to prevent exposure if accessed directly."
        ),
    },
    "7.4": {
        "title": "Ensure that only approved VM extensions are installed",
        "category": "Virtual Machines",
        "description": (
            "VM extensions run with high privileges. Only approved "
            "and necessary extensions should be deployed."
        ),
    },

    # ── Key Vault ─────────────────────────────────────────────────────────
    "8.1": {
        "title": "Ensure that the expiration date is set on all keys and secrets",
        "category": "Key Vault",
        "description": (
            "Setting expiration dates on keys and secrets enforces "
            "rotation and reduces risk of stale credentials."
        ),
    },
    "8.2": {
        "title": "Ensure that the expiration date is set on all certificates",
        "category": "Key Vault",
        "description": (
            "Certificate expiration tracking prevents outages caused "
            "by expired TLS/SSL certificates."
        ),
    },
    "8.3": {
        "title": "Ensure that Key Vault is recoverable",
        "category": "Key Vault",
        "description": (
            "Enabling soft-delete and purge protection ensures "
            "accidental or malicious deletion can be reversed."
        ),
    },
    "8.4": {
        "title": "Ensure that soft delete is enabled for Key Vault",
        "category": "Key Vault",
        "description": (
            "Soft delete preserves deleted vaults and vault objects "
            "for a configurable retention period."
        ),
    },
    "8.5": {
        "title": "Ensure that purge protection is enabled for Key Vault",
        "category": "Key Vault",
        "description": (
            "Purge protection prevents permanent deletion of "
            "soft-deleted vaults and their contents."
        ),
    },

    # ── AppService ────────────────────────────────────────────────────────
    "9.1": {
        "title": "Ensure App Service Authentication is set up for apps in Azure App Service",
        "category": "AppService",
        "description": (
            "Built-in authentication (Easy Auth) provides identity "
            "verification without additional application code."
        ),
    },
    "9.2": {
        "title": "Ensure web app redirects all HTTP traffic to HTTPS",
        "category": "AppService",
        "description": (
            "Redirecting HTTP to HTTPS ensures all client "
            "communication is encrypted in transit."
        ),
    },
    "9.3": {
        "title": "Ensure web app is using the latest version of TLS encryption",
        "category": "AppService",
        "description": (
            "Using TLS 1.2 or higher prevents exploitation of "
            "known weaknesses in older TLS versions."
        ),
    },
    "9.4": {
        "title": "Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On'",
        "category": "AppService",
        "description": (
            "Requiring client certificates adds mutual TLS "
            "authentication for stronger identity assurance."
        ),
    },
}

# ---------------------------------------------------------------------------
# NIST SP 800-53 Rev. 5 – Azure-relevant subset
# At least 25 controls across the required families.
# ---------------------------------------------------------------------------
NIST_CONTROLS: dict[str, dict] = {
    # ── Access Control (AC) ───────────────────────────────────────────────
    "AC-2": {
        "title": "Account Management",
        "family": "Access Control",
        "description": (
            "Manage system accounts including creating, enabling, "
            "modifying, disabling, and removing accounts in "
            "accordance with organisational policy."
        ),
    },
    "AC-3": {
        "title": "Access Enforcement",
        "family": "Access Control",
        "description": (
            "Enforce approved authorisations for logical access to "
            "information and system resources."
        ),
    },
    "AC-4": {
        "title": "Information Flow Enforcement",
        "family": "Access Control",
        "description": (
            "Enforce approved authorisations for controlling the flow "
            "of information within the system and between systems."
        ),
    },
    "AC-5": {
        "title": "Separation of Duties",
        "family": "Access Control",
        "description": (
            "Define and enforce separation of duties to prevent any "
            "single individual from controlling all critical functions."
        ),
    },
    "AC-6": {
        "title": "Least Privilege",
        "family": "Access Control",
        "description": (
            "Employ the principle of least privilege, allowing only "
            "the minimum access necessary for users and processes."
        ),
    },
    "AC-7": {
        "title": "Unsuccessful Logon Attempts",
        "family": "Access Control",
        "description": (
            "Enforce a limit on consecutive invalid logon attempts "
            "and take defined actions when the threshold is reached."
        ),
    },
    "AC-17": {
        "title": "Remote Access",
        "family": "Access Control",
        "description": (
            "Establish usage restrictions and implementation guidance "
            "for each type of remote access allowed."
        ),
    },

    # ── Audit and Accountability (AU) ─────────────────────────────────────
    "AU-2": {
        "title": "Event Logging",
        "family": "Audit and Accountability",
        "description": (
            "Identify events that the system must be capable of "
            "logging in support of the audit function."
        ),
    },
    "AU-3": {
        "title": "Content of Audit Records",
        "family": "Audit and Accountability",
        "description": (
            "Ensure audit records contain sufficient information to "
            "establish what occurred, when, where, and who was "
            "involved."
        ),
    },
    "AU-6": {
        "title": "Audit Record Review, Analysis, and Reporting",
        "family": "Audit and Accountability",
        "description": (
            "Review and analyse audit records for indications of "
            "inappropriate or unusual activity and report findings."
        ),
    },
    "AU-12": {
        "title": "Audit Record Generation",
        "family": "Audit and Accountability",
        "description": (
            "Provide audit record generation capability for the "
            "events identified in AU-2 at all required components."
        ),
    },

    # ── System and Communications Protection (SC) ─────────────────────────
    "SC-7": {
        "title": "Boundary Protection",
        "family": "System and Communications Protection",
        "description": (
            "Monitor and control communications at the external and "
            "key internal boundaries of the system."
        ),
    },
    "SC-8": {
        "title": "Transmission Confidentiality and Integrity",
        "family": "System and Communications Protection",
        "description": (
            "Protect the confidentiality and integrity of transmitted "
            "information using cryptographic mechanisms."
        ),
    },
    "SC-12": {
        "title": "Cryptographic Key Establishment and Management",
        "family": "System and Communications Protection",
        "description": (
            "Establish and manage cryptographic keys using approved "
            "key management technology and processes."
        ),
    },
    "SC-13": {
        "title": "Cryptographic Protection",
        "family": "System and Communications Protection",
        "description": (
            "Implement FIPS-validated or NSA-approved cryptography "
            "in accordance with applicable laws and policies."
        ),
    },
    "SC-28": {
        "title": "Protection of Information at Rest",
        "family": "System and Communications Protection",
        "description": (
            "Protect the confidentiality and integrity of "
            "information at rest using encryption or other means."
        ),
    },

    # ── System and Information Integrity (SI) ─────────────────────────────
    "SI-2": {
        "title": "Flaw Remediation",
        "family": "System and Information Integrity",
        "description": (
            "Identify, report, and correct system flaws in a timely "
            "manner, including software and firmware updates."
        ),
    },
    "SI-3": {
        "title": "Malicious Code Protection",
        "family": "System and Information Integrity",
        "description": (
            "Implement malicious code protection mechanisms at "
            "system entry and exit points and keep them up to date."
        ),
    },
    "SI-4": {
        "title": "System Monitoring",
        "family": "System and Information Integrity",
        "description": (
            "Monitor the system to detect attacks, indicators of "
            "potential attacks, and unauthorised connections."
        ),
    },
    "SI-5": {
        "title": "Security Alerts, Advisories, and Directives",
        "family": "System and Information Integrity",
        "description": (
            "Receive, generate, and disseminate security alerts and "
            "advisories to relevant personnel."
        ),
    },

    # ── Identification and Authentication (IA) ────────────────────────────
    "IA-2": {
        "title": "Identification and Authentication (Organizational Users)",
        "family": "Identification and Authentication",
        "description": (
            "Uniquely identify and authenticate organisational users "
            "or processes acting on behalf of users."
        ),
    },
    "IA-4": {
        "title": "Identifier Management",
        "family": "Identification and Authentication",
        "description": (
            "Manage system identifiers by receiving authorisation, "
            "assigning identifiers, and preventing reuse."
        ),
    },
    "IA-5": {
        "title": "Authenticator Management",
        "family": "Identification and Authentication",
        "description": (
            "Manage system authenticators (passwords, tokens, "
            "certificates) including initial distribution, lost or "
            "compromised credentials, and revocation."
        ),
    },

    # ── Configuration Management (CM) ─────────────────────────────────────
    "CM-2": {
        "title": "Baseline Configuration",
        "family": "Configuration Management",
        "description": (
            "Develop, document, and maintain a current baseline "
            "configuration of the information system."
        ),
    },
    "CM-6": {
        "title": "Configuration Settings",
        "family": "Configuration Management",
        "description": (
            "Establish and document mandatory configuration settings "
            "for IT products using security configuration checklists."
        ),
    },
    "CM-7": {
        "title": "Least Functionality",
        "family": "Configuration Management",
        "description": (
            "Configure the system to provide only essential "
            "capabilities and prohibit or restrict the use of "
            "unnecessary functions, ports, and services."
        ),
    },
    "CM-8": {
        "title": "System Component Inventory",
        "family": "Configuration Management",
        "description": (
            "Develop and maintain an inventory of system components "
            "that is accurate, current, and includes all components "
            "within the authorisation boundary."
        ),
    },

    # ── Contingency Planning (CP) – relevant to key vault / backup ────────
    "CP-9": {
        "title": "System Backup",
        "family": "Contingency Planning",
        "description": (
            "Conduct backups of system-level and user-level "
            "information at a defined frequency and protect backup "
            "confidentiality, integrity, and availability."
        ),
    },
}


def get_control_info(framework: str, control_id: str) -> dict | None:
    """
    Get control metadata (title, category/family, description) by framework
    and ID.

    Args:
        framework: "cis_azure" or "nist"
        control_id: The control identifier (e.g. "1.1", "AC-2")

    Returns:
        Dict with title, category/family, and description, or None if not
        found.
    """
    if framework == "cis_azure":
        return CIS_AZURE_CONTROLS.get(control_id)
    if framework == "nist":
        return NIST_CONTROLS.get(control_id)
    return None
