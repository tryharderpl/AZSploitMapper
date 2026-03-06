"""
Full benchmark control definitions for compliance mapping.

Contains the complete set of controls from:
- CIS Microsoft Azure Foundations Benchmark v2.1.0
- NIST SP 800-53 Rev. 5 (Azure-relevant subset)
- PCI DSS v4.0.1 (Azure-relevant controls for financial industry)

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


# ---------------------------------------------------------------------------
# PCI DSS v4.0.1 – Azure-relevant controls for financial industry
# Covers all 12 principal requirements with focus on cloud infrastructure.
# ---------------------------------------------------------------------------
PCI_DSS_CONTROLS: dict[str, dict] = {
    # ── Requirement 1: Install and Maintain Network Security Controls ──────
    "1.2.1": {
        "title": "Network security controls (NSCs) configuration is defined, documented, and maintained",
        "category": "Req 1: Network Security Controls",
        "description": (
            "NSCs (firewalls, cloud security groups, etc.) must be configured "
            "per documented standards. All rules should follow least-privilege "
            "and deny-all-by-default principles."
        ),
    },
    "1.3.1": {
        "title": "Inbound traffic to the CDE is restricted to only necessary traffic",
        "category": "Req 1: Network Security Controls",
        "description": (
            "All inbound traffic to the cardholder data environment must be "
            "evaluated and only traffic with an authorized business purpose "
            "should be allowed. All other traffic must be denied."
        ),
    },
    "1.3.2": {
        "title": "Outbound traffic from the CDE is restricted to only necessary traffic",
        "category": "Req 1: Network Security Controls",
        "description": (
            "Outbound traffic from the CDE should be limited to what is "
            "necessary for business operations. All other traffic must be "
            "explicitly denied."
        ),
    },
    "1.4.1": {
        "title": "NSCs are implemented between trusted and untrusted networks",
        "category": "Req 1: Network Security Controls",
        "description": (
            "Network security controls must be placed between any trusted "
            "network and any untrusted network, including the internet and "
            "cloud-based public endpoints."
        ),
    },
    "1.4.2": {
        "title": "Inbound traffic from untrusted networks is restricted to system components that provide publicly accessible services",
        "category": "Req 1: Network Security Controls",
        "description": (
            "Only system components providing authorized, publicly accessible "
            "services should be directly reachable from untrusted networks. "
            "Other components must be isolated."
        ),
    },

    # ── Requirement 2: Apply Secure Configurations ─────────────────────────
    "2.2.1": {
        "title": "Configuration standards are developed, implemented, and maintained for all system components",
        "category": "Req 2: Secure Configurations",
        "description": (
            "Configuration standards must address known security vulnerabilities "
            "and be consistent with industry-accepted system hardening standards "
            "(CIS, NIST, etc.)."
        ),
    },
    "2.2.2": {
        "title": "Vendor default accounts are managed appropriately",
        "category": "Req 2: Secure Configurations",
        "description": (
            "Default accounts (including Azure service defaults) must be "
            "removed, disabled, or changed before deploying a system in "
            "production."
        ),
    },
    "2.2.4": {
        "title": "Only necessary services, protocols, daemons, and functions are enabled",
        "category": "Req 2: Secure Configurations",
        "description": (
            "All unnecessary functionality must be removed or disabled. "
            "Only protocols and services with a documented business "
            "justification should be enabled."
        ),
    },
    "2.2.7": {
        "title": "All non-console administrative access is encrypted using strong cryptography",
        "category": "Req 2: Secure Configurations",
        "description": (
            "Management access to cloud infrastructure (SSH, RDP, Azure Portal) "
            "must use strong encryption protocols (TLS 1.2+) to prevent "
            "credential interception."
        ),
    },

    # ── Requirement 3: Protect Stored Account Data ─────────────────────────
    "3.4.1": {
        "title": "PAN is secured with strong cryptography wherever it is stored",
        "category": "Req 3: Protect Stored Data",
        "description": (
            "All stored cardholder data must be protected using strong "
            "cryptographic methods. Key Vaults must be recoverable "
            "(soft delete and purge protection enabled)."
        ),
    },
    "3.5.1": {
        "title": "PAN is rendered unreadable anywhere it is stored using strong cryptography",
        "category": "Req 3: Protect Stored Data",
        "description": (
            "Disk encryption (at rest) must be enabled on all storage "
            "media including VM disks and storage accounts. "
            "Customer-managed keys provide additional control."
        ),
    },
    "3.5.1.2": {
        "title": "Disk-level or partition-level cryptography is used to render PAN unreadable",
        "category": "Req 3: Protect Stored Data",
        "description": (
            "If disk-level encryption is the only method used to protect "
            "stored PAN, it must use a mechanism separate from the "
            "native operating system encryption."
        ),
    },
    "3.6.1": {
        "title": "Procedures are defined and implemented to protect cryptographic keys used for data protection",
        "category": "Req 3: Protect Stored Data",
        "description": (
            "Cryptographic key management procedures must include "
            "key generation, distribution, storage, rotation, and "
            "destruction. Key Vaults are the recommended method in Azure."
        ),
    },
    "3.6.1.1": {
        "title": "Additional requirement for service providers: A documented description of the cryptographic architecture is maintained",
        "category": "Req 3: Protect Stored Data",
        "description": (
            "Service providers must document their cryptographic "
            "architecture including algorithms, key lengths, key custodians, "
            "and key management lifecycle."
        ),
    },

    # ── Requirement 4: Protect Data with Strong Cryptography in Transit ────
    "4.2.1": {
        "title": "Strong cryptography and security protocols are implemented to safeguard PAN during transmission over open, public networks",
        "category": "Req 4: Encrypt Transmissions",
        "description": (
            "Only trusted keys/certificates and secure protocol versions "
            "must be used. TLS 1.2 or higher is required. SSL and early "
            "TLS (1.0, 1.1) must not be used as a security control."
        ),
    },
    "4.2.1.1": {
        "title": "An inventory of trusted keys and certificates used to protect PAN during transmission is maintained",
        "category": "Req 4: Encrypt Transmissions",
        "description": (
            "An inventory of all trusted keys and certificates is "
            "maintained and updated, including their purpose, owner, "
            "and expiration dates."
        ),
    },
    "4.2.2": {
        "title": "PAN is secured with strong cryptography whenever it is sent via end-user messaging technologies",
        "category": "Req 4: Encrypt Transmissions",
        "description": (
            "If cardholder data is transmitted via messaging (email, "
            "instant messaging, SMS), it must be encrypted using strong "
            "cryptography before transmission."
        ),
    },

    # ── Requirement 5: Protect All Systems from Malicious Software ─────────
    "5.2.1": {
        "title": "An anti-malware solution is deployed on all system components that are commonly affected by malicious software",
        "category": "Req 5: Malware Protection",
        "description": (
            "All system components (including VMs and containers) must "
            "have anti-malware solutions deployed and active. Microsoft "
            "Defender for Cloud provides this for Azure workloads."
        ),
    },
    "5.2.2": {
        "title": "The deployed anti-malware solution detects all known types of malware",
        "category": "Req 5: Malware Protection",
        "description": (
            "Anti-malware solutions must detect viruses, trojans, "
            "ransomware, spyware, adware, rootkits, and other "
            "malicious software categories."
        ),
    },
    "5.3.1": {
        "title": "The anti-malware solution is kept current via automatic updates",
        "category": "Req 5: Malware Protection",
        "description": (
            "Anti-malware definitions and engines must be kept up to "
            "date through automatic updates to detect the latest threats."
        ),
    },

    # ── Requirement 6: Develop and Maintain Secure Systems ─────────────────
    "6.3.1": {
        "title": "Security vulnerabilities are identified and managed through a defined process",
        "category": "Req 6: Secure Systems & Software",
        "description": (
            "A process must exist to identify and rank security "
            "vulnerabilities using industry sources (NVD, vendor "
            "advisories) and assign risk rankings."
        ),
    },
    "6.3.3": {
        "title": "All system components are protected from known vulnerabilities by installing applicable security patches/updates",
        "category": "Req 6: Secure Systems & Software",
        "description": (
            "Critical and high security patches must be installed "
            "within one month of release. Azure Update Manager can "
            "automate this for VM workloads."
        ),
    },
    "6.4.1": {
        "title": "For public-facing web applications, new threats and vulnerabilities are addressed on an ongoing basis",
        "category": "Req 6: Secure Systems & Software",
        "description": (
            "Public-facing web applications must be reviewed using "
            "manual or automated vulnerability assessment tools "
            "at least annually and after significant changes."
        ),
    },

    # ── Requirement 7: Restrict Access to System Components ────────────────
    "7.2.1": {
        "title": "An access control model is defined and includes granting access based on business needs",
        "category": "Req 7: Restrict Access",
        "description": (
            "Access to system components and cardholder data must "
            "be limited to individuals whose jobs require such access. "
            "Azure RBAC must implement least privilege."
        ),
    },
    "7.2.2": {
        "title": "Access is assigned to users based on job classification and function",
        "category": "Req 7: Restrict Access",
        "description": (
            "Role assignments must match job responsibilities. "
            "Overly broad roles like Contributor or Owner should "
            "be replaced with specific, scoped roles."
        ),
    },
    "7.2.5": {
        "title": "All application and system accounts and related access privileges are assigned and managed appropriately",
        "category": "Req 7: Restrict Access",
        "description": (
            "Application accounts (managed identities, service principals) "
            "must follow least privilege. Broad-scope subscription-level "
            "assignments must be avoided."
        ),
    },
    "7.2.6": {
        "title": "All user access to query repositories of stored cardholder data is restricted per the access control model",
        "category": "Req 7: Restrict Access",
        "description": (
            "Access to databases and storage containing cardholder data "
            "must be restricted. Key Vault access policies must follow "
            "the principle of least privilege."
        ),
    },

    # ── Requirement 8: Identify Users and Authenticate Access ──────────────
    "8.2.1": {
        "title": "All users are assigned a unique ID before access to system components or cardholder data is allowed",
        "category": "Req 8: User Identification & Auth",
        "description": (
            "Unique user identification ensures accountability. "
            "Shared or generic accounts must not be used for "
            "administrative access."
        ),
    },
    "8.3.1": {
        "title": "All user access to system components is authenticated via at least one authentication factor",
        "category": "Req 8: User Identification & Auth",
        "description": (
            "Authentication must use at least one factor: something "
            "you know (password), have (token/key), or are (biometric). "
            "SSH key authentication is preferred over passwords."
        ),
    },
    "8.3.2": {
        "title": "Strong cryptography is used to render all authentication factors unreadable during transmission and storage",
        "category": "Req 8: User Identification & Auth",
        "description": (
            "Authentication credentials must be encrypted both in "
            "transit and at rest. Password-based SSH discloses "
            "credentials over the network without key exchange."
        ),
    },
    "8.6.1": {
        "title": "If accounts used by systems or applications can be used for interactive login, they are managed as follows: interactive use is prevented unless needed",
        "category": "Req 8: User Identification & Auth",
        "description": (
            "Service accounts and managed identities with no recent "
            "activity should be reviewed and removed to reduce the "
            "attack surface."
        ),
    },

    # ── Requirement 9: Restrict Physical Access ────────────────────────────
    "9.4.1": {
        "title": "All media with cardholder data is physically secured",
        "category": "Req 9: Physical Access",
        "description": (
            "In cloud environments, this maps to ensuring storage "
            "accounts and disks are encrypted at rest and access "
            "is restricted to authorized principals only."
        ),
    },

    # ── Requirement 10: Log and Monitor All Access ─────────────────────────
    "10.2.1": {
        "title": "Audit logs are enabled and active for all system components and cardholder data",
        "category": "Req 10: Logging & Monitoring",
        "description": (
            "Audit logging must be enabled for all system components. "
            "In Azure, Diagnostic Settings and Activity Logs must be "
            "configured to capture security-relevant events."
        ),
    },
    "10.2.2": {
        "title": "Audit logs record all defined events for each auditable event type",
        "category": "Req 10: Logging & Monitoring",
        "description": (
            "Logs must capture user identification, event type, date/time, "
            "success/failure, origination, and identity/name of affected "
            "resource or data."
        ),
    },
    "10.3.1": {
        "title": "Read access to audit logs is limited to those with a job-related need",
        "category": "Req 10: Logging & Monitoring",
        "description": (
            "Audit logs contain sensitive information and must be "
            "protected from unauthorized access and modification."
        ),
    },

    # ── Requirement 11: Test Security of Systems and Networks ──────────────
    "11.3.1": {
        "title": "Internal vulnerability scans are performed at least once every three months",
        "category": "Req 11: Security Testing",
        "description": (
            "Regular vulnerability scanning must be performed on all "
            "in-scope system components. High-risk vulnerabilities "
            "must be resolved and rescans conducted."
        ),
    },
    "11.3.2": {
        "title": "External vulnerability scans are performed at least once every three months",
        "category": "Req 11: Security Testing",
        "description": (
            "External scans must be performed by a PCI SSC Approved "
            "Scanning Vendor (ASV). All exploitable vulnerabilities "
            "must be resolved."
        ),
    },
    "11.4.1": {
        "title": "A penetration testing methodology is defined, documented, and implemented",
        "category": "Req 11: Security Testing",
        "description": (
            "Penetration testing must cover the CDE perimeter and "
            "critical systems. Tests must include both network-layer "
            "and application-layer testing."
        ),
    },

    # ── Requirement 12: Information Security Policies ──────────────────────
    "12.1.1": {
        "title": "An overall information security policy is established, published, maintained, and disseminated",
        "category": "Req 12: Security Policy",
        "description": (
            "The security policy must address all PCI DSS requirements, "
            "be reviewed at least annually, and updated when the "
            "environment changes."
        ),
    },
    "12.3.1": {
        "title": "Each PCI DSS requirement that provides flexibility for how frequently it is performed is supported by a targeted risk analysis",
        "category": "Req 12: Security Policy",
        "description": (
            "When PCI DSS allows periodic performance of an activity, "
            "the entity must document the frequency based on a risk "
            "analysis and demonstrate it is appropriate."
        ),
    },
    "12.5.2": {
        "title": "PCI DSS scope is documented and confirmed at least once every 12 months and upon significant changes",
        "category": "Req 12: Security Policy",
        "description": (
            "The entity must confirm accuracy of PCI DSS scope by "
            "identifying all locations and flows of account data and "
            "all connected systems."
        ),
    },
}


def get_control_info(framework: str, control_id: str) -> dict | None:
    """
    Get control metadata (title, category/family, description) by framework
    and ID.

    Args:
        framework: "cis_azure", "nist", or "pci_dss"
        control_id: The control identifier (e.g. "1.1", "AC-2", "1.3.1")

    Returns:
        Dict with title, category/family, and description, or None if not
        found.
    """
    if framework == "cis_azure":
        return CIS_AZURE_CONTROLS.get(control_id)
    if framework == "nist":
        return NIST_CONTROLS.get(control_id)
    if framework == "pci_dss":
        return PCI_DSS_CONTROLS.get(control_id)
    return None
