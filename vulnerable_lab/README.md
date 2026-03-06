# Vulnerable Lab -- Test Environment for AZSploitMapper

This directory contains a Terraform configuration that deploys **intentionally vulnerable**
Azure resources. Use it as a test target for AZSploitMapper so you can see how the scanner
detects misconfigurations and visualizes attack paths.

**WARNING: These resources are intentionally insecure. Deploy them ONLY in a test/lab
subscription. Destroy them immediately after testing. Never use this in production.**

## What Gets Created

The Terraform code creates the following resources in Azure:

| Resource | Name | What it is |
|----------|------|------------|
| Resource Group | `rg-vulnerable-lab` | Container for all lab resources |
| Virtual Network | `vnet-vulnerable-lab` | Private network (10.0.0.0/16) |
| Subnet | `subnet-lab` | Subnet inside the VNet (10.0.1.0/24) |
| Network Security Group | `nsg-allow-all` | Firewall that allows ALL inbound traffic |
| Public IP | `pip-vulnerable-vm` | Static public IP address |
| Virtual Machine | `vm-vulnerable-lab` | Ubuntu 22.04 VM with managed identity |
| Storage Account | `stvulnlab<random>` | Storage with public blob access enabled |
| Storage Container | `sensitive-data` | Container with public read access |
| Blob | `database-credentials.txt` | Fake credentials file (exposed publicly) |
| Role Assignment | Storage Blob Data Reader | VM identity can read all blobs |

## Vulnerabilities (by design)

The lab contains **4 intentional security misconfigurations** that create a realistic attack path:

### Vulnerability #1: Network Security Group -- ALL ports open

The NSG allows all inbound traffic from any source to any destination on any port.
An attacker can scan all 65535 ports and connect to any running service.

### Vulnerability #2: VM with Managed Identity exposed to the internet

The VM has a public IP and a System-Assigned Managed Identity. By itself, managed identity
is good practice. But combined with the open NSG and the role assignment below, it becomes
an attack path: anyone who compromises the VM inherits its Azure permissions.

### Vulnerability #3: Storage Account with public blob access

The storage account allows public blob access and the container is set to `blob` access level.
Anyone who knows the blob URL can download the files without authentication.
The TLS minimum version is set to 1.0 (insecure).

### Vulnerability #4: Role Assignment -- the attack path link

The VM's managed identity has `Storage Blob Data Reader` role on the storage account.
This is the critical link that creates the full attack path:

```
Internet --> Open NSG --> VM (public IP) --> Managed Identity --> Storage Account --> database-credentials.txt
```

An attacker who compromises the VM can use the managed identity to get an access token
from the Azure Instance Metadata Service (IMDS at 169.254.169.254) and read all blobs
in the storage account -- without knowing any Azure credentials.

## Prerequisites

- **Azure subscription** (free tier works)
- **Azure CLI** installed and logged in (`az login`)
- **Terraform** installed (v1.0+)

If you do not have Terraform installed:

```bash
# macOS (Homebrew)
brew install terraform

# Verify
terraform --version
```

## Step 1: Log in to Azure

```bash
az login
```

This opens your browser for Microsoft authentication. After logging in,
verify you are using the correct subscription:

```bash
az account show --query name --output tsv
```

## Step 2: Initialize Terraform

```bash
cd vulnerable_lab

terraform init
```

This downloads the Azure provider plugin. You should see
"Terraform has been successfully initialized!"

## Step 3: Preview what will be created

```bash
terraform plan -out=vulnlab.tfplan
```

Review the output. You should see approximately 11 resources to be created.
Make sure the subscription and region are correct.

## Step 4: Deploy the vulnerable infrastructure

```bash
terraform apply vulnlab.tfplan
```

Wait for the deployment to complete (usually 2-5 minutes). When it finishes,
Terraform displays the outputs:

- `vm_public_ip` -- the public IP of the vulnerable VM
- `storage_account_name` -- the name of the storage account
- `sensitive_blob_url` -- direct URL to the exposed credentials file
- `attack_path_summary` -- the full attack chain

## Step 5: Verify the attack path works

To prove the attack path is real, SSH into the VM and use its managed identity
to access the storage account:

```bash
# SSH into the vulnerable VM (replace <VM_PUBLIC_IP> with the actual IP from output)
ssh labadmin@<VM_PUBLIC_IP>
# Password: VulnLab@2025!
```

Once on the VM, run these commands:

```bash
# Get an access token using the VM's managed identity.
# 169.254.169.254 is Azure's Instance Metadata Service (IMDS) --
# a special endpoint available inside every Azure VM that provides
# access tokens without any credentials.
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# List blobs in the sensitive-data container
# (replace <STORAGE_ACCOUNT_NAME> with actual name from Terraform output)
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "x-ms-version: 2020-10-02" \
  "https://<STORAGE_ACCOUNT_NAME>.blob.core.windows.net/sensitive-data?restype=container&comp=list"

# Download the sensitive file
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "x-ms-version: 2020-10-02" \
  "https://<STORAGE_ACCOUNT_NAME>.blob.core.windows.net/sensitive-data/database-credentials.txt"
```

You should see the content of `database-credentials.txt` in the terminal.
This proves that anyone who compromises the VM can access the storage account
through the managed identity -- without knowing any Azure passwords.

Type `exit` to disconnect from the VM.

## Step 6: Scan with AZSploitMapper

Now use AZSploitMapper to detect these misconfigurations:

```bash
# Go back to the AZSploitMapper project root
cd ..

# Make sure your .env has the correct AZURE_SUBSCRIPTION_ID
# (the same subscription where you deployed the vulnerable lab)

# Start the dashboard
python -m azsploitmapper serve
```

Open `https://localhost:8443` and click **EXECUTE SCAN**. AZSploitMapper will:

1. Discover the VM, NSG, Public IP, Storage Account, and Managed Identity
2. Detect the misconfigurations (open NSG, public storage, weak TLS, etc.)
3. Build an attack graph showing the path from Internet to the credentials file
4. Map findings to CIS Azure Benchmark and NIST SP 800-53 controls

## Step 7: Clean up -- IMPORTANT

When you are done testing, **destroy all resources** to avoid charges:

```bash
cd vulnerable_lab

terraform destroy
```

Type `yes` to confirm. This deletes everything in the `rg-vulnerable-lab` resource group.

Verify nothing is left:

```bash
az group list --output table
```

You should NOT see `rg-vulnerable-lab` in the output.

## .gitignore

The following files are generated locally and should never be committed:

- `.terraform/` -- provider plugins (downloaded by `terraform init`)
- `.terraform.lock.hcl` -- provider version lock file
- `terraform.tfstate` -- contains resource IDs and sensitive outputs
- `terraform.tfstate.backup` -- backup of previous state
- `*.tfplan` -- plan files may contain sensitive values

These are already excluded by the project's root `.gitignore`.
