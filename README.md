# \# AWS Security Scanner

# 

# !\[CI](https://github.com/Sumanth718/aws-security-scanner/actions/workflows/ci.yml/badge.svg)

# !\[Python](https://img.shields.io/badge/python-3.10%2B-blue)

# !\[License](https://img.shields.io/badge/license-MIT-green)

# 

# A Python-based AWS security auditing tool that identifies common cloud security misconfigurations and maps applicable findings to the \*\*CIS AWS Foundations Benchmark v3.0\*\*.

# 

# The scanner provides 21 read-only security checks across IAM, S3, EC2, VPC, CloudTrail, GuardDuty, and IAM Access Analyzer. It calculates a severity-weighted security score and generates HTML, JSON, and CSV reports with remediation guidance.

# 

# \*\*No AWS account or credentials are required to try the built-in demo mode.\*\*

# 

# \## Table of Contents

# 

# \- \[Features](#features)

# \- \[Sample Report](#sample-report)

# \- \[Security Checks](#security-checks)

# \- \[Quick Start](#quick-start)

# \- \[Example Output](#example-output)

# \- \[Scanning a Real AWS Account](#scanning-a-real-aws-account)

# \- \[Architecture](#architecture)

# \- \[Testing](#testing)

# \- \[Security Considerations and Limitations](#security-considerations-and-limitations)

# \- \[Roadmap](#roadmap)

# \- \[License](#license)

# 

# \## Features

# 

# \- 21 security checks for common AWS configuration risks.

# \- CIS AWS Foundations Benchmark v3.0 references where applicable.

# \- Severity levels: critical, high, medium, low, and informational.

# \- Severity-weighted security score.

# \- HTML, JSON, and CSV report generation.

# \- Built-in fake AWS environment for offline demonstrations.

# \- Configurable AWS regions and services.

# \- Read-only AWS API access.

# \- Error isolation so one failed check does not stop the entire scan.

# \- Automated linting and testing through GitHub Actions.

# \- Optional scheduled scans using GitHub Actions and AWS OIDC.

# 

# \## Sample Report

# 

# The HTML report presents security findings, severity levels, affected resources, and remediation guidance.

# 

# !\[Sample AWS security report](docs/report-screenshot.png)

# 

# If the screenshot is not available yet, add it to `docs/report-screenshot.png` or remove this image reference until the screenshot is ready.

# 

# \## Security Checks

# 

# \### Identity and Access Management (IAM)

# 

# | ID | Check | Severity | CIS Reference |

# |---|---|---|---|

# | IAM-001 | Root account has MFA enabled | Critical | 1.5 |

# | IAM-002 | Root account has no access keys | Critical | 1.4 |

# | IAM-003 | Console users have MFA | High | 1.10 |

# | IAM-004 | Active access keys rotated within 90 days | Medium | 1.14 |

# | IAM-005 | Password policy meets configured requirements | Medium | 1.8, 1.9 |

# | IAM-006 | Users receive permissions through groups | Medium | 1.15 |

# | IAM-007 | IAM Access Analyzer enabled | Low | 1.20 |

# 

# \### Simple Storage Service (S3)

# 

# | ID | Check | Severity | CIS Reference |

# |---|---|---|---|

# | S3-001 | Account-level Block Public Access enabled | High | 2.1.4 |

# | S3-002 | Bucket-level Block Public Access enabled | High | 2.1.4 |

# | S3-003 | Bucket ACL does not grant public access | Critical | — |

# | S3-004 | Bucket policy enforces HTTPS | Medium | 2.1.1 |

# | S3-005 | Bucket versioning enabled | Low | — |

# 

# \### Elastic Compute Cloud (EC2)

# 

# | ID | Check | Severity | CIS Reference |

# |---|---|---|---|

# | EC2-001 | Security groups do not expose SSH/RDP to the internet | High | 5.2, 5.3 |

# | EC2-002 | Default security groups have no rules | Medium | 5.4 |

# | EC2-003 | EBS encryption by default enabled | Medium | 2.2.1 |

# | EC2-004 | Instances require IMDSv2 | Medium | 5.6 |

# 

# \### Virtual Private Cloud (VPC)

# 

# | ID | Check | Severity | CIS Reference |

# |---|---|---|---|

# | VPC-001 | VPC flow logs enabled | Medium | 3.7 |

# 

# \### CloudTrail

# 

# | ID | Check | Severity | CIS Reference |

# |---|---|---|---|

# | CT-001 | Multi-region CloudTrail trail is logging | Critical | 3.1 |

# | CT-002 | CloudTrail log file validation enabled | Medium | 3.2 |

# | CT-003 | CloudTrail encrypted with KMS | Medium | 3.5 |

# 

# \### GuardDuty

# 

# | ID | Check | Severity | CIS Reference |

# |---|---|---|---|

# | GD-001 | GuardDuty enabled | High | — |

# 

# \*\*Note:\*\* CIS references are provided where applicable. Verify the precise benchmark version, recommendation IDs, and applicability before using the findings for a formal compliance assessment.

# 

# \## Quick Start

# 

# \### 1. Clone the repository

# 

# ```bash

# git clone https://github.com/Sumanth718/aws-security-scanner.git

# cd aws-security-scanner

# ```

# 

# \### 2. Create a virtual environment

# 

# \*\*Windows PowerShell:\*\*

# 

# ```powershell

# python -m venv .venv

# .venv\\Scripts\\Activate.ps1

# ```

# 

# \*\*macOS or Linux:\*\*

# 

# ```bash

# python -m venv .venv

# source .venv/bin/activate

# ```

# 

# \### 3. Install dependencies

# 

# ```bash

# python -m pip install -r requirements.txt

# ```

# 

# \### 4. Run the demo scan

# 

# ```bash

# python -m awsscan scan --demo

# ```

# 

# The demo uses fake AWS clients and does not require AWS credentials.

# 

# Generated reports are written to the configured output directory. The default is `reports/` if that is how the CLI is configured.

# 

# To list available checks:

# 

# ```bash

# python -m awsscan list-checks

# ```

# 

# \## Example Output

# 

# The following is illustrative demo output. Actual scores, findings, and resource identifiers depend on the demo implementation and selected checks.

# 

# ```text

# Account: demo account

# Security score: calculated by the scanner

# 

# Failed checks:

# &#x20; \[CRIT] IAM-002  Root access keys exist

# &#x20; \[CRIT] S3-003   Public grants detected

# &#x20; \[HIGH] EC2-001  SSH or RDP exposed to the internet

# &#x20; \[HIGH] GD-001   GuardDuty detector not enabled

# 

# Reports:

# &#x20; report.html

# &#x20; findings.json

# &#x20; findings.csv

# ```

# 

# The demo's account identifiers and resources are simulated. They do not represent a real AWS account.

# 

# \## Scanning a Real AWS Account

# 

# \*\*Important:\*\* Start with the demo mode before configuring access to a real account.

# 

# \### 1. Configure read-only permissions

# 

# Use the project's policy:

# 

# \[`iam-policy/awsscan-readonly.json`](iam-policy/awsscan-readonly.json)

# 

# Alternatively, AWS provides the managed `SecurityAudit` policy, which may grant additional permissions beyond those required by this scanner.

# 

# Review all permissions and account policies before scanning. Use a dedicated audit role and grant only the permissions necessary for your intended checks.

# 

# \### 2. Configure AWS credentials

# 

# Install and configure the AWS CLI if needed.

# 

# Using a named profile:

# 

# ```bash

# aws configure --profile audit

# ```

# 

# If your organization uses AWS IAM Identity Center:

# 

# ```bash

# aws sso login --profile audit

# ```

# 

# Never commit access keys, secret keys, session tokens, or private credential files to GitHub.

# 

# \### 3. Run the scanner

# 

# Scan selected regions:

# 

# ```bash

# python -m awsscan scan --profile audit --regions eu-west-3,us-east-1

# ```

# 

# Scan selected services:

# 

# ```bash

# python -m awsscan scan --profile audit --services s3,iam

# ```

# 

# Fail the command when high-severity findings are detected:

# 

# ```bash

# python -m awsscan scan --profile audit --fail-on high

# ```

# 

# List all available checks:

# 

# ```bash

# python -m awsscan list-checks

# ```

# 

# Use `python -m awsscan scan --help` to see the supported CLI options.

# 

# If a required AWS API call is denied, the scanner may record an error for that check while continuing with other checks. Review the resulting report to distinguish actual findings from checks that could not be completed.

# 

# \### Scheduled Scanning

# 

# An optional scheduled workflow is available at:

# 

# \[`examples/scheduled-scan.yml`](examples/scheduled-scan.yml)

# 

# It is designed to use GitHub Actions and AWS OIDC to assume an AWS role without storing long-lived AWS access keys in GitHub secrets.

# 

# Before enabling it, configure the required GitHub settings and AWS trust policy, and review the workflow permissions.

# 

# \## Architecture

# 

# ```mermaid

# flowchart LR

# &#x20;   CLI\[CLI] --> CTX\[ScanContext]

# &#x20;   CTX -->|AWS session| AWS\[(AWS APIs)]

# &#x20;   CTX -->|Demo mode| FAKE\[Fake AWS clients]

# &#x20;   REG\[Check registry] --> SCAN\[Scanner]

# &#x20;   CTX --> SCAN

# &#x20;   SCAN --> RES\[Findings and security score]

# &#x20;   RES --> HTML\[HTML report]

# &#x20;   RES --> JSON\[JSON report]

# &#x20;   RES --> CSV\[CSV report]

# ```

# 

# \### Design Principles

# 

# \- \*\*Centralized scanning:\*\* The scanner executes registered checks and collects their findings.

# \- \*\*Shared context:\*\* Checks obtain AWS clients through `ScanContext`, keeping AWS access separate from check logic.

# \- \*\*Testability:\*\* Fake AWS clients support repeatable offline tests without real AWS resources.

# \- \*\*Error isolation:\*\* Failures in individual checks are recorded instead of automatically terminating the entire scan.

# \- \*\*Actionable findings:\*\* Findings include severity and remediation information.

# \- \*\*Multiple output formats:\*\* HTML, JSON, and CSV reports support both human review and further processing.

# 

# \### Adding a Check

# 

# Checks are registered with metadata such as an identifier, title, service, severity, CIS reference, and remediation instructions.

# 

# The following is an illustrative example. Confirm that the decorator, result class, and function signatures match the current implementation before using it.

# 

# ```python

# @check(

# &#x20;   id="EC2-003",

# &#x20;   title="EBS encryption by default is enabled",

# &#x20;   service="ec2",

# &#x20;   severity="medium",

# &#x20;   cis="2.2.1",

# &#x20;   remediation="Enable EBS encryption by default in the affected region.",

# )

# def ebs\_default\_encryption(ctx, region):

# &#x20;   enabled = ctx.client(

# &#x20;       "ec2", region

# &#x20;   ).get\_ebs\_encryption\_by\_default()\["EbsEncryptionByDefault"]

# 

# &#x20;   yield Result(

# &#x20;       enabled,

# &#x20;       f"ebs-default/{region}",

# &#x20;       "Enabled" if enabled else "Disabled",

# &#x20;   )

# ```

# 

# \## Testing

# 

# Install development dependencies:

# 

# ```bash

# python -m pip install -r requirements-dev.txt

# ```

# 

# Run the test suite:

# 

# ```bash

# python -m pytest -v

# ```

# 

# Run Ruff lint checks:

# 

# ```bash

# python -m ruff check .

# ```

# 

# The test suite covers scanner behavior, filtering, reporting, CLI behavior, error handling, and IAM policy coverage.

# 

# GitHub Actions runs automated checks for Python 3.10 and Python 3.12.

# 

# See the \[GitHub Actions workflow](https://github.com/Sumanth718/aws-security-scanner/actions) for the latest results.

# 

# \## Security Considerations and Limitations

# 

# \- The scanner is a security auditing aid, not a guarantee that an AWS account is secure.

# \- It does not automatically remediate findings.

# \- A read-only role is recommended for real-account scans.

# \- Checks may report errors when permissions, services, or regional configurations prevent inspection.

# \- Passing a check does not prove that every related security control is correctly configured.

# \- Validate findings against current AWS documentation and the applicable CIS benchmark.

# \- Do not commit real AWS credentials or sensitive account information.

# \- Review the IAM policy and GitHub Actions permissions before using the scanner in production.

# 

# \## Roadmap

# 

# Potential future improvements include:

# 

# \- RDS public snapshot checks.

# \- KMS key rotation checks.

# \- Lambda public URL checks.

# \- Detection of unused IAM credentials.

# \- AWS Organizations multi-account scanning.

# \- AWS Security Hub findings integration using ASFF.

# 

# \## License

# 

# This project is distributed under the MIT License. See \[`LICENSE`](LICENSE).

