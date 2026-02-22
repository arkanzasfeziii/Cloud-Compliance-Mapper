#!/usr/bin/env python3
"""
Cloud Compliance Mapper
Author: arkanzasfeziii
License: MIT

A comprehensive compliance assessment tool for mapping cloud configurations
to NIST SP 800-53, ISO 27001, and CIS Benchmarks across AWS, Azure, and GCP.

WARNING: This tool requires valid cloud credentials and is for authorized
compliance auditing of your own accounts only. Results are indicative and not
a substitute for formal audits or certifications.
"""

# === Imports ===
import argparse
import csv
import json
import logging
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple

# Third-party imports (will be checked at runtime)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    from rich.markdown import Markdown
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# === Constants ===
VERSION = "1.0.0"
TOOL_NAME = "Cloud Compliance Mapper"
AUTHOR = "arkanzasfeziii"

# Compliance status levels
class ComplianceStatus(Enum):
    """Compliance status for controls."""
    COMPLIANT = "COMPLIANT"
    PARTIAL = "PARTIAL"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


# Risk severity levels
class RiskSeverity(Enum):
    """Risk severity for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Legal warning text
LEGAL_WARNING = """
⚠️  COMPLIANCE AUDIT WARNING ⚠️

This tool requires valid cloud credentials with read/list permissions across
multiple services and is designed for AUTHORIZED compliance auditing of YOUR
OWN cloud accounts ONLY.

IMPORTANT DISCLAIMERS:
1. Compliance results are INDICATIVE and NOT a substitute for formal audits
   or certifications by accredited bodies
2. This tool provides automated checks but cannot replace human judgment
3. Results should be validated by qualified security/compliance professionals
4. No guarantee of 100% coverage of all framework controls
5. Framework interpretations are based on best practices and may vary

LEGAL NOTICE:
- Scanning without authorization is ILLEGAL
- You must have explicit permission for all scanned accounts
- The author (arkanzasfeziii) assumes NO LIABILITY for:
  * Misuse of this tool
  * Reliance on compliance results
  * Any consequences of using this tool
  
Use responsibly and ethically!
"""

# Control family codes (NIST SP 800-53)
NIST_FAMILIES = {
    'AC': 'Access Control',
    'AU': 'Audit and Accountability',
    'AT': 'Awareness and Training',
    'CM': 'Configuration Management',
    'CP': 'Contingency Planning',
    'IA': 'Identification and Authentication',
    'IR': 'Incident Response',
    'MA': 'Maintenance',
    'MP': 'Media Protection',
    'PE': 'Physical and Environmental Protection',
    'PL': 'Planning',
    'PS': 'Personnel Security',
    'RA': 'Risk Assessment',
    'CA': 'Assessment, Authorization, and Monitoring',
    'SC': 'System and Communications Protection',
    'SI': 'System and Information Integrity',
    'SA': 'System and Services Acquisition'
}

# ISO 27001:2022 Annex A domains
ISO_DOMAINS = {
    'A.5': 'Organizational Controls',
    'A.6': 'People Controls',
    'A.7': 'Physical Controls',
    'A.8': 'Technological Controls'
}


# === Data Classes ===
@dataclass
class ControlMapping:
    """Represents a control mapping across frameworks."""
    control_id: str
    framework: str  # NIST, ISO, CIS
    title: str
    description: str
    family: str
    check_function: str  # Name of function to call
    severity: RiskSeverity = RiskSeverity.MEDIUM
    


@dataclass
class ComplianceResult:
    """Represents a compliance check result."""
    control_id: str
    framework: str
    control_title: str
    status: ComplianceStatus
    risk_severity: RiskSeverity
    evidence: Dict[str, Any]
    remediation: str
    references: List[str]
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    provider: str = ""
    resource_ids: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        data = asdict(self)
        data['status'] = self.status.value
        data['risk_severity'] = self.risk_severity.value
        return data


@dataclass
class ComplianceStats:
    """Statistics for a compliance assessment."""
    total_controls: int = 0
    compliant: int = 0
    partial: int = 0
    non_compliant: int = 0
    not_applicable: int = 0
    errors: int = 0
    compliance_score: float = 0.0
    by_framework: Dict[str, Dict[str, int]] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=lambda: {s.value: 0 for s in RiskSeverity})
    scan_duration: float = 0.0


# === Utility Functions ===
def setup_logging(verbose: bool = False, debug: bool = False) -> logging.Logger:
    """
    Configure logging for the application.
    
    Args:
        verbose: Enable verbose logging
        debug: Enable debug logging
        
    Returns:
        Configured logger instance
    """
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )
    
    return logging.getLogger('CloudComplianceMapper')


def create_console() -> Any:
    """
    Create a Rich console or fallback printer.
    
    Returns:
        Console instance or fallback object
    """
    if RICH_AVAILABLE:
        return Console()
    else:
        class FallbackConsole:
            def print(self, *args, **kwargs):
                print(*args)
            def log(self, *args, **kwargs):
                print(*args)
        return FallbackConsole()


def display_banner(console: Any) -> None:
    """Display tool banner."""
    if RICH_AVAILABLE:
        banner_text = f"""
# {TOOL_NAME}
**Version:** {VERSION} | **Author:** {AUTHOR}

Multi-cloud compliance mapper for NIST SP 800-53, ISO 27001, and CIS Benchmarks.
        """
        console.print(Panel(Markdown(banner_text), title="🔍 Compliance Mapper", border_style="blue"))
    else:
        print(f"\n{'='*70}")
        print(f"{TOOL_NAME}")
        print(f"Version: {VERSION} | Author: {AUTHOR}")
        print(f"{'='*70}\n")


def confirm_legal_acknowledgment(console: Any) -> bool:
    """
    Display legal warning and get user confirmation.
    
    Returns:
        True if user confirms, False otherwise
    """
    if RICH_AVAILABLE:
        console.print(Panel(LEGAL_WARNING, title="⚠️  WARNING", border_style="red"))
    else:
        print(f"\n{LEGAL_WARNING}")
    
    try:
        response = input("\nDo you understand and acknowledge these terms? (yes/no): ").strip().lower()
        return response == 'yes'
    except (EOFError, KeyboardInterrupt):
        return False


# === Control Mappings ===
class ControlMappingRegistry:
    """Registry of control mappings and checks."""
    
    def __init__(self):
        """Initialize the control mapping registry."""
        self.mappings: Dict[str, ControlMapping] = {}
        self._initialize_nist_controls()
        self._initialize_iso_controls()
        self._initialize_cis_controls()
    
    def _initialize_nist_controls(self) -> None:
        """Initialize NIST SP 800-53 Rev. 5 control mappings."""
        # Access Control
        self.mappings['NIST-AC-2'] = ControlMapping(
            control_id='AC-2',
            framework='NIST',
            title='Account Management',
            description='Manage system accounts including creation, modification, and removal',
            family='AC',
            check_function='check_account_management',
            severity=RiskSeverity.HIGH
        )
        
        self.mappings['NIST-AC-3'] = ControlMapping(
            control_id='AC-3',
            framework='NIST',
            title='Access Enforcement',
            description='Enforce approved authorizations for logical access',
            family='AC',
            check_function='check_access_enforcement',
            severity=RiskSeverity.HIGH
        )
        
        self.mappings['NIST-AC-17'] = ControlMapping(
            control_id='AC-17',
            framework='NIST',
            title='Remote Access',
            description='Authorize and monitor remote access',
            family='AC',
            check_function='check_remote_access',
            severity=RiskSeverity.MEDIUM
        )
        
        # Audit and Accountability
        self.mappings['NIST-AU-2'] = ControlMapping(
            control_id='AU-2',
            framework='NIST',
            title='Event Logging',
            description='Ensure the system logs relevant security events',
            family='AU',
            check_function='check_event_logging',
            severity=RiskSeverity.HIGH
        )
        
        self.mappings['NIST-AU-6'] = ControlMapping(
            control_id='AU-6',
            framework='NIST',
            title='Audit Record Review, Analysis, and Reporting',
            description='Review and analyze audit records for security-relevant events',
            family='AU',
            check_function='check_audit_review',
            severity=RiskSeverity.MEDIUM
        )
        
        # Identification and Authentication
        self.mappings['NIST-IA-2'] = ControlMapping(
            control_id='IA-2',
            framework='NIST',
            title='Identification and Authentication',
            description='Uniquely identify and authenticate users',
            family='IA',
            check_function='check_mfa_enabled',
            severity=RiskSeverity.CRITICAL
        )
        
        self.mappings['NIST-IA-5'] = ControlMapping(
            control_id='IA-5',
            framework='NIST',
            title='Authenticator Management',
            description='Manage system authenticators',
            family='IA',
            check_function='check_password_policy',
            severity=RiskSeverity.HIGH
        )
        
        # System and Communications Protection
        self.mappings['NIST-SC-7'] = ControlMapping(
            control_id='SC-7',
            framework='NIST',
            title='Boundary Protection',
            description='Monitor and control communications at external boundaries',
            family='SC',
            check_function='check_network_boundaries',
            severity=RiskSeverity.HIGH
        )
        
        self.mappings['NIST-SC-8'] = ControlMapping(
            control_id='SC-8',
            framework='NIST',
            title='Transmission Confidentiality and Integrity',
            description='Protect information confidentiality and integrity during transmission',
            family='SC',
            check_function='check_encryption_in_transit',
            severity=RiskSeverity.HIGH
        )
        
        self.mappings['NIST-SC-12'] = ControlMapping(
            control_id='SC-12',
            framework='NIST',
            title='Cryptographic Key Establishment and Management',
            description='Establish and manage cryptographic keys',
            family='SC',
            check_function='check_key_management',
            severity=RiskSeverity.HIGH
        )
        
        self.mappings['NIST-SC-13'] = ControlMapping(
            control_id='SC-13',
            framework='NIST',
            title='Cryptographic Protection',
            description='Implement FIPS-validated cryptography',
            family='SC',
            check_function='check_encryption_at_rest',
            severity=RiskSeverity.HIGH
        )
        
        # Configuration Management
        self.mappings['NIST-CM-2'] = ControlMapping(
            control_id='CM-2',
            framework='NIST',
            title='Baseline Configuration',
            description='Develop, document, and maintain baseline configurations',
            family='CM',
            check_function='check_config_management',
            severity=RiskSeverity.MEDIUM
        )
        
        self.mappings['NIST-CM-7'] = ControlMapping(
            control_id='CM-7',
            framework='NIST',
            title='Least Functionality',
            description='Configure systems to provide only essential capabilities',
            family='CM',
            check_function='check_least_functionality',
            severity=RiskSeverity.MEDIUM
        )
    
    def _initialize_iso_controls(self) -> None:
        """Initialize ISO 27001:2022 Annex A control mappings."""
        self.mappings['ISO-A.8.2'] = ControlMapping(
            control_id='A.8.2',
            framework='ISO',
            title='Privileged Access Rights',
            description='Allocation and use of privileged access rights should be restricted',
            family='A.8',
            check_function='check_privileged_access',
            severity=RiskSeverity.HIGH
        )
        
        self.mappings['ISO-A.8.3'] = ControlMapping(
            control_id='A.8.3',
            framework='ISO',
            title='Information Access Restriction',
            description='Access to information and systems should be restricted',
            family='A.8',
            check_function='check_access_restriction',
            severity=RiskSeverity.HIGH
        )
        
        self.mappings['ISO-A.8.5'] = ControlMapping(
            control_id='A.8.5',
            framework='ISO',
            title='Secure Authentication',
            description='Secure authentication technologies should be implemented',
            family='A.8',
            check_function='check_mfa_enabled',
            severity=RiskSeverity.CRITICAL
        )
        
        self.mappings['ISO-A.8.9'] = ControlMapping(
            control_id='A.8.9',
            framework='ISO',
            title='Configuration Management',
            description='Configurations should be documented and reviewed',
            family='A.8',
            check_function='check_config_management',
            severity=RiskSeverity.MEDIUM
        )
        
        self.mappings['ISO-A.8.24'] = ControlMapping(
            control_id='A.8.24',
            framework='ISO',
            title='Use of Cryptography',
            description='Rules for effective use of cryptography should be defined',
            family='A.8',
            check_function='check_encryption_usage',
            severity=RiskSeverity.HIGH
        )
    
    def _initialize_cis_controls(self) -> None:
        """Initialize CIS Benchmark control mappings."""
        # AWS CIS Foundations Benchmark
        self.mappings['CIS-AWS-1.12'] = ControlMapping(
            control_id='1.12',
            framework='CIS-AWS',
            title='Ensure MFA is enabled for root account',
            description='Root account should have MFA enabled',
            family='IAM',
            check_function='check_root_mfa_aws',
            severity=RiskSeverity.CRITICAL
        )
        
        self.mappings['CIS-AWS-2.1.1'] = ControlMapping(
            control_id='2.1.1',
            framework='CIS-AWS',
            title='Ensure S3 bucket encryption is enabled',
            description='S3 buckets should have default encryption',
            family='Storage',
            check_function='check_s3_encryption',
            severity=RiskSeverity.HIGH
        )
        
        self.mappings['CIS-AWS-3.1'] = ControlMapping(
            control_id='3.1',
            framework='CIS-AWS',
            title='Ensure CloudTrail is enabled in all regions',
            description='CloudTrail should be enabled globally',
            family='Logging',
            check_function='check_cloudtrail_enabled',
            severity=RiskSeverity.HIGH
        )
        
        # Azure CIS Benchmark
        self.mappings['CIS-AZURE-1.23'] = ControlMapping(
            control_id='1.23',
            framework='CIS-AZURE',
            title='Ensure MFA is enabled for all users',
            description='All users should have MFA enabled',
            family='Identity',
            check_function='check_mfa_enabled',
            severity=RiskSeverity.CRITICAL
        )
        
        self.mappings['CIS-AZURE-3.1'] = ControlMapping(
            control_id='3.1',
            framework='CIS-AZURE',
            title='Ensure storage account encryption is enabled',
            description='Storage accounts should use encryption',
            family='Storage',
            check_function='check_storage_encryption',
            severity=RiskSeverity.HIGH
        )
        
        # GCP CIS Benchmark
        self.mappings['CIS-GCP-1.1'] = ControlMapping(
            control_id='1.1',
            framework='CIS-GCP',
            title='Ensure corporate login credentials are used',
            description='Use corporate login instead of Gmail accounts',
            family='Identity',
            check_function='check_corporate_login',
            severity=RiskSeverity.MEDIUM
        )
        
        self.mappings['CIS-GCP-2.1'] = ControlMapping(
            control_id='2.1',
            framework='CIS-GCP',
            title='Ensure Cloud Audit Logging is configured',
            description='Cloud Audit Logs should be enabled',
            family='Logging',
            check_function='check_audit_logging_gcp',
            severity=RiskSeverity.HIGH
        )
    
    def get_controls_by_framework(self, framework: str) -> List[ControlMapping]:
        """Get all controls for a specific framework."""
        framework_upper = framework.upper()
        return [m for m in self.mappings.values() if m.framework.upper() == framework_upper or framework_upper == 'ALL']
    
    def get_controls_by_family(self, family: str) -> List[ControlMapping]:
        """Get all controls for a specific family."""
        return [m for m in self.mappings.values() if m.family.upper() == family.upper()]


# === Provider Clients ===
class AWSComplianceClient:
    """AWS compliance checking client."""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize AWS client."""
        self.logger = logger or logging.getLogger(__name__)
        self._boto3 = None
        self._iam_client = None
        self._s3_client = None
        self._cloudtrail_client = None
        self._ec2_client = None
    
    def _get_boto3(self):
        """Lazy import of boto3."""
        if self._boto3 is None:
            try:
                import boto3
                self._boto3 = boto3
            except ImportError:
                raise ImportError("boto3 is required for AWS support. Install with: pip install boto3")
        return self._boto3
    
    def _get_client(self, service: str):
        """Get or create AWS service client."""
        boto3 = self._get_boto3()
        return boto3.client(service)
    
    def check_root_mfa_aws(self) -> ComplianceResult:
        """Check if root account has MFA enabled."""
        try:
            iam = self._get_client('iam')
            
            # Get account summary
            summary = iam.get_account_summary()
            account_mfa_enabled = summary['SummaryMap'].get('AccountMFAEnabled', 0)
            
            status = ComplianceStatus.COMPLIANT if account_mfa_enabled == 1 else ComplianceStatus.NON_COMPLIANT
            severity = RiskSeverity.CRITICAL if status == ComplianceStatus.NON_COMPLIANT else RiskSeverity.INFO
            
            return ComplianceResult(
                control_id='CIS-AWS-1.12',
                framework='CIS-AWS',
                control_title='Root MFA Enabled',
                status=status,
                risk_severity=severity,
                evidence={'AccountMFAEnabled': account_mfa_enabled},
                remediation='Enable MFA for root account in IAM console',
                references=['https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html'],
                provider='aws'
            )
        except Exception as e:
            self.logger.error(f"Error checking root MFA: {e}")
            return self._error_result('CIS-AWS-1.12', str(e))
    
    def check_cloudtrail_enabled(self) -> ComplianceResult:
        """Check if CloudTrail is enabled in all regions."""
        try:
            cloudtrail = self._get_client('cloudtrail')
            
            trails = cloudtrail.describe_trails()['trailList']
            
            multi_region_trails = [t for t in trails if t.get('IsMultiRegionTrail', False)]
            logging_trails = []
            
            for trail in multi_region_trails:
                status = cloudtrail.get_trail_status(Name=trail['TrailARN'])
                if status.get('IsLogging', False):
                    logging_trails.append(trail['Name'])
            
            status = ComplianceStatus.COMPLIANT if logging_trails else ComplianceStatus.NON_COMPLIANT
            severity = RiskSeverity.HIGH if status == ComplianceStatus.NON_COMPLIANT else RiskSeverity.INFO
            
            return ComplianceResult(
                control_id='CIS-AWS-3.1',
                framework='CIS-AWS',
                control_title='CloudTrail Multi-Region Enabled',
                status=status,
                risk_severity=severity,
                evidence={
                    'multi_region_trails': len(multi_region_trails),
                    'logging_trails': logging_trails
                },
                remediation='Enable CloudTrail in all regions with logging enabled',
                references=['https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html'],
                provider='aws',
                resource_ids=logging_trails
            )
        except Exception as e:
            self.logger.error(f"Error checking CloudTrail: {e}")
            return self._error_result('CIS-AWS-3.1', str(e))
    
    def check_s3_encryption(self) -> ComplianceResult:
        """Check if S3 buckets have default encryption enabled."""
        try:
            s3 = self._get_client('s3')
            
            buckets = s3.list_buckets()['Buckets']
            encrypted_buckets = []
            unencrypted_buckets = []
            
            for bucket in buckets[:10]:  # Limit for performance
                try:
                    s3.get_bucket_encryption(Bucket=bucket['Name'])
                    encrypted_buckets.append(bucket['Name'])
                except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                    unencrypted_buckets.append(bucket['Name'])
                except Exception:
                    pass
            
            total_checked = len(encrypted_buckets) + len(unencrypted_buckets)
            if total_checked == 0:
                status = ComplianceStatus.NOT_APPLICABLE
                severity = RiskSeverity.INFO
            elif unencrypted_buckets:
                status = ComplianceStatus.PARTIAL if encrypted_buckets else ComplianceStatus.NON_COMPLIANT
                severity = RiskSeverity.HIGH
            else:
                status = ComplianceStatus.COMPLIANT
                severity = RiskSeverity.INFO
            
            return ComplianceResult(
                control_id='CIS-AWS-2.1.1',
                framework='CIS-AWS',
                control_title='S3 Bucket Encryption',
                status=status,
                risk_severity=severity,
                evidence={
                    'encrypted_buckets': len(encrypted_buckets),
                    'unencrypted_buckets': len(unencrypted_buckets),
                    'total_checked': total_checked
                },
                remediation='Enable default encryption on all S3 buckets',
                references=['https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html'],
                provider='aws',
                resource_ids=unencrypted_buckets
            )
        except Exception as e:
            self.logger.error(f"Error checking S3 encryption: {e}")
            return self._error_result('CIS-AWS-2.1.1', str(e))
    
    def check_mfa_enabled(self) -> ComplianceResult:
        """Check if MFA is enabled for IAM users."""
        try:
            iam = self._get_client('iam')
            
            users = iam.list_users()['Users']
            users_with_mfa = []
            users_without_mfa = []
            
            for user in users[:20]:  # Limit for performance
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                if mfa_devices:
                    users_with_mfa.append(user['UserName'])
                else:
                    users_without_mfa.append(user['UserName'])
            
            total_users = len(users_with_mfa) + len(users_without_mfa)
            if total_users == 0:
                status = ComplianceStatus.NOT_APPLICABLE
                severity = RiskSeverity.INFO
            elif users_without_mfa:
                status = ComplianceStatus.PARTIAL if users_with_mfa else ComplianceStatus.NON_COMPLIANT
                severity = RiskSeverity.CRITICAL
            else:
                status = ComplianceStatus.COMPLIANT
                severity = RiskSeverity.INFO
            
            return ComplianceResult(
                control_id='NIST-IA-2',
                framework='NIST',
                control_title='MFA for Users',
                status=status,
                risk_severity=severity,
                evidence={
                    'users_with_mfa': len(users_with_mfa),
                    'users_without_mfa': len(users_without_mfa),
                    'total_users': total_users
                },
                remediation='Enable MFA for all IAM users',
                references=['https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html'],
                provider='aws',
                resource_ids=users_without_mfa
            )
        except Exception as e:
            self.logger.error(f"Error checking MFA: {e}")
            return self._error_result('NIST-IA-2', str(e))
    
    def _error_result(self, control_id: str, error_msg: str) -> ComplianceResult:
        """Create an error result."""
        return ComplianceResult(
            control_id=control_id,
            framework='ERROR',
            control_title='Check Failed',
            status=ComplianceStatus.ERROR,
            risk_severity=RiskSeverity.INFO,
            evidence={'error': error_msg},
            remediation='Fix authentication or permissions issue',
            references=[],
            provider='aws'
        )


class AzureComplianceClient:
    """Azure compliance checking client."""
    
    def __init__(self, subscription_id: Optional[str] = None, logger: Optional[logging.Logger] = None):
        """Initialize Azure client."""
        self.logger = logger or logging.getLogger(__name__)
        self.subscription_id = subscription_id or os.environ.get('AZURE_SUBSCRIPTION_ID')
        self._credential = None
    
    def _get_credential(self):
        """Get Azure credential."""
        if self._credential is None:
            try:
                from azure.identity import DefaultAzureCredential
                self._credential = DefaultAzureCredential()
            except ImportError:
                raise ImportError("azure-identity is required for Azure support")
        return self._credential
    
    def check_mfa_enabled(self) -> ComplianceResult:
        """Check if MFA is enabled (placeholder - requires Graph API)."""
        return ComplianceResult(
            control_id='CIS-AZURE-1.23',
            framework='CIS-AZURE',
            control_title='MFA Enabled for Users',
            status=ComplianceStatus.NOT_APPLICABLE,
            risk_severity=RiskSeverity.INFO,
            evidence={'note': 'Requires Microsoft Graph API access'},
            remediation='Enable MFA for all users via Azure AD',
            references=['https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-getstarted'],
            provider='azure'
        )
    
    def check_storage_encryption(self) -> ComplianceResult:
        """Check if storage accounts have encryption enabled."""
        try:
            from azure.mgmt.storage import StorageManagementClient
            
            credential = self._get_credential()
            storage_client = StorageManagementClient(credential, self.subscription_id)
            
            accounts = list(storage_client.storage_accounts.list())
            encrypted_accounts = []
            
            for account in accounts[:10]:  # Limit for performance
                if account.encryption and account.encryption.services:
                    encrypted_accounts.append(account.name)
            
            total = min(len(accounts), 10)
            status = ComplianceStatus.COMPLIANT if len(encrypted_accounts) == total else ComplianceStatus.PARTIAL
            severity = RiskSeverity.HIGH if status != ComplianceStatus.COMPLIANT else RiskSeverity.INFO
            
            return ComplianceResult(
                control_id='CIS-AZURE-3.1',
                framework='CIS-AZURE',
                control_title='Storage Encryption Enabled',
                status=status,
                risk_severity=severity,
                evidence={
                    'encrypted_accounts': len(encrypted_accounts),
                    'total_accounts': total
                },
                remediation='Enable encryption for all storage accounts',
                references=['https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption'],
                provider='azure',
                resource_ids=encrypted_accounts
            )
        except Exception as e:
            self.logger.error(f"Error checking Azure storage encryption: {e}")
            return self._error_result('CIS-AZURE-3.1', str(e))
    
    def _error_result(self, control_id: str, error_msg: str) -> ComplianceResult:
        """Create an error result."""
        return ComplianceResult(
            control_id=control_id,
            framework='ERROR',
            control_title='Check Failed',
            status=ComplianceStatus.ERROR,
            risk_severity=RiskSeverity.INFO,
            evidence={'error': error_msg},
            remediation='Fix authentication or permissions issue',
            references=[],
            provider='azure'
        )


class GCPComplianceClient:
    """GCP compliance checking client."""
    
    def __init__(self, project_id: Optional[str] = None, logger: Optional[logging.Logger] = None):
        """Initialize GCP client."""
        self.logger = logger or logging.getLogger(__name__)
        self.project_id = project_id or os.environ.get('GCP_PROJECT_ID')
    
    def check_audit_logging_gcp(self) -> ComplianceResult:
        """Check if Cloud Audit Logging is configured."""
        return ComplianceResult(
            control_id='CIS-GCP-2.1',
            framework='CIS-GCP',
            control_title='Cloud Audit Logging Configured',
            status=ComplianceStatus.NOT_APPLICABLE,
            risk_severity=RiskSeverity.INFO,
            evidence={'note': 'Requires Cloud Asset Inventory API'},
            remediation='Enable Cloud Audit Logging for all services',
            references=['https://cloud.google.com/logging/docs/audit'],
            provider='gcp'
        )


# === Core Mapper ===
class CloudComplianceMapper:
    """Main compliance mapper class."""
    
    def __init__(self, providers: List[str], frameworks: List[str], 
                 control_family: Optional[str] = None, aggressive: bool = False,
                 logger: Optional[logging.Logger] = None):
        """
        Initialize the compliance mapper.
        
        Args:
            providers: List of cloud providers to check
            frameworks: List of compliance frameworks
            control_family: Optional control family filter
            aggressive: Enable aggressive/deeper checks
            logger: Logger instance
        """
        self.providers = providers
        self.frameworks = frameworks
        self.control_family = control_family
        self.aggressive = aggressive
        self.logger = logger or logging.getLogger(__name__)
        
        self.registry = ControlMappingRegistry()
        self.results: List[ComplianceResult] = []
        self.stats = ComplianceStats()
        
        # Initialize provider clients
        self.aws_client = None
        self.azure_client = None
        self.gcp_client = None
    
    def _init_clients(self) -> None:
        """Initialize cloud provider clients."""
        if 'aws' in self.providers or 'all' in self.providers:
            try:
                self.aws_client = AWSComplianceClient(logger=self.logger)
            except Exception as e:
                self.logger.warning(f"Failed to initialize AWS client: {e}")
        
        if 'azure' in self.providers or 'all' in self.providers:
            try:
                self.azure_client = AzureComplianceClient(logger=self.logger)
            except Exception as e:
                self.logger.warning(f"Failed to initialize Azure client: {e}")
        
        if 'gcp' in self.providers or 'all' in self.providers:
            try:
                self.gcp_client = GCPComplianceClient(logger=self.logger)
            except Exception as e:
                self.logger.warning(f"Failed to initialize GCP client: {e}")
    
    def run_assessment(self) -> Tuple[List[ComplianceResult], ComplianceStats]:
        """
        Run the compliance assessment.
        
        Returns:
            Tuple of (results, statistics)
        """
        start_time = time.time()
        
        self._init_clients()
        
        # Get controls to check
        controls_to_check = []
        for framework in self.frameworks:
            controls_to_check.extend(self.registry.get_controls_by_framework(framework))
        
        # Apply family filter
        if self.control_family:
            controls_to_check = [c for c in controls_to_check if c.family.upper() == self.control_family.upper()]
        
        # Remove duplicates
        controls_to_check = list({c.control_id: c for c in controls_to_check}.values())
        
        self.logger.info(f"Running {len(controls_to_check)} compliance checks...")
        
        # Run checks
        for control in controls_to_check:
            result = self._run_control_check(control)
            if result:
                self.results.append(result)
                self._update_stats(result)
        
        self.stats.scan_duration = time.time() - start_time
        self._calculate_compliance_score()
        
        return self.results, self.stats
    
    def _run_control_check(self, control: ControlMapping) -> Optional[ComplianceResult]:
        """Run a single control check."""
        try:
            # Determine which client to use
            client = None
            if control.framework.startswith('CIS-AWS') or (control.framework in ['NIST', 'ISO'] and self.aws_client):
                client = self.aws_client
            elif control.framework.startswith('CIS-AZURE') and self.azure_client:
                client = self.azure_client
            elif control.framework.startswith('CIS-GCP') and self.gcp_client:
                client = self.gcp_client
            
            if not client:
                return None
            
            # Call the check function
            if hasattr(client, control.check_function):
                check_method = getattr(client, control.check_function)
                return check_method()
            
        except Exception as e:
            self.logger.error(f"Error running check {control.control_id}: {e}")
        
        return None
    
    def _update_stats(self, result: ComplianceResult) -> None:
        """Update statistics with a result."""
        self.stats.total_controls += 1
        
        if result.status == ComplianceStatus.COMPLIANT:
            self.stats.compliant += 1
        elif result.status == ComplianceStatus.PARTIAL:
            self.stats.partial += 1
        elif result.status == ComplianceStatus.NON_COMPLIANT:
            self.stats.non_compliant += 1
        elif result.status == ComplianceStatus.NOT_APPLICABLE:
            self.stats.not_applicable += 1
        elif result.status == ComplianceStatus.ERROR:
            self.stats.errors += 1
        
        # By framework
        if result.framework not in self.stats.by_framework:
            self.stats.by_framework[result.framework] = {
                'compliant': 0,
                'partial': 0,
                'non_compliant': 0,
                'not_applicable': 0,
                'errors': 0
            }
        
        status_key = result.status.value.lower()
        if status_key in self.stats.by_framework[result.framework]:
            self.stats.by_framework[result.framework][status_key] += 1
        
        # By severity
        self.stats.by_severity[result.risk_severity.value] += 1
    
    def _calculate_compliance_score(self) -> None:
        """Calculate overall compliance score."""
        total_applicable = self.stats.compliant + self.stats.partial + self.stats.non_compliant
        if total_applicable > 0:
            self.stats.compliance_score = (self.stats.compliant / total_applicable) * 100


# === Reporting ===
class ComplianceReporter:
    """Generate compliance reports."""
    
    @staticmethod
    def generate_json(results: List[ComplianceResult], stats: ComplianceStats, output_file: str) -> None:
        """Generate JSON report."""
        report = {
            'metadata': {
                'tool': TOOL_NAME,
                'version': VERSION,
                'author': AUTHOR,
                'scan_time': datetime.utcnow().isoformat(),
                'duration_seconds': stats.scan_duration
            },
            'summary': {
                'total_controls': stats.total_controls,
                'compliant': stats.compliant,
                'partial': stats.partial,
                'non_compliant': stats.non_compliant,
                'not_applicable': stats.not_applicable,
                'errors': stats.errors,
                'compliance_score': round(stats.compliance_score, 2),
                'by_framework': stats.by_framework,
                'by_severity': stats.by_severity
            },
            'results': [r.to_dict() for r in results]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    @staticmethod
    def generate_csv(results: List[ComplianceResult], output_file: str) -> None:
        """Generate CSV report."""
        if not results:
            return
        
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['framework', 'control_id', 'control_title', 'status', 
                         'risk_severity', 'provider', 'remediation']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow({
                    'framework': result.framework,
                    'control_id': result.control_id,
                    'control_title': result.control_title,
                    'status': result.status.value,
                    'risk_severity': result.risk_severity.value,
                    'provider': result.provider,
                    'remediation': result.remediation
                })
    
    @staticmethod
    def generate_html(results: List[ComplianceResult], stats: ComplianceStats, output_file: str) -> None:
        """Generate HTML report."""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Cloud Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .score-card {{ background: white; padding: 30px; margin: 20px 0; border-radius: 5px; 
                      box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .score {{ font-size: 4em; font-weight: bold; color: #3498db; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        .results {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #34495e; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f8f9fa; }}
        .COMPLIANT {{ color: #27ae60; font-weight: bold; }}
        .PARTIAL {{ color: #f39c12; font-weight: bold; }}
        .NON_COMPLIANT {{ color: #e74c3c; font-weight: bold; }}
        .NOT_APPLICABLE {{ color: #95a5a6; }}
        .ERROR {{ color: #7f8c8d; }}
        .CRITICAL {{ background: #e74c3c; color: white; padding: 3px 8px; border-radius: 3px; }}
        .HIGH {{ background: #e67e22; color: white; padding: 3px 8px; border-radius: 3px; }}
        .MEDIUM {{ background: #f39c12; color: white; padding: 3px 8px; border-radius: 3px; }}
        .LOW {{ background: #3498db; color: white; padding: 3px 8px; border-radius: 3px; }}
        .INFO {{ background: #95a5a6; color: white; padding: 3px 8px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 {tool_name}</h1>
        <p>Author: {author} | Version: {version}</p>
        <p>Report generated: {scan_time}</p>
    </div>
    
    <div class="score-card">
        <div class="score">{compliance_score}%</div>
        <div>Overall Compliance Score</div>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value" style="color: #27ae60;">{compliant}</div>
            <div>Compliant</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: #f39c12;">{partial}</div>
            <div>Partial</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: #e74c3c;">{non_compliant}</div>
            <div>Non-Compliant</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: #95a5a6;">{not_applicable}</div>
            <div>Not Applicable</div>
        </div>
    </div>
    
    <div class="results">
        <h2>Compliance Results ({total_controls} controls)</h2>
        <table>
            <tr>
                <th>Framework</th>
                <th>Control</th>
                <th>Title</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Provider</th>
            </tr>
            {results_rows}
        </table>
    </div>
</body>
</html>
        """
        
        results_rows = ""
        for result in sorted(results, key=lambda x: (x.framework, x.control_id)):
            results_rows += f"""
            <tr>
                <td>{result.framework}</td>
                <td>{result.control_id}</td>
                <td>{result.control_title}</td>
                <td class="{result.status.value}">{result.status.value}</td>
                <td><span class="{result.risk_severity.value}">{result.risk_severity.value}</span></td>
                <td>{result.provider.upper()}</td>
            </tr>
            """
        
        html_content = html_template.format(
            tool_name=TOOL_NAME,
            author=AUTHOR,
            version=VERSION,
            scan_time=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            compliance_score=round(stats.compliance_score, 1),
            compliant=stats.compliant,
            partial=stats.partial,
            non_compliant=stats.non_compliant,
            not_applicable=stats.not_applicable,
            total_controls=stats.total_controls,
            results_rows=results_rows
        )
        
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    @staticmethod
    def display_console_summary(results: List[ComplianceResult], stats: ComplianceStats, console: Any) -> None:
        """Display summary in console."""
        if RICH_AVAILABLE:
            # Compliance score
            score_text = f"\n[bold]Compliance Score: [{'green' if stats.compliance_score >= 80 else 'yellow' if stats.compliance_score >= 60 else 'red'}]{stats.compliance_score:.1f}%[/]\n"
            console.print(score_text)
            
            # Summary table
            summary_table = Table(title="📊 Compliance Summary", box=box.ROUNDED)
            summary_table.add_column("Status", style="cyan")
            summary_table.add_column("Count", justify="right")
            
            summary_table.add_row("[green]Compliant[/green]", str(stats.compliant))
            summary_table.add_row("[yellow]Partial[/yellow]", str(stats.partial))
            summary_table.add_row("[red]Non-Compliant[/red]", str(stats.non_compliant))
            summary_table.add_row("[dim]Not Applicable[/dim]", str(stats.not_applicable))
            if stats.errors > 0:
                summary_table.add_row("[dim]Errors[/dim]", str(stats.errors))
            
            console.print(summary_table)
            
            # Framework breakdown
            if stats.by_framework:
                fw_table = Table(title="📋 By Framework", box=box.ROUNDED)
                fw_table.add_column("Framework")
                fw_table.add_column("Compliant", justify="right")
                fw_table.add_column("Non-Compliant", justify="right")
                
                for framework, counts in stats.by_framework.items():
                    fw_table.add_row(
                        framework,
                        str(counts.get('compliant', 0)),
                        str(counts.get('non_compliant', 0))
                    )
                
                console.print(fw_table)
        else:
            print(f"\nCompliance Score: {stats.compliance_score:.1f}%")
            print(f"Compliant: {stats.compliant}")
            print(f"Partial: {stats.partial}")
            print(f"Non-Compliant: {stats.non_compliant}")
            print(f"Not Applicable: {stats.not_applicable}")


# === CLI ===
def print_examples() -> None:
    """Print usage examples."""
    examples = """
USAGE EXAMPLES:

1. Assess AWS against all frameworks:
   python cloudcompliancemapper.py --provider aws --framework all

2. Check NIST controls for AWS:
   python cloudcompliancemapper.py --provider aws --framework nist --output html --output-file nist_report.html

3. Check CIS benchmarks for Azure:
   export AZURE_SUBSCRIPTION_ID="your-subscription-id"
   python cloudcompliancemapper.py --provider azure --framework cis

4. Multi-cloud ISO 27001 assessment:
   python cloudcompliancemapper.py --provider all --framework iso --output json --output-file iso_compliance.json

5. Check specific control family (Access Control):
   python cloudcompliancemapper.py --provider aws --framework nist --control-family AC

6. Comprehensive assessment with verbose output:
   python cloudcompliancemapper.py --provider aws --framework all --output html --output-file report.html --verbose

7. Quick CIS check for AWS:
   python cloudcompliancemapper.py --provider aws --framework cis

8. Generate CSV for spreadsheet analysis:
   python cloudcompliancemapper.py --provider aws --framework all --output csv --output-file compliance.csv
    """
    print(examples)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{VERSION} by {AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="For more examples, use --examples flag"
    )
    
    parser.add_argument(
        '--provider',
        choices=['aws', 'azure', 'gcp', 'all'],
        required=False,
        help='Cloud provider to assess (required unless using --examples)'
    )
    
    parser.add_argument(
        '--framework',
        choices=['nist', 'iso', 'cis', 'cis-aws', 'cis-azure', 'cis-gcp', 'all'],
        default='all',
        help='Compliance framework to check (default: all)'
    )
    
    parser.add_argument(
        '--control-family',
        type=str,
        help='Filter by control family (e.g., AC, AU, IA for NIST)'
    )
    
    parser.add_argument(
        '--output',
        choices=['json', 'csv', 'html', 'console'],
        default='console',
        help='Output format (default: console)'
    )
    
    parser.add_argument(
        '--output-file',
        type=str,
        help='Output file path (required for json/csv/html output)'
    )
    
    parser.add_argument(
        '--aggressive',
        action='store_true',
        help='Enable aggressive/deeper compliance checks'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Timeout in seconds for operations (default: 300)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    parser.add_argument(
        '--i-understand-legal-responsibilities',
        action='store_true',
        help='Acknowledge legal responsibilities'
    )
    
    parser.add_argument(
        '--examples',
        action='store_true',
        help='Show usage examples and exit'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'{TOOL_NAME} v{VERSION} by {AUTHOR}'
    )
    
    args = parser.parse_args()
    
    # Handle examples flag
    if args.examples:
        print_examples()
        sys.exit(0)
    
    # Validate provider is specified
    if not args.provider:
        parser.error("--provider is required (or use --examples to see usage)")
    
    # Setup logging
    logger = setup_logging(verbose=args.verbose, debug=args.debug)
    
    # Create console
    console = create_console()
    
    # Display banner
    display_banner(console)
    
    # Legal acknowledgment
    if not confirm_legal_acknowledgment(console):
        logger.error("You must acknowledge legal responsibilities to use this tool")
        sys.exit(1)
    
    # Output file validation
    if args.output in ['json', 'csv', 'html'] and not args.output_file:
        logger.error(f"--output-file is required for {args.output} output")
        sys.exit(1)
    
    # Parse providers and frameworks
    providers = [args.provider] if args.provider != 'all' else ['aws', 'azure', 'gcp']
    
    if args.framework == 'all':
        frameworks = ['NIST', 'ISO', 'CIS-AWS', 'CIS-AZURE', 'CIS-GCP']
    elif args.framework == 'cis':
        frameworks = ['CIS-AWS', 'CIS-AZURE', 'CIS-GCP']
    else:
        frameworks = [args.framework.upper()]
    
    try:
        # Initialize mapper
        logger.info(f"Starting compliance assessment for {', '.join(providers)}...")
        mapper = CloudComplianceMapper(
            providers=providers,
            frameworks=frameworks,
            control_family=args.control_family,
            aggressive=args.aggressive,
            logger=logger
        )
        
        # Run assessment
        results, stats = mapper.run_assessment()
        
        # Display console summary
        ComplianceReporter.display_console_summary(results, stats, console)
        
        # Generate output
        if args.output == 'json' and args.output_file:
            ComplianceReporter.generate_json(results, stats, args.output_file)
            logger.info(f"JSON report saved to {args.output_file}")
        
        elif args.output == 'csv' and args.output_file:
            ComplianceReporter.generate_csv(results, args.output_file)
            logger.info(f"CSV report saved to {args.output_file}")
        
        elif args.output == 'html' and args.output_file:
            ComplianceReporter.generate_html(results, stats, args.output_file)
            logger.info(f"HTML report saved to {args.output_file}")
        
        # Exit code based on compliance
        if stats.compliance_score < 50:
            sys.exit(2)  # Critical compliance issues
        elif stats.compliance_score < 80:
            sys.exit(1)  # Compliance issues
        else:
            sys.exit(0)  # Good compliance
    
    except KeyboardInterrupt:
        logger.warning("Assessment interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        logger.error(f"Assessment failed: {e}", exc_info=args.debug)
        sys.exit(1)


if __name__ == '__main__':
    main()
