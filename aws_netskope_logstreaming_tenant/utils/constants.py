"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

AWS Netskope LogStreaming Provider constants.
"""

from netskope_api.iterator.const import Const

MODULE_NAME = "TENANT"
PLUGIN_VERSION = "1.0.0-beta"
PLATFORM_NAME = "AWS Netskope LogStreaming"
MAINTENANCE_PULL = "maintenance_pulling"
HISTORICAL_PULL = "historical_pulling"
TYPE_EVENT = "events"
EVENTS = {
    "network": Const.EVENT_TYPE_NETWORK
}
MAX_RETRIES = 3
READ_TIMEOUT = 300
DEFAULT_WAIT_TIME = 30
VALIDATION_READTIMEOUT = 60
RESULT = "result"
QUEUE_SIZE = 10
AUTHENTICATION_METHODS = [
    "aws_iam_roles_anywhere",
    "deployed_on_aws",
]
BATCH_SIZE = 10000
BACK_PRESSURE_WAIT_TIME = 300
NLS_EVENT_MAPPINGS = {
    "alert_type_c2": "NLS CTEP",
    "alert_type_compromised_credential": "NLS Compromised Credential",
    "alert_type_content": "NLS Content",
    "alert_type_ctep": "NLS CTEP",
    "alert_type_device": "NLS Device",
    "alert_type_dlp": "NLS DLP",
    "alert_type_ips": "NLS CTEP",
    "alert_type_malsite": "NLS Malsite",
    "alert_type_malware": "NLS Malware",
    "alert_type_policy": "NLS Policy",
    "alert_type_quarantine": "NLS Quarantine",
    "alert_type_remediation": "NLS Remediation",
    "alert_type_security_assessment": "NLS Security Assessment",
    "alert_type_uba": "NLS UBA",
    "alert_type_watchlist": "NLS Watchlist",
    "application": "NLS Application",
    "audit": "NLS Audit",
    "clientstatus": "NLS Clientstatus",
    "epdlp": "NLS EPDLP",
    "incident": "NLS Incident",
    "infrastructure": "NLS Infrastructure",
    "network": "NLS Network",
    "page": "NLS Page",
    "policy": "NLS Policy",
    "malsite": "NLS Malsite",
    "DLP": "NLS DLP",
    "uba": "NLS UBA",
    "watchlist": "NLS Watchlist",
    "Security Assessment": "NLS Security Assessment",
    "Compromised Credential": "NLS Compromised Credential",
    "Malware": "NLS Malware",
    "ips": "NLS CTEP",
    "quarantine": "NLS Quarantine",
    "Remediation": "NLS Remediation",
    "ctep": "NLS CTEP",
    "c2": "NLS CTEP",
    "Device": "NLS Device",
    "Content": "NLS Content",
}

REGIONS = [
    "us-east-2",
    "us-east-1",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "cn-north-1",
    "cn-northwest-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-south-1",
    "eu-west-3",
    "eu-north-1",
    "me-south-1",
    "sa-east-1",
    "ap-south-2",
    "ap-southeast-3",
    "eu-south-2",
    "eu-central-2",
    "me-central-1",
    "ca-west-1",
    "ap-southeast-4",
    "il-central-1",
    "ap-southeast-7",
    "ca-west-1",
    "ap-southeast-5",
    "mx-central-1"
]
