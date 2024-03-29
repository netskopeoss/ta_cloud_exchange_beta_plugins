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

BMC Helix ITSM Constants."""


PLATFORM_NAME = "BMC Helix ITSM"
MODULE_NAME = "CTO"
PLUGIN_VERSION = "1.0.0"
MAX_RETRIES = 4
DEFAULT_WAIT_TIME = 60
RETRY_SLEEP_TIME = 50
MAX_PAGE_SIZE = 1000
PAGE_LIMIT = 100
DATE_FORMAT_FOR_IOCS = "%Y-%m-%dT%H:%M:%S.%f%z"

LOGIN_URL = "api/jwt/login"
TASK_URL = "api/arsys/v1/entry/HPD:IncidentInterface_Create"
GET_TASK_URL = "api/arsys/v1/entry/HPD:IncidentInterface"

INCIDENT_SERVICE_TYPE_MAPPING = {
    "user_service_restoration": "User Service Restoration",
    "user_service_request": "User Service Request",
    "infrastructure_restoration": "Infrastructure Restoration",
    "infrastructure_event": "Infrastructure Event",
    "security_incident": "Security Incident",
}
INCIDENT_TYPES = list(INCIDENT_SERVICE_TYPE_MAPPING.keys())
URGENCY_MAPPING = {
    "critical": "1-Critical",
    "high": "2-High",
    "medium": "3-Medium",
    "low": "4-Low"
}
URGENCY = list(URGENCY_MAPPING.keys())

IMPACT_MAPPING = {
    "extensive": "1-Extensive/Widespread",
    "significant": "2-Significant/Large",
    "moderate": "3-Moderate/Limited",
    "minor": "4-Minor/Localized"
}
IMPACT = list(IMPACT_MAPPING.keys())
