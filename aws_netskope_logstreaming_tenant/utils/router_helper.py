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

AWS Netskope LogStreaming router helper.
"""


def get_all_subtypes():
    """Get subtypes for alerts and events."""
    return {
        "events": {
            "NLS Page": "NLS Page",
            "NLS Application": "NLS Application",
            "NLS Audit": "NLS Audit",
            "NLS Infrastructure": "NLS Infrastructure",
            "NLS Network": "NLS Network",
            "NLS Incident": "NLS Incident",
            "NLS Clientstatus": "NLS Clientstatus",
            "NLS DLP": "NLS DLP",
            "NLS Malware": "NLS Malware",
            "NLS Policy": "NLS Policy",
            "NLS Compromised Credential": "NLS Compromised Credential",
            "NLS Malsite": "NLS Malsite",
            "NLS Quarantine": "NLS Quarantine",
            "NLS Remediation": "NLS Remediation",
            "NLS Security Assessment": "NLS Security Assessment",
            "NLS Watchlist": "NLS Watchlist",
            "NLS UBA": "NLS UBA",
            "NLS CTEP": "NLS CTEP",
            "NLS Device": "NLS Device",
            "NLS Content": "NLS Content",
            "NLS WebTx": "NLS WebTx",
            "NLS EPDLP": "NLS EPDLP",
        }
    }
