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

CTE Infoblox Plugin constants.
"""

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MODULE_NAME = "CTE"
PLATFORM_NAME = "Infoblox TIDE"
PLUGIN_VERSION = "1.0.0-beta"
DEFAULT_WAIT_TIME = 60
MAX_API_CALLS = 4
RETRACTION = "Retraction"
DEFAULT_SLEEP_TIME = 60
INDICATOR_TYPES = ["hash", "host", "ipv4", "ipv6", "url"]
HASH_TYPES = ["sha256", "md5"]
IP_TYPES = ["ipv4", "ipv6"]
DEFAULT_SLEEP_TIME = 60
INTEGER_THRESHOLD = 4611686018427387904
MAX_API_CALLS = 4
TIME_PAGINATION_INTERVAL = 24  # 24 hours
IOC_UI_ENDPOINT = "{base_url}/#/security_research/search/auto/{value}/summary"
DEFAULT_PUSH_BATCH = 100000
DEFAULT_PULL_LIMIT = 100000
