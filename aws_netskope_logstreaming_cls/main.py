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

AWS Netskope LogStreaming CLS plugin.
"""

import traceback
from typing import List

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)

from .utils.constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    EVENT_TYPES,
)

from netskope.common.utils.alerts_helper import AlertsHelper

helper = AlertsHelper()


class AWSNetskopeLogstreamingCLSPlugin(PluginBase):
    """The Netskope Borderless WAN CLS plugin implementation class."""

    def __init__(
        self,
        name,
        configuration,
        storage,
        last_run_at,
        logger,
        use_proxy=False,
        ssl_validation=True,
        source=None,
        mappings=None,
    ):
        """Initialize."""
        super().__init__(
            name,
            configuration,
            storage,
            last_run_at,
            logger,
            use_proxy,
            ssl_validation,
            source=source,
            mappings=mappings,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AWSNetskopeLogstreamingCLSPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform."""
        pass

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw Netskope JSON data into target platform \
        supported data formats."""
        pass

    def get_types_to_pull(self, data_type):
        """Get the types of data to pull.

        Returns:
            List of sub types to pull
        """
        types = []
        if data_type == "events":
            return EVENT_TYPES
        else:
            return types

    def validate(
        self, configuration: dict, tenant_name=None
    ) -> ValidationResult:
        """Validate the configuration parameters dict."""

        hours = configuration.get("hours")
        if not hours and hours != 0:
            err_msg = (
                "Initial Range for events is a required "
                "configuration parameter, it should be 0."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(hours, int):
            err_msg = (
                "Invalid Initial Range for events provided in "
                "the configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif hours != 0:
            err_msg = (
                "Invalid Initial Range in hours provided in"
                " the configuration parameter, it should be 0."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        days = configuration.get("days")
        if not days and days != 0:
            err_msg = (
                "Initial Range for Alerts is a required"
                " configuration parameter, it should be 0."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(days, int):
            err_msg = (
                "Invalid Initial Range for Alerts provided "
                "in configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days != 0:
            err_msg = (
                "Invalid Initial Range for Alerts provided"
                " in configuration parameter, it should be 0."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return ValidationResult(success=True, message="Validation successful.")
