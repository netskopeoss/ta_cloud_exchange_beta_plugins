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

import json
import traceback
import time
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Callable, Dict, Generator, List, Literal, Set, Tuple, Union
from urllib.parse import quote, urlparse

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from .utils.constants import (
    DATETIME_FORMAT,
    DEFAULT_PULL_LIMIT,
    DEFAULT_PUSH_BATCH,
    DEFAULT_SLEEP_TIME,
    HASH_TYPES,
    INDICATOR_TYPES,
    INTEGER_THRESHOLD,
    IOC_UI_ENDPOINT,
    IP_TYPES,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    RETRACTION,
    TIME_PAGINATION_INTERVAL,
)
from .utils.helper import InfobloxTIDEPluginException, InfobloxTIDEPluginHelper

INFOBLOX_TIDE_TO_INTERNAL_TYPE = {
    "host": IndicatorType.HOSTNAME,
    "ipv4": IndicatorType.IPV4,
    "ipv6": IndicatorType.IPV6,
    "url": IndicatorType.URL,
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
}


class InfobloxTIDEPlugin(PluginBase):
    """Infoblox TIDE Plugin class"""

    def __init__(self, name, *args, **kwargs):
        """Init function.

        Args:
           name (str): Configuration Name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.infoblox_tide_helper = InfobloxTIDEPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            metadata = InfobloxTIDEPlugin.metadata
            plugin_name = metadata.get("name", PLATFORM_NAME)
            plugin_version = metadata.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _create_tags(
        self, utils: TagUtils, tags: List[str], enable_tagging: str
    ) -> Tuple[List[str], Set[str]]:
        """Create new tag(s) in database if required.

        Args:
            utils (TagUtils): Utils
            tags (List[str]): Tags
            enable_tagging (str): Enable/disable tagging

        Returns:
            Tuple[List[str], Set[str]]: Created tags, Skipped tags
        """
        if enable_tagging != "yes":
            return [], set()

        tag_names, skipped_tags = [], set()
        for tag in tags:
            tag = tag.strip()
            # Skip Empty tags
            if not tag:
                skipped_tags.add(tag)
                continue
            tag = f"{PLATFORM_NAME}-{tag}"
            try:
                if not utils.exists(tag):
                    utils.create_tag(
                        TagIn(
                            name=tag,
                            color="#ED3347",
                        )
                    )
            except ValueError:
                skipped_tags.add(tag)
            else:
                tag_names.append(tag)
        return tag_names, skipped_tags

    def _determine_ip_version(
        self, ip_string: str
    ) -> Union[Literal["ipv4", "ipv6"], None]:
        """
        Determine IP version of given string.

        Args:
            ip_string (str): IP string

        Returns:
            str: "IPv4" or "IPv6" if valid IP string, None otherwise
        """
        try:
            ip_obj = ip_address(ip_string)
            if isinstance(ip_obj, IPv4Address):
                return "ipv4"
            elif isinstance(ip_obj, IPv6Address):
                return "ipv6"
        except (ValueError, Exception):
            return None

    def _confidence_normalization(
        self,
        value: int,
        method: Literal["pull", "push"],
    ) -> int:
        """
        Normalize the given confidence value.

        If method is "pull", it takes a value from 0 to 100 and maps it to
        a value from 1 to 10. If the value is outside this range, it returns
        the value as is.

        If method is "push", it takes a value from 1 to 10 and maps it to
        a value from 0 to 100. If the value is outside this range, it returns
        the value as is.

        Args:
            value (int): Confidence value
            method (str): Either "pull" or "push"

        Returns:
            int: Normalized confidence value
        """
        if method == "pull":
            return round((value / 100) * 9 + 1)
        elif method == "push":
            return round(((value - 1) / 9) * 100)
        else:
            self.logger.error(f"{self.log_prefix}: Invalid method provided")
            return value

    def _severity_mapping(
        self,
        value: Union[int, SeverityType],
        method: Literal["pull", "push"],
    ) -> Union[int, SeverityType]:
        """
        Maps the given value to either an integer or a SeverityType.

        If method is "pull", it takes an integer from 0 to 100 and maps it to
        a SeverityType. If the value is outside this range, it returns
        SeverityType.UNKNOWN.

        If method is "push", it takes a SeverityType and maps it to an integer
        from 0 to 100. If the SeverityType is not recognized, it returns 0.

        The mapping is as follows:
            - 0-25: LOW
            - 25-50: MEDIUM
            - 50-75: HIGH
            - 75-100: CRITICAL
        """
        if method == "pull":
            if value >= 0 and value <= 25:
                return SeverityType.LOW
            elif value > 25 and value <= 50:
                return SeverityType.MEDIUM
            elif value > 50 and value <= 75:
                return SeverityType.HIGH
            elif value > 75 and value <= 100:
                return SeverityType.CRITICAL
            else:
                return SeverityType.UNKNOWN
        elif method == "push":
            if value == SeverityType.LOW:
                return 25
            elif value == SeverityType.MEDIUM:
                return 50
            elif value == SeverityType.HIGH:
                return 75
            elif value == SeverityType.CRITICAL:
                return 100
            else:
                return None
        else:
            self.logger.error(f"{self.log_prefix}: Invalid method provided")
            return value

    def _get_profile_filter_query_param(self, data_profiles: str) -> str:
        """
        Takes a string of profile names and returns a string
        in the format required by the Infoblox TIDE API for the
        profile filter query parameter.

        The method first fetches all the profiles from the API.
        Then, it iterates over the given list of profile names.
        If a profile name matches any of the ones fetched from the
        API, it adds the corresponding profile ID to the list.
        Finally, it joins the list with commas and returns the
        resulting string.
        """
        if not data_profiles.strip():
            return ""
        profiles_to_filter = []
        profiles = self._fetch_profiles()
        data_profiles = [
            profile.strip() for profile in data_profiles.split(",")
        ]

        for profile_name, profile_id in profiles.items():
            if profile_name in data_profiles:
                profiles_to_filter.append(profile_id)
        return ",".join(profiles_to_filter)

    def _get_type_filter_query_param(self, iocs_to_be_pulled: list) -> str:
        """
        Takes a list of iocs_to_be_pulled and returns a string
        in the format required by the Infoblox TIDE API for the
        type filter query parameter.

        The method first makes a copy of the given list. Then, it
        checks if "ipv4" is in the list. If it is, it removes it and
        adds "ip". Next, it checks if "ipv6" is in the list. If it is,
        it removes it. If "ip" is not in the list, it adds it. Finally,
        it joins the list with commas and returns the resulting string.
        """
        type_to_filter = iocs_to_be_pulled.copy()
        if "ipv4" in iocs_to_be_pulled:
            type_to_filter.remove("ipv4")
            type_to_filter.append("ip")
        if "ipv6" in iocs_to_be_pulled:
            type_to_filter.remove("ipv6")
            if "ip" not in type_to_filter:
                type_to_filter.append("ip")
        type_to_filter = ",".join(type_to_filter)
        return type_to_filter

    def _fetch_properties(self) -> List[str]:
        """
        Fetches all properties from Infoblox TIDE server.

        Returns:
            List[str]: List of property IDs.
        """
        base_url, api_key, _, _, _, _, _, _ = (
            self.infoblox_tide_helper.get_configuration_parameters(
                self.configuration,
            )
        )
        properties = []
        logger_msg = f"fetching properties from {PLATFORM_NAME} server"
        try:
            response = self.infoblox_tide_helper.api_helper(
                logger_msg=logger_msg,
                method="GET",
                url=f"{base_url}/tide/api/data/properties",
                headers=self.infoblox_tide_helper.get_auth_headers(api_key),
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_validation=False,
                is_handle_error_required=True,
            )

            for property in response.get("property", []):
                if property.get("id"):
                    properties.append(property.get("id"))
        except InfobloxTIDEPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise InfobloxTIDEPluginException(err_msg)

        return properties

    def _fetch_profiles(
        self,
        logger_msg: str = f"fetching profiles from {PLATFORM_NAME} server",
        is_validation: bool = False,
        base_url: str = None,
        api_key: str = None,
    ) -> Dict:
        """
        Fetches all active profiles from Infoblox TIDE server.

        Returns:
            List[str]: List of profile names.
        """
        if not is_validation:
            base_url, api_key, _, _, _, _, _, _ = (
                self.infoblox_tide_helper.get_configuration_parameters(
                    self.configuration,
                )
            )
        profiles_dict = {}
        try:
            response = self.infoblox_tide_helper.api_helper(
                logger_msg=logger_msg,
                method="GET",
                url=f"{base_url}/tide/admin/v1/resources/dataprofiles",
                headers=self.infoblox_tide_helper.get_auth_headers(api_key),
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_validation=is_validation,
                is_handle_error_required=True,
            )

            for profile in response.get("profiles", []):
                if not profile.get("active"):
                    continue
                if profile.get("name"):
                    profiles_dict[profile.get("name")] = profile.get("id")
        except InfobloxTIDEPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise InfobloxTIDEPluginException(err_msg)

        return profiles_dict

    def _create_profile(self, profile_name: str) -> Union[str, None]:
        """
        Creates a new profile on Infoblox TIDE server.

        Args:
            profile_name (str): Name of the profile to be created.

        Returns:
            Union[str, None]: Created profile name if successful, else None.
        """
        base_url, api_key, _, _, _, _, _, _ = (
            self.infoblox_tide_helper.get_configuration_parameters(
                self.configuration,
            )
        )
        logger_msg = (
            f"creating profile '{profile_name}' on {PLATFORM_NAME} server"
        )
        current_time = datetime.now(timezone.utc)
        try:
            response = self.infoblox_tide_helper.api_helper(
                logger_msg=logger_msg,
                method="POST",
                url=f"{base_url}/tide/admin/v1/resources/dataprofiles",
                headers=self.infoblox_tide_helper.get_auth_headers(api_key),
                json={
                    "name": profile_name,
                    "description": (
                        f"Created via Netskope Cloud Exchange plugin "
                        f"{MODULE_NAME} {PLATFORM_NAME} v{PLUGIN_VERSION}"
                        f" on {current_time.strftime('%Y-%m-%d')} at"
                        f" {current_time.strftime('%H:%M:%S')} UTC."
                    ),
                    "default_ttl": True,
                },
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_validation=False,
                is_handle_error_required=True,
                is_retraction=False,
            )
            created_profile_name = response.get("profile", {}).get("name")
            self.logger.info(
                f"{self.log_prefix}: Successfully created profile "
                f"'{created_profile_name}' on {PLATFORM_NAME} server."
            )
            return created_profile_name
        except InfobloxTIDEPluginException:
            raise
        except Exception as err:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise InfobloxTIDEPluginException(err_msg)

    def _create_iocs_ui_link(self, value: str, type: str) -> str:
        """
        Create a link to the Infoblox TIDE UI for the given IOC value and type.

        Args:
            value (str): The IOC value.
            type (str): The IOC type.

        Returns:
            str: The link to the Infoblox TIDE UI.
        """
        base_url = self.configuration.get("base_url").strip().strip("/")
        if type == "url":
            try:
                value = quote(value, safe="")
            except Exception as err:
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred"
                        f" while creating URL encoded value for {value}."
                        f" Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                return ""
        return IOC_UI_ENDPOINT.format(base_url=base_url, value=value)

    def _create_time_based_pagination(
        self, start_time: str, end_time: str
    ) -> Generator[List[Tuple[str, str]], None, None]:
        """
        Create a generator that yields tuples of (start_time, end_time) from
        given start_time to end_time. The start_time and end_time of each tuple
        will not exceed one day.

        Args:
            start_time (str): The start time for pagination.
            end_time (str): The end time for pagination.

        Yields:
            tuple: A tuple containing the start time and end time for
            pagination.
        """
        start_time = datetime.strptime(start_time, DATETIME_FORMAT)
        end_time = datetime.strptime(end_time, DATETIME_FORMAT)
        while True:
            if (end_time - start_time) > timedelta(
                hours=TIME_PAGINATION_INTERVAL,
            ):
                intermediate_time = start_time + timedelta(
                    hours=TIME_PAGINATION_INTERVAL,
                )
                yield (
                    datetime.strftime(start_time, DATETIME_FORMAT),
                    datetime.strftime(intermediate_time, DATETIME_FORMAT),
                )
                start_time = intermediate_time
            else:
                yield (
                    datetime.strftime(start_time, DATETIME_FORMAT),
                    datetime.strftime(end_time, DATETIME_FORMAT),
                )
                break

    def _create_indicator_object(
        self,
        threat_data: Dict,
        enable_tagging: str,
        success_ioc_count: Dict,
        skipped_ioc: int,
        skipped_tags: Set[str],
        tag_utils: TagUtils,
    ) -> Tuple[Indicator, Dict, int, Set[str]]:
        """
        Create an indicator object from the given threat data.

        Args:
            threat_data (Dict): Threat data in the format received from
                Infoblox TIDE API.
            enable_tagging (str): Whether to enable tagging or not.
            success_ioc_count (Dict): Dictionary to keep track of the count of
                indicators by type.
            skipped_ioc (int): Count of indicators that were skipped.
            skipped_tags (Set[str]): Set of tags that were skipped.
            tag_utils (TagUtils): An instance of TagUtils to create tags.

        Returns:
            tuple: A tuple containing the created indicator object, updated
                success_ioc_count, updated skipped_ioc count, and updated
                skipped_tags set.
        """
        if not threat_data.get("value"):
            skipped_ioc += 1
            return None, success_ioc_count, skipped_ioc, skipped_tags
        elif threat_data.get("value"):
            try:
                tags, tags_skipped = self._create_tags(
                    utils=tag_utils,
                    tags=threat_data.get("tags", []),
                    enable_tagging=enable_tagging,
                )
                indicator_obj = Indicator(
                    value=threat_data.get("value"),
                    type=INFOBLOX_TIDE_TO_INTERNAL_TYPE.get(
                        threat_data.get("type"),
                    ),
                    tags=tags,
                    severity=self._severity_mapping(
                        int(threat_data.get("severity")), "pull"
                    ),
                    reputation=self._confidence_normalization(
                        int(threat_data.get("reputation")), "pull"
                    ),
                    comments=threat_data.get("comments"),
                    extendedInformation=self._create_iocs_ui_link(
                        value=threat_data.get("value"),
                        type=threat_data.get("type"),
                    ),
                )
            except (ValidationError, Exception) as err:
                indicator_type = threat_data.get("type")
                indicator_value = threat_data.get("value")
                error_msg = (
                    "Validation error occurred"
                    if isinstance(err, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_msg} while creating "
                        f"indicator object for indicator type "
                        f"'{indicator_type}' and indicator value "
                        f"'{indicator_value}' ."
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_ioc += 1
                skipped_tags.update(tags_skipped)
                return None, success_ioc_count, skipped_ioc, skipped_tags
            if threat_data.get("type") in HASH_TYPES:
                success_ioc_count["hash"] += 1
            else:
                success_ioc_count[threat_data.get("type")] += 1
            skipped_tags.update(tags_skipped)
            return (
                indicator_obj,
                success_ioc_count,
                skipped_ioc,
                skipped_tags,
            )

    def _fetch_threat_data(
        self,
        base_url: str,
        headers: Dict,
        fetch_start_time: str,
        fetch_end_time: str,
        iocs_to_be_pulled: List[str],
        profile_filter: str,
        type_to_filter: str,
        page_number: int,
        is_retraction: bool,
    ) -> Generator[Union[Dict, str], None, None]:
        """
        Fetch threat data from Infoblox TIDE.

        Args:
            base_url (str): The base URL of the Infoblox TIDE API.
            headers (Dict): The headers to pass in the API call.
            fetch_start_time (str): The start time for the API call.
            fetch_end_time (str): The end time for the API call.
            iocs_to_be_pulled (List[str]): The list of IOCs to be pulled.
            page_number (int): The page number for the API call.
            is_retraction (bool): Whether the method call is for retraction or
                not.

        Yields:
            Dict: A dictionary containing the threat data.
        """
        if is_retraction:
            logger_msg = (
                f"fetching modified indicators for page {page_number}"
                f" from {PLATFORM_NAME} server"
            )
        else:
            logger_msg = (
                f"fetching threat data for page {page_number} from"
                f" {PLATFORM_NAME} server"
            )
        query_params = {
            "type": type_to_filter,
            "rlimit": DEFAULT_PULL_LIMIT,
            "from_date": fetch_start_time,
            "to_date": fetch_end_time,
            "data_format": "json",
            "include_ipv6": True if "ipv6" in iocs_to_be_pulled else False,
        }
        if profile_filter:
            query_params["profile"] = profile_filter
        try:
            response = self.infoblox_tide_helper.api_helper(
                logger_msg=logger_msg,
                url=f"{base_url}/tide/api/data/threats",
                method="GET",
                params=query_params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=False,
                is_handle_error_required=True,
                is_retraction=is_retraction,
            )
            for threat in response.get("threat", []):
                if not threat:
                    continue
                threat_type = threat.get("type", "").lower()
                if is_retraction:
                    if threat_type == "hash":
                        if threat.get("hash_type", "") in HASH_TYPES:
                            yield threat.get(threat_type, "")
                        else:
                            continue
                    else:
                        yield threat.get(threat_type, "")
                else:
                    if "netskope" in threat.get("threat_label", "").lower():
                        continue
                    tags_list = [
                        threat.get("threat_label", ""),
                        threat.get("property", threat.get("class", "")),
                    ]
                    threat_dict = {
                        "type": threat_type,
                        "value": threat.get(threat_type, ""),
                        # If we do not get threat_level from api
                        # response set the severity value to -1 which
                        # will be mapped to SeverityType.UNKNOWN in the
                        # function _severity_mapping()
                        "severity": threat.get("threat_level", -1),
                        # Default value for reputation is 5 (set by core if
                        # not provided)
                        # So if the api response does not provide confidence
                        # value, set it to 44 which will be normalized to 5
                        # in the function _confidence_normalization()
                        "reputation": threat.get("confidence", 44),
                        "tags": tags_list,
                        "comments": threat.get("extended", {}).get(
                            "notes", ""
                        ),
                    }
                    if (
                        threat.get("hash_type")
                        and threat.get("hash_type", "").lower() in HASH_TYPES
                    ):
                        threat_dict["type"] = threat.get("hash_type").lower()
                    if threat_dict.get("type", "") == "ip":
                        ip_version = self._determine_ip_version(
                            threat_dict.get("value"),
                        )
                        if "ipv4" not in iocs_to_be_pulled and ip_version == "ipv4":
                            continue
                        if ip_version:
                            threat_dict["type"] = ip_version
                        else:
                            self.logger.info(
                                f"{self.log_prefix}: Skipping IoC with"
                                f" value {threat_dict.get('value', '')}"
                                " as IP value was invalid."
                            )
                    yield threat_dict
        except InfobloxTIDEPluginException:
            raise
        except Exception as err:
            error_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise InfobloxTIDEPluginException(error_msg)

    def _pull(self):
        """Pull Indicator from Infoblox TIDE"""
        (
            base_url,
            api_key,
            iocs_to_be_pulled,
            _,
            _,
            enable_tagging,
            initial_pull_range,
            data_profiles,
        ) = self.infoblox_tide_helper.get_configuration_parameters(
            self.configuration,
        )
        end_time = datetime.strftime(
            datetime.now(timezone.utc),
            DATETIME_FORMAT,
        )
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        skipped_tags = set()
        start_time = None
        tag_utils = TagUtils()
        fetch_checkpoint = {
            "last_start_time": "",
        }

        if sub_checkpoint:
            start_time = sub_checkpoint.get("last_start_time")
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME} "
                f"using checkpoint: {str(start_time)}"
            )
        elif self.last_run_at:
            start_time = datetime.strftime(self.last_run_at, DATETIME_FORMAT)
            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME} "
                f"using checkpoint: {str(start_time)}"
            )
        else:
            start_time = datetime.strftime(
                datetime.strptime(end_time, DATETIME_FORMAT)
                - timedelta(days=int(initial_pull_range)),
                DATETIME_FORMAT,
            )
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch since "
                "checkpoint is empty. Querying indicators for "
                f"last {initial_pull_range} days."
            )
        profile_filter = self._get_profile_filter_query_param(data_profiles)
        type_to_filter = self._get_type_filter_query_param(iocs_to_be_pulled)
        page_number = 1
        total_indicators_fetched = 0
        headers = self.infoblox_tide_helper.get_auth_headers(api_key)
        for page_start_time, page_end_time in self._create_time_based_pagination(
            start_time, end_time
        ):
            indicator_list = []
            success_ioc_count = {
                "hash": 0,
                "host": 0,
                "ipv4": 0,
                "ipv6": 0,
                "url": 0,
            }
            skipped_ioc = 0
            try:
                for threat_data in self._fetch_threat_data(
                    base_url=base_url,
                    headers=headers,
                    fetch_start_time=page_start_time,
                    fetch_end_time=page_end_time,
                    iocs_to_be_pulled=iocs_to_be_pulled,
                    profile_filter=profile_filter,
                    type_to_filter=type_to_filter,
                    page_number=page_number,
                    is_retraction=False,
                ):
                    (
                        indicator_obj,
                        success_ioc_count,
                        skipped_ioc,
                        skipped_tags,
                    ) = self._create_indicator_object(
                        threat_data=threat_data,
                        enable_tagging=enable_tagging,
                        success_ioc_count=success_ioc_count,
                        skipped_ioc=skipped_ioc,
                        skipped_tags=skipped_tags,
                        tag_utils=tag_utils,
                    )
                    if indicator_obj:
                        indicator_list.append(indicator_obj)
            except InfobloxTIDEPluginException:
                raise
            except Exception as err:
                err_msg = (
                    "Unexpected error occurred while fetching"
                    f"threat data from {PLATFORM_NAME} server."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg} Error: {err}")
                raise InfobloxTIDEPluginException(err_msg)
            total_indicators_fetched += sum(success_ioc_count.values())
            self.logger.info(
                f"{self.log_prefix}: Fetched "
                f"{sum(success_ioc_count.values())} "
                f"indicator(s) and skipped {skipped_ioc} indicator(s) in "
                f"page {page_number} from {PLATFORM_NAME}."
                " Pull Stats:"
                f" Hash: {success_ioc_count['hash']},"
                f" Host: {success_ioc_count['host']},"
                f" URLs: {success_ioc_count['url']},"
                f" IPv4: {success_ioc_count['ipv4']},"
                f" IPv6: {success_ioc_count['ipv6']}"
                f" Total indicator(s) fetched - "
                f"{total_indicators_fetched}."
            )
            fetch_checkpoint["last_start_time"] = page_end_time
            page_number += 1
            if not indicator_list:
                continue
            yield indicator_list, fetch_checkpoint

    def pull(self):
        try:
            if self.configuration.get("is_pull_required").strip() == "yes":
                if hasattr(self, "sub_checkpoint"):

                    def wrapper(self):
                        yield from self._pull()

                    return wrapper(self)
                else:
                    indicators = []
                    for batch, _ in self._pull():
                        indicators.extend(batch)
                    return indicators
            else:
                self.logger.info(
                    f"{self.log_prefix}: Polling is disabled in configuration "
                    "parameter hence skipping pulling of indicators from "
                    f"{PLATFORM_NAME}."
                )
                return []
        except InfobloxTIDEPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Error occurred while pulling indicators"
                f" from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise InfobloxTIDEPluginException(err_msg)

    def get_modified_indicators(
        self, source_indicators: List[List[Dict]]
    ) -> Generator[Tuple[List[str], bool], None, None]:
        """Get all modified indicators status.

        Args:
            source_indicators (List[List[Dict]]): Source Indicators.

        Yields:
            List of retracted indicators, Status (List, bool): List of
                retracted indicators values. Status of execution.
        """
        self.log_prefix = f"{self.log_prefix} [{RETRACTION}]"
        (
            base_url,
            api_key,
            iocs_to_be_pulled,
            _,
            retraction_interval,
            _,
            _,
            data_profiles,
        ) = self.infoblox_tide_helper.get_configuration_parameters(
            self.configuration,
        )
        if not (retraction_interval and isinstance(retraction_interval, int)):
            log_msg = (
                "Retraction Interval is not available for the configuration"
                f' "{self.config_name}". Skipping retraction of IoC(s)'
                f" from {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            yield [], True
        retraction_interval = int(retraction_interval)
        end_time = datetime.strftime(
            datetime.now(timezone.utc),
            DATETIME_FORMAT,
        )
        start_time = datetime.strftime(
            datetime.now(timezone.utc) - timedelta(days=retraction_interval),
            DATETIME_FORMAT,
        )

        pulled_indicators = set()
        self.logger.info(
            message=(
                f"{self.log_prefix}: Pulling modified indicators "
                f"from {PLATFORM_NAME}."
            )
        )
        profile_filter = self._get_profile_filter_query_param(data_profiles)
        type_to_filter = self._get_type_filter_query_param(iocs_to_be_pulled)
        try:
            page_number = 1
            headers = self.infoblox_tide_helper.get_auth_headers(api_key)
            for page_start_time, page_end_time in self._create_time_based_pagination(
                start_time, end_time
            ):
                ioc_fetch_count = 0
                for threat_data in self._fetch_threat_data(
                    base_url=base_url,
                    headers=headers,
                    fetch_start_time=page_start_time,
                    fetch_end_time=page_end_time,
                    iocs_to_be_pulled=iocs_to_be_pulled,
                    profile_filter=profile_filter,
                    type_to_filter=type_to_filter,
                    page_number=page_number,
                    is_retraction=True,
                ):
                    pulled_indicators.add(threat_data)
                    ioc_fetch_count += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{ioc_fetch_count} modified IoC(s) in page "
                    f"{page_number} from {PLATFORM_NAME}."
                )
                page_number += 1
        except InfobloxTIDEPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while pulling modified"
                f"indicators from {PLATFORM_NAME} server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise InfobloxTIDEPluginException(err_msg)

        for ioc_page in source_indicators:
            source_unique_iocs = set()
            for ioc in ioc_page:
                source_unique_iocs.add(ioc.value)
            retracted_iocs = source_unique_iocs - pulled_indicators
            self.logger.info(
                f"{self.log_prefix}: {len(retracted_iocs)} indicator(s) will "
                f"be marked as retracted from {len(source_unique_iocs)} total "
                f"indicator(s) present in cloud exchange for {PLATFORM_NAME}."
            )
            yield list(retracted_iocs), False

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Share Indicators", value="add"),
        ]

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "add":
            properties = self._fetch_properties()
            profiles = self._fetch_profiles()
            default_profile_value = (
                list(profiles.keys())[0] if len(profiles) > 0 else "create"
            )
            return [
                {
                    "label": "Profile",
                    "key": "profile",
                    "type": "choice",
                    "mandatory": True,
                    "choices": [
                        {
                            "key": key,
                            "value": key,
                        }
                        for key, _ in profiles.items()
                    ]
                    + [{"key": "Create new profile", "value": "create"}],
                    "default": default_profile_value,
                    "description": "Select a data profile to push data into.",
                },
                {
                    "label": "New Profile Name",
                    "key": "create_profile_name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Name of the data profile to create if it does not"
                        " exist."
                    ),
                },
                {
                    "label": "Property",
                    "key": "property",
                    "type": "choice",
                    "mandatory": True,
                    "choices": [
                        {
                            "key": key,
                            "value": key,
                        }
                        for key in properties
                    ],
                    "default": properties[0],
                    "description": (
                        "Select threat classification for IoC. For more"
                        " details navigate to Monitor > Research >"
                        " Resources > Classification Guide page on the"
                        " Infoblox platform."
                    ),
                },
            ]

    def validate_action(self, action: Action):
        """Validate Infoblox TIDE action configuration."""
        if action.value not in ["add"]:
            self.logger.error(
                message=f"{self.log_prefix}: Unsupported action {action.label}"
                " provided. Allowed action is 'Share Indicators'."
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        profile_name = action.parameters.get("profile")
        create_profile = action.parameters.get("create_profile_name")
        if not profile_name:
            err_msg = "Profile is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(profile_name, str):
            err_msg = "Invalid Profile provided in action parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if profile_name == "create":
            if not create_profile:
                err_msg = "Profile name is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            if not isinstance(create_profile, str):
                err_msg = "Invalid Profile name provided in action parameters."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        property_name = action.parameters.get("property")
        if not property_name:
            err_msg = "Property is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(property_name, str):
            err_msg = "Invalid Property provided in action parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        success_msg = f"Validation successful for {action.value} action."
        self.logger.debug(f"{self.log_prefix}: {success_msg}")
        return ValidationResult(
            success=True,
            message=success_msg,
        )

    def _create_batch_of_1lac(
        self, ioc_dict: Dict[str, List[Dict]]
    ) -> Dict[str, List[List[Dict]]]:
        """
        Divide a list of IoC records into batches of DEFAULT_PUSH_BATCH.

        Args:
            ioc_dict (Dict[str, List[Dict]]): A dictionary containing IoC
                types as keys and list of IoC records as values.

        Returns:
            Dict[str, List[Dict]]: A dictionary of IoC batches with the keys
                as IoC types and the values as a list of dictionaries where
                each dictionary represents an IoC record.
        """
        for key, value_list in ioc_dict.items():
            if len(value_list) < DEFAULT_PUSH_BATCH:
                ioc_dict[key] = [value_list]
                continue
            batches = [
                value_list[i: i + DEFAULT_PUSH_BATCH]
                for i in range(0, len(value_list), DEFAULT_PUSH_BATCH)
            ]
            ioc_dict[key] = batches

        return ioc_dict

    def _create_push_batch_by_type(
        self, indicators: List[Indicator], source_label: str, property: str
    ) -> Dict[str, List[List[Dict]]]:
        """
        Create IoC batches for given indicators and source label.

        Args:
            indicators (List[Indicator]): List of Indicator objects.
            source_label (str): Source label for the IoCs to be pushed.
            property (str): Property for the IoCs to be pushed.

        Returns:
            Dict[str, List[List[Dict]]]: A dictionary of IoC batches with the
                keys as IoC types and the values as a list of dictionaries
                where each dictionary represents an IoC record.
        """
        ioc_batches = {"hash": [], "host": [], "ip": [], "url": []}
        skipped_iocs = 0
        count = 0
        skipped_ioc_types = set()
        for indicator in indicators:
            count += 1
            indicator_type = indicator.type
            if indicator_type not in [
                "hostname",
                "sha256",
                "md5",
                "ipv4",
                "ipv6",
                "url",
            ]:
                skipped_ioc_types.add(indicator_type)
                skipped_iocs += 1
                continue
            record_base = {
                "threat_label": source_label,
                "property": property,
                "notes": indicator.comments,
            }
            if severity := self._severity_mapping(indicator.severity, "push"):
                record_base["threat_level"] = severity
            if confidence := self._confidence_normalization(
                    indicator.reputation, "push"
            ):
                record_base["confidence"] = confidence
            if indicator_type in HASH_TYPES:
                record_base["hash"] = indicator.value
                record_base["hash_type"] = indicator_type
                ioc_batches["hash"].append(record_base)
            elif indicator_type in IP_TYPES:
                record_base["ip"] = indicator.value
                ioc_batches["ip"].append(record_base)
            elif indicator_type == "hostname":
                record_base["host"] = indicator.value
                ioc_batches["host"].append(record_base)
            elif indicator_type == "url":
                record_base["url"] = indicator.value
                ioc_batches["url"].append(record_base)
            else:
                skipped_iocs += 1
        self.logger.info(
            message=(
                f"{self.log_prefix}: {count - skipped_iocs} IoC(s)"
                f" will be shared to Infoblox TIDE. Skipped {skipped_iocs}"
                " IoC(s) as they are not supported by Infoblox TIDE."
            ),
            details=f"Skipped IoC types: {', '.join(skipped_ioc_types)}",
        )
        ioc_batches = self._create_batch_of_1lac(ioc_batches)
        return ioc_batches

    def push(
        self,
        indicators: List[Indicator],
        action_dict: Dict,
        source: str = None,
        business_rule: str = None,
        plugin_name: str = None,
    ) -> PushResult:
        """Push given indicators to Infoblox TIDE.

        Args:
            indicators (List[Indicator]): List of indicators received from
            business rule.
            action_dict (Dict): Action Dictionary

        Returns:
            PushResult: PushResult containing flag and message.
        """
        action_label = action_dict.get("label")
        self.logger.info(
            f"{self.log_prefix}: Executing push method for"
            f' "{action_label}" target action.'
        )
        action_value = action_dict.get("value")
        if action_value != "add":
            err_msg = (
                "Invalid action parameter selected. Allowed value is "
                "'Share Indicators'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise InfobloxTIDEPluginException(err_msg)
        base_url, api_key, _, _, _, _, _, _ = (
            self.infoblox_tide_helper.get_configuration_parameters(
                self.configuration,
            )
        )
        source_label = f"Netskope CE | {plugin_name}" if plugin_name else "netskope-ce"
        profile = action_dict.get("parameters", {}).get("profile")
        create_profile_name = action_dict.get(
            "parameters",
            {},
        ).get("create_profile_name")
        property = action_dict.get("parameters", {}).get("property")
        if profile == "create":
            existing_profiles = self._fetch_profiles()
            if create_profile_name in existing_profiles:
                self.logger.info(
                    f"{self.log_prefix}: Skipped creating profile "
                    f"{create_profile_name} as it already exists."
                )
                profile = create_profile_name
            else:
                profile = self._create_profile(create_profile_name)
                # Sleep for 60 seconds as pushing data instantly into
                # newly created profile sometimes gives 400 bad request error
                # as infoblox sever takes some time to create the profile
                self.logger.debug(
                    f"{self.log_prefix}: Sleeping for 60 seconds before"
                    " sharing data to newly created profile to incorporate"
                    f" profile creation delay on {PLATFORM_NAME} server."
                )
                time.sleep(DEFAULT_SLEEP_TIME)
        indicator_batches = self._create_push_batch_by_type(
            indicators, source_label, property
        )
        total_push_count = 0
        total_skip_count = 0
        for ioc_type, indicator_lists in indicator_batches.items():
            for batch_number, indicator_list in enumerate(
                indicator_lists, start=1
            ):
                if not indicator_list:
                    continue
                logger_msg = (
                    f"sharing {len(indicator_list)} IoC(s) of type"
                    f" {ioc_type} to {PLATFORM_NAME} server for"
                    f" batch {batch_number}"
                )
                try:
                    response = self.infoblox_tide_helper.api_helper(
                        logger_msg=logger_msg,
                        method="POST",
                        url=f"{base_url}/tide/api/data/batches",
                        headers=self.infoblox_tide_helper.get_auth_headers(
                            api_key,
                        ),
                        json={
                            "feed": {
                                "profile": profile,
                                "record_type": ioc_type,
                                "external_id": source_label,
                                "record": indicator_list,
                            }
                        },
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        is_handle_error_required=True,
                        is_validation=False,
                        is_retraction=False,
                    )
                    num_success = response.get("num_successful")
                    num_error = response.get("num_errors")
                    error_messages = response.get("errors", "")
                    total_push_count += num_success
                    total_skip_count += num_error
                except InfobloxTIDEPluginException as err:
                    err_msg = (
                        f"Failed to share {len(indicator_list)} IoC(s) of"
                        f" type {ioc_type} to {PLATFORM_NAME} for batch"
                        f" {batch_number}."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg} Error: {err}"
                    )
                    total_skip_count += len(indicator_list)
                    continue
                except Exception as err:
                    err_msg = f"Unexpected error occurred while {logger_msg}."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {err}",
                        details=traceback.format_exc(),
                    )
                    total_skip_count += len(indicator_list)
                    continue
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Successfully shared {num_success}"
                        f" IoC(s), failed to share {num_error} IoC(s) of type"
                        f" {ioc_type} to Infoblox TIDE for batch {batch_number}."
                        f" Total IoC(s) shared - {total_push_count}. Total"
                        f" IoC(s) skipped - {total_skip_count}."
                    ),
                    details=f"Reason for failure {json.dumps(error_messages)}",
                )
        return PushResult(
            success=True, message="Successfully shared indicators."
        )

    def _validate_connectivity(
        self, base_url: str, api_key: str, data_profiles: str
    ):
        """
        Validate API key by making REST API call.

        Args:
            base_url (str): Base URL.
            api_key (str): Infoblox TIDE API Key.

        Returns:
            ValidationResult: Validation result containing success
            flag and message.
        """
        logger_msg = f"validating connectivity with {PLATFORM_NAME} server"
        data_profiles = data_profiles.split(",") if data_profiles.strip() else []
        try:
            profiles = self._fetch_profiles(
                logger_msg=logger_msg,
                is_validation=True,
                base_url=base_url,
                api_key=api_key,
            )
            if data_profiles:
                invalid_profiles = []
                for profile in data_profiles:
                    profile = profile.strip()
                    if profile not in profiles:
                        invalid_profiles.append(profile)
                if invalid_profiles:
                    error = (
                        f"Invalid profile(s) {', '.join(invalid_profiles)}"
                        " provided in configuration parameters."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {error}"
                    )
                    return ValidationResult(
                        success=False,
                        message=error,
                    )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                f"connectivity with {PLATFORM_NAME} server"
                " and plugin configuration."
            )
            return ValidationResult(
                success=True,
                message="Validation Successful.",
            )
        except InfobloxTIDEPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = (
                f"Unexpected validation error occurred while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        allowed_values: List = None,
        max_value: int = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred. ",
    ):
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            allowed_values (List, optional): List of allowed values for the
                configuration field. Defaults to None.
            max_value (int, optional): Maximum allowed value for the
                configuration field. Defaults to None.
            custom_validation_func (Callable, optional): Custom validation
                function to be applied. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            validation_err_msg (str, optional): Error message to be logged in
                case of validation failure. Defaults to "Validation error
                occurred. ".

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if field_type == str:
            field_value = field_value.strip()
        if is_required and not isinstance(field_value, int) and not field_value:
            err_msg = f"{field_name} is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if is_required and not isinstance(field_value, field_type) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg}{err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if allowed_values:
            allowed_values_str = ", ".join(
                [allowed_value.capitalize() for allowed_value in allowed_values]
            )
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'. Allowed values are"
                f" {allowed_values_str}."
            )
            if field_type == str and field_value not in allowed_values:
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif field_type == list:
                for value in field_value:
                    if value not in allowed_values:
                        self.logger.error(
                            f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                        )
                        return ValidationResult(
                            success=False,
                            message=err_msg,
                        )
        if max_value and isinstance(field_value, int) and (
            field_value > max_value or field_value <= 0
        ):
            if max_value == INTEGER_THRESHOLD:
                max_value = "2^62"
            err_msg = (
                f"Invalid {field_name} provided in configuration"
                " parameters. Valid value should be an integer "
                f"greater than 0 and less than {max_value}."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}{err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def validate(self, configuration: Dict):
        """Validate the Plugin's configuration parameters."""
        (
            base_url,
            api_key,
            iocs_to_be_pulled,
            is_pull_required,
            retraction_interval,
            enable_tagging,
            initial_pull_range,
            data_profiles,
        ) = self.infoblox_tide_helper.get_configuration_parameters(
            configuration,
        )

        # Validate base url
        if validation_result := self._validate_configuration_parameters(
            field_name="API Base URL",
            field_value=base_url,
            field_type=str,
            custom_validation_func=self._validate_url,
        ):
            return validation_result

        # Validate API Key
        if validation_result := self._validate_configuration_parameters(
            field_name="API Key",
            field_value=api_key,
            field_type=str,
        ):
            return validation_result

        # Validate IoC types to be pulled
        if validation_result := self._validate_configuration_parameters(
            field_name="Type of Threat data to pull",
            field_value=iocs_to_be_pulled,
            field_type=list,
            allowed_values=INDICATOR_TYPES,
        ):
            return validation_result

        # Validate Data profiles
        if data_profiles and (
            validation_result := self._validate_configuration_parameters(
                field_name="Data Profiles",
                field_value=data_profiles,
                field_type=str,
            )
        ):
            return validation_result

        # Validate Enable Polling
        if validation_result := self._validate_configuration_parameters(
            field_name="Enable Polling",
            field_value=is_pull_required,
            field_type=str,
            allowed_values=["yes", "no"],
        ):
            return validation_result

        # Validate Enable Tagging
        if validation_result := self._validate_configuration_parameters(
            field_name="Enable Tagging",
            field_value=enable_tagging,
            field_type=str,
            allowed_values=["yes", "no"],
        ):
            return validation_result

        # Validate Initial Pull Range
        if validation_result := self._validate_configuration_parameters(
            field_name="Initial Range",
            field_value=initial_pull_range,
            field_type=int,
            max_value=INTEGER_THRESHOLD,
        ):
            return validation_result

        # Validate Retraction interval
        if validation_result := self._validate_configuration_parameters(
            field_name="Retraction Interval",
            field_value=retraction_interval,
            field_type=Union[int, None],
            max_value=INTEGER_THRESHOLD,
            is_required=False,
        ):
            return validation_result

        return self._validate_connectivity(
            base_url=base_url, api_key=api_key, data_profiles=data_profiles
        )
