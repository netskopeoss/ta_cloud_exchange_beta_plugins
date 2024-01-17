import requests
from datetime import datetime, timedelta
import traceback
import hashlib
import uuid
from urllib.parse import urlparse
import re
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
)

MAX_PAGE_SIZE = 100
MAX_PULL_PAGE_SIZE = 2000
PLUGIN_NAME = "CommVault CTE Plugin"
MAX_RETRY_COUNT = 4
TIME_OUT = 30
TOKEN_VALIDITY_SECONDS = 7 * 24 * 60 * 60  # 7 days
TOKEN_EXPIRY_BUFFER_SECONDS = 2 * 24 * 60 * 60  # 2 days
RE_DEL_HTML = re.compile(r"(<span[^>]*>(.+?)</span>)|(<.*?>)")
RE_GET_LINK = re.compile(r"<a[^>]*href=(.+?)>.+?</a>")
ACCESS_TOKEN_NAME_PREFIX = "netskope-access-token-"
ANOMALOUS_EVENTCODE_STRINGS = {
    "7:333": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
    "14:336": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
    "14:337": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
    "69:59": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
    "69:60": {"comments": RE_DEL_HTML, "extended_info": RE_GET_LINK},
}


COMMVAULT_TO_NETSKOPE_SEVERITY = {
    -1: SeverityType.UNKNOWN,
    0: SeverityType.LOW,
    1: SeverityType.LOW,
    2: SeverityType.LOW,
    3: SeverityType.MEDIUM,
    4: SeverityType.MEDIUM,
    5: SeverityType.MEDIUM,
    6: SeverityType.HIGH,
    7: SeverityType.HIGH,
    8: SeverityType.HIGH,
    9: SeverityType.CRITICAL,
    10: SeverityType.CRITICAL,
}

NETSKOPE_TO_COMMVAULT_SEVERITY = {
    SeverityType.UNKNOWN: 0,
    SeverityType.LOW: 1,
    SeverityType.HIGH: 2,
    SeverityType.MEDIUM: 4,
    SeverityType.CRITICAL: 5,
}


class CommVaultPlugin(PluginBase):
    """The CommVault plugin implementation."""

    def _validate_url(self, url: str) -> bool:
        parsed = urlparse(url.strip())
        flag = (parsed.scheme.strip() != "") and (parsed.netloc.strip() != "")
        return flag

    def http_request(self, method, custom_message=None, *args, **kwargs):
        if method == "GET":
            resp = requests.get(*args, **kwargs)
        if method == "POST":
            resp = requests.post(*args, **kwargs)
        if method == "PUT":
            resp = requests.put(*args, **kwargs)
        return self.handle_status_code(resp, custom_message=custom_message)

    def _validate_credentials(self, configuration: dict) -> ValidationResult:
        try:
            base_url = configuration["commandcenter_url"].strip().strip("/")
            headers = {
                "authToken": configuration["auth_token"],
                "Accept": "application/json",
            }
            response = requests.get(
                f"{base_url}/Events",
                headers=headers,
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            if response.status_code == 200:
                self.logger.info(
                    f"{PLUGIN_NAME}: Credentials validated successfully"
                )
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            else:
                return ValidationResult(
                    success=False, message="Incorrect Credentials Provided."
                )
        except requests.ConnectionError as ex:
            self.logger.error(repr(ex))
            return ValidationResult(
                success=False, message="Incorrect Credentials provided."
            )
        except Exception as ex:
            self.logger.error(str(ex))
            return ValidationResult(
                success=False,
                message=(
                    "Error occurred while validating configuration parameters."
                    " Check logs for more detail."
                ),
            )

    def handle_status_code(
        self,
        response,
        custom_message: str = None,
    ):
        """Handle status code of response.

        Args:
            response (response): response of API call
            error_code (str, optional): error code. Defaults to None.
            custom_message (str, optional): custom message to write. Defaults
            to None.
            plugin (str, optional): plugin name. Defaults to None.
        """
        custom_message_str = (
            (custom_message + ",") if custom_message is not None else ""
        )
        error_str_prefix = f"{PLUGIN_NAME}: {custom_message_str}"

        if response.status_code == 200 or response.status_code == 201:
            try:
                return response.json()
            except ValueError as err:
                error = (
                    f"{error_str_prefix} Exception"
                    + " occurred while parsing JSON response."
                )
                self.logger.error(error, details=traceback.format_exc())
                raise err
        elif response.status_code == 401:
            self.logger.error(
                (
                    f"{error_str_prefix} Received"
                    + " exit code 401, Authentication Error."
                ),
                details=response.text,
            )
            self.notifier.warn(
                f"{error_str_prefix} Authentication Error,"
                + " probably token has expired"
            )
            self.logger.error(
                f"{error_str_prefix} Notified Authentication error"
            )
        elif response.status_code == 403:
            self.logger.error(
                (
                    f"{error_str_prefix},"
                    + " Received exit code 403, Forbidden Error."
                ),
                details=response.text,
            )
        elif response.status_code == 429:
            self.logger.error(
                (
                    f"{error_str_prefix},"
                    + " Received exit code 429, Too many requests."
                ),
                details=response.text,
            )
        elif response.status_code == 409:
            self.logger.error(
                (
                    f"{error_str_prefix},"
                    " Received exit code 409, Concurrency found while calling"
                    " the API."
                ),
                details=response.text,
            )
        elif response.status_code >= 400 and response.status_code < 500:
            self.logger.error(
                (
                    f" {error_str_prefix} Received"
                    f" exit code {response.status_code}, HTTP client Error."
                    + f"{response.text}"
                ),
                details=response.text,
            )
        elif response.status_code >= 500 and response.status_code < 600:
            self.logger.error(
                (
                    f" {error_str_prefix} Received"
                    f" exit code {response.status_code}, HTTP server Error."
                ),
                details=response.text,
            )
        response.raise_for_status()

    def fetch_events(self, from_time: datetime = None) -> tuple:
        """
        Fetches the events from Commvault REST API from from_time onwards
        """
        base_url = self.configuration["commandcenter_url"].strip().strip("/")
        params = {
            "level": 10,
            "showAnomalous": True,
        }
        if from_time and isinstance(from_time, datetime):
            params["fromTime"] = str(int(from_time.timestamp()))
        response = self.http_request(
            "GET",
            "Error occurred while pulling indicators",
            f"{base_url}/Events",
            params=params,
            headers=self._get_headers(),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )

        if not response.get("commservEvents"):
            self.logger.info(
                f"{PLUGIN_NAME}: No new events from {str(from_time)}"
            )
            return []

        events = response.get("commservEvents")
        events = [
            d
            for d in events
            if d.get("eventCodeString") in ANOMALOUS_EVENTCODE_STRINGS
        ]
        events = sorted(events, key=lambda d: d.get("timeSource"))
        for event in events:
            try:
                client_id = event.get("clientEntity").get("clientId")
                client_hostname = self.get_client_hostname(client_id)
                event["client_hostname"] = client_hostname
            except KeyError:
                pass

        return events

    def get_client_hostname(self, client_id: int) -> str:
        "Get the hostname from client properties using client id"
        base_url = self.configuration["commandcenter_url"].strip().strip("/")
        response = self.http_request(
            "GET",
            "Error occurred in get_client_hostname()",
            f"{base_url}/Client/{int(client_id)}",
            params={},
            headers=self._get_headers(),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        hostname = ""
        try:
            hostname = response["clientProperties"][0]["client"][
                "clientEntity"
            ]["hostName"]
        except KeyError as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Error while getting client hostname: {str(e)}"
            )
        return hostname

    def pull(self):
        """Pull indicators from CommVault."""
        try:
            indicators = []
            base_url = (
                self.configuration["commandcenter_url"].strip().strip("/")
            )
            self.logger.info(
                f"{PLUGIN_NAME}: Pulling indicators from {base_url} "
            )
            if not self.last_run_at:
                from_time = datetime.now() - timedelta(
                    days=int(self.configuration["days"])
                )
                self.logger.info(
                    f"{PLUGIN_NAME}: will run for the first time"
                    + f" and pull events from: {str(from_time)}"
                )
            else:
                from_time = self.last_run_at
                self.logger.info(
                    f"{PLUGIN_NAME}: Pulling events"
                    + f" from timestamp: {str(from_time)}"
                )
            events = self.fetch_events(from_time)
            if events and len(events) > 0:
                for event in events:
                    detectedTime = datetime.fromtimestamp(
                        int(event.get("timeSource"))
                    )
                    event_desc = event.get("description", "")
                    event_code = event.get("eventCodeString")
                    re_extended_info = ANOMALOUS_EVENTCODE_STRINGS[
                        event_code
                    ].get("extended_info")
                    re_comments = ANOMALOUS_EVENTCODE_STRINGS[event_code].get(
                        "comments"
                    )
                    if len(re_extended_info.findall(event_desc)) > 0:
                        extended_info = (
                            re_extended_info.findall(event_desc)[0]
                            .strip()
                            .strip('"')
                            .strip('"')
                        )
                        res = urlparse(extended_info)
                        if not all([res.scheme, res.netloc]):
                            extended_info = ""
                    else:
                        extended_info = ""
                    comments = re_comments.sub(
                        "", event.get("description", "")
                    )
                    comments = " ".join(comments.split())
                    comments = re.sub(
                        "Please click here for more details.",
                        "",
                        comments,
                        flags=re.I,
                    )
                    indicators.append(
                        Indicator(
                            value=event.get("client_hostname"),
                            type=IndicatorType.URL,
                            firstSeen=detectedTime,
                            lastSeen=detectedTime,
                            severity=COMMVAULT_TO_NETSKOPE_SEVERITY.get(
                                event.get("severity"), -1
                            ),
                            tags=[],
                            comments=comments,
                            extendedInformation=extended_info,
                        )
                    )

        except Exception as err:
            self.logger.error(
                (
                    f"{PLUGIN_NAME}: Error occured while pulling indicators,"
                    f" {err}"
                ),
                details=traceback.format_exc(),
            )
            raise err
        return indicators

    def push(self, indicators, action_dict) -> PushResult:
        """Push indicators to CommVault."""
        try:
            base_url = (
                self.configuration["commandcenter_url"].strip().strip("/")
            )
            self.logger.info(
                f"{PLUGIN_NAME}: Pushing indicators started at: "
                + f"{str(datetime.now())}"
            )
            # build the body
            request_body = {"anomalyDetections": []}
            for indicator in indicators:
                indicator_value = indicator.value.strip()
                lastSeen = indicator.lastSeen
                extendedInformation = indicator.extendedInformation
                if action_dict.get("value") == "report_client_as_anomalous":
                    if indicator.type == IndicatorType.URL:
                        event_id = int(
                            hashlib.sha1("URL".encode("utf-8")).hexdigest(), 16
                        ) % (10**8)
                        anomaly_dict = {
                            "client": {"hostName": indicator_value},
                            "anomalyDetectedBy": {
                                "vendorName": "NetSkope CTE",
                                "anomalyDetails": [
                                    {
                                        "anomalyEvents": [
                                            {
                                                "detectionTime": int(
                                                    lastSeen.timestamp()
                                                ),
                                                "eventId": str(uuid.uuid4())[
                                                    :8
                                                ],
                                                "eventUrl": (
                                                    extendedInformation
                                                ),
                                            }
                                        ],
                                        "detectionTime": int(
                                            lastSeen.timestamp()
                                        ),
                                        "anomalyReason": indicator.comments,
                                        "eventId": str(event_id),
                                        "timesSeen": 1,
                                        "eventType": "URL",
                                        "additionalInfo": [
                                            {
                                                "dataType": 2,
                                                "name": "SeverityScore",
                                                "value": str(
                                                    NETSKOPE_TO_COMMVAULT_SEVERITY.get(
                                                        indicator.severity
                                                    )
                                                ),
                                            }
                                        ],
                                    }
                                ],
                            },
                        }
                        request_body["anomalyDetections"].append(anomaly_dict)
            self.http_request(
                "PUT",
                "Error while pushing indicator",
                f"{base_url}/Client/Action/Report/Bulk/Anomaly",
                json=request_body,
                params={},
                headers=self._get_headers(),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )

        except Exception as e:
            return PushResult(
                success=False,
                message=f"Could not push to CommVault. Exception: {str(e)}.",
            )

        return PushResult(
            success=True,
            message=f"Pushed indicators successfully to CommVault",
        )

    def _get_headers(self) -> dict:
        """Get common headers."""
        headers = {
            "AuthToken": self.configuration["auth_token"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        return headers

    def validate(self, configuration):
        """Validate the configuration."""
        if (
            "commandcenter_url" not in configuration
            or not configuration["commandcenter_url"].strip()
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: No Command Center URL found in the"
                f" configuration parameters."
            )
            return ValidationResult(
                success=False,
                message=(
                    f"Command Center URL can not be empty."
                    + f" Supplied Command Center URL:"
                    f" {configuration['commandcenter_url']}"
                ),
            )
        if not self._validate_url(configuration["commandcenter_url"]):
            self.logger.error(
                f"{PLUGIN_NAME}: Invalid Command Center URL found in the"
                " configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Command Center URL provided."
            )
        if "auth_token" not in configuration:
            self.logger.error(
                f"{PLUGIN_NAME}: No auth_token key found in the configuration"
                " parameters."
            )
            return ValidationResult(
                success=False, message="Authentication Token can not be empty."
            )
        try:
            if (
                "days" not in configuration
                or not configuration["days"]
                or int(configuration["days"]) <= 0
            ):
                self.logger.error(
                    f"{PLUGIN_NAME}: Validation error occured Error: Invalid"
                    " days provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Number of days provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid Number of days provided.",
            )
        return self._validate_credentials(configuration)

    def get_actions(self):
        """Get available actions."""
        return [
            Action(
                label="Report client as Anomalous",
                value="report_client_as_anomalous",
            )
        ]

    def validate_action(self, action: Action):
        """Validate Mimecast configuration."""

        if action.value not in [
            "report_client_as_anomalous",
        ]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
