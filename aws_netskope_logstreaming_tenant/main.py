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

AWS Netskope LogStreaming plugin.
"""

import datetime
import gzip
import threading
import traceback
import json
import pandas as pd
import csv
import time
import requests
from typing import List
from io import BytesIO, StringIO
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from urllib.parse import unquote
from botocore.exceptions import ClientError

from netskope.common.utils import (
    Notifier,
    get_sub_type_config_mapping,
)
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.common.utils.provider_plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.common.utils import back_pressure
from netskope.common.models import NetskopeFieldType, FieldDataType

from .utils.helper import AWSD2CProviderPluginHelper
from .utils.exceptions import AWSD2CProviderException
from .utils.validator import AWSD2CProviderValidator
from .utils.client import AWSD2CProviderClient
from .utils.router_helper import get_all_subtypes

from .utils.constants import (
    MODULE_NAME,
    PLUGIN_VERSION,
    PLATFORM_NAME,
    MAINTENANCE_PULL,
    TYPE_EVENT,
    DEFAULT_WAIT_TIME,
    RESULT,
    AUTHENTICATION_METHODS,
    REGIONS,
    BACK_PRESSURE_WAIT_TIME,
    BATCH_SIZE,
    NLS_EVENT_MAPPINGS,
)

plugin_provider_helper = PluginProviderHelper()
notifier = Notifier()


class AWSD2CProviderPlugin(PluginBase):
    """AWS Netskope LogStreaming ProviderPlugin class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function.

        Args:
            name (str): Configuration Name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.should_exit = threading.Event()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.aws_d2c_provider_helper = AWSD2CProviderPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AWSD2CProviderPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    @classmethod
    def supported_subtypes(cls):
        """Get the subtypes defined in router_helper."""
        return get_all_subtypes()

    def transform(self, raw_data, data_type, subtype, **kwargs) -> List:
        """Transform the raw netskope target platform supported.

        Args:
            raw_data (dict): Raw data to be transformed.
            data_type (str): Data type of the raw data.
            subtype (str): Subtype of the raw data.

        Returns:
            List: List of transformed data
        """
        return raw_data

    def _validate_auth_params(
        self, configuration, user_agent, queue_name, validation_err_msg
    ):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin
            configuration parameters.
            user_agent (str): User agent string.
            queue_name (str): Queue name.
        """
        try:
            aws_validator = AWSD2CProviderValidator(
                configuration.get("region_name", "").strip(),
                self.logger,
                self.proxy,
                self.log_prefix,
                user_agent,
            )
            aws_client = AWSD2CProviderClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                user_agent,
            )
            aws_client.set_credentials()
            sqs_client = aws_validator.validate_credentials(aws_client)
            aws_validator.validate_queue_url_using_name(sqs_client, queue_name)
            return True, "success"
        except AWSD2CProviderException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg}" f" Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return False, str(exp)
        except Exception as err:
            error_msg = (
                "Invalid authentication parameters provided."
                " Check logs for more details."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg}" f" Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return False, error_msg

    def _tenant_creation_and_validation(self, queue_name, checkpoint):
        """Validate the Plugin configuration parameters.

        Args:
            queue_name (str): Queue name.
            checkpoint (dict): Dict object having all the Plugin
            configuration parameters.

        Returns:
            tuple: Tuple of success flag, message and checkpoint
        """

        tenant_creation = True
        if self.storage and self.storage.get("existing_configuration", {}).get(
            "tenantName"
        ):
            tenant_creation = False
            existing_tenant_name = self.storage.get(
                "existing_configuration", {}
            ).get("tenantName")
            if existing_tenant_name != queue_name:
                err_msg = (
                    f" AWS SQS Queue Name '{queue_name}' is mismatched with"
                    f" '{existing_tenant_name}'"
                )
                return False, err_msg, checkpoint

        if tenant_creation:
            checkpoint = {
                "events": datetime.datetime.now(),
            }
            self.storage["existing_configuration"] = {"tenantName": queue_name}

        return True, "success", checkpoint

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """

        checkpoint = None
        validation_err_msg = "Validation error occurred."

        user_agent = self.aws_d2c_provider_helper._add_user_agent()

        authentication_method = configuration.get("v2token", "").strip()

        if not authentication_method:
            err_msg = (
                "Authentication Method is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} " f"Error: {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )
        elif not isinstance(authentication_method, str):
            err_msg = (
                "Invalid Authentication Method found in the "
                "configuration parameters. Authentication Method "
                "should be a valid string."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} " f"Error: {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )
        if authentication_method not in AUTHENTICATION_METHODS:
            error_msg = (
                "Invalid value for Authentication Method provided. "
                "Allowed values are "
                "'AWS IAM Roles Anywhere' or 'Deployed on AWS'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}"
                f" Error: {error_msg}"
            )
            return ValidationResult(
                success=False, message=f"{error_msg}", checkpoint=checkpoint
            )

        if authentication_method == "aws_iam_roles_anywhere":
            pass_phrase = configuration.get("pass_phrase")
            if not pass_phrase:
                err_msg = (
                    "Password Phrase is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False, message=f"{err_msg}", checkpoint=checkpoint
                )
            elif not isinstance(pass_phrase, str):
                err_msg = (
                    "Invalid Password Phrase found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                    checkpoint=checkpoint,
                )
            # Validate Private Key File.
            private_key_file = configuration.get(
                "private_key_file", ""
            ).strip()
            if not private_key_file:
                error_msg = (
                    "Private Key is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix} {validation_err_msg} Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=error_msg,
                    checkpoint=checkpoint,
                )
            elif not isinstance(private_key_file, str):
                err_msg = (
                    "Invalid Private Key found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                    checkpoint=checkpoint,
                )
            else:
                try:
                    serialization.load_pem_private_key(
                        private_key_file.encode("utf-8"), None
                    )
                except Exception:
                    try:
                        serialization.load_pem_private_key(
                            private_key_file.encode("utf-8"),
                            password=str.encode(pass_phrase),
                        )
                    except Exception:
                        err_msg = (
                            "Invalid Private Key or Password Phrase provided."
                            " Verify the Private Key and Password Phrase."
                            " Private Key should be in a valid PEM format."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {validation_err_msg}"
                                f" Error: {err_msg}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        return ValidationResult(
                            success=False,
                            message=f"{err_msg}",
                            checkpoint=checkpoint,
                        )

            # Validate Certificate Body.
            public_certificate_file = configuration.get(
                "public_certificate_file", ""
            ).strip()
            if not public_certificate_file:
                error_msg = (
                    "Certificate Body is a required configuration"
                    " parameter when 'AWS IAM Roles Anywhere' "
                    "is selected as Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix} {validation_err_msg} Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                    checkpoint=checkpoint,
                )
            elif not isinstance(public_certificate_file, str):
                err_msg = (
                    "Invalid Certificate Body found in "
                    "the configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                    checkpoint=checkpoint,
                )
            else:
                try:
                    x509.load_pem_x509_certificate(
                        public_certificate_file.encode()
                    )
                except Exception:
                    err_msg = (
                        "Invalid Certificate Body provided. "
                        "Certificate Body should be in valid PEM Format."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {validation_err_msg} "
                            f"Error: {err_msg}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    return ValidationResult(
                        success=False,
                        message=f"{err_msg}",
                        checkpoint=checkpoint,
                    )

            # Validate Profile ARN.
            profile_arn = configuration.get("profile_arn", "").strip()
            if not profile_arn:
                error_msg = (
                    "Profile ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                    checkpoint=checkpoint,
                )
            elif not isinstance(profile_arn, str):
                err_msg = (
                    "Invalid Profile ARN found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                    checkpoint=checkpoint,
                )

            # Validate Role ARN.
            role_arn = configuration.get("role_arn", "").strip()
            if not role_arn:
                error_msg = (
                    "Role ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                    checkpoint=checkpoint,
                )

            elif not isinstance(role_arn, str):
                err_msg = (
                    "Invalid Role ARN found in the configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                    checkpoint=checkpoint,
                )

            # Validate Trust Anchor ARN.
            trust_anchor_arn = configuration.get(
                "trust_anchor_arn", ""
            ).strip()
            if not trust_anchor_arn:
                error_msg = (
                    "Trust Anchor ARN is a required configuration parameter "
                    "when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                    checkpoint=checkpoint,
                )

            elif not isinstance(trust_anchor_arn, str):
                err_msg = (
                    "Invalid Trust Anchor ARN found in the "
                    "configuration parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} Error: "
                    f"{err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                    checkpoint=checkpoint,
                )

        # Validate Region Name.
        region_name = configuration.get("region_name", "").strip()
        if not region_name:
            error_msg = (
                "AWS Region Name is a " "required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"Error: {error_msg}"
            )
            return ValidationResult(
                success=False, message=error_msg, checkpoint=checkpoint
            )
        elif not (isinstance(region_name, str)):
            error_msg = (
                "Invalid AWS Region Name value found in "
                "the configuration parameters. AWS Region Name "
                "should be a valid string."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}"
                f" Error: {error_msg}"
            )
            return ValidationResult(
                success=False, message=error_msg, checkpoint=checkpoint
            )
        elif region_name not in REGIONS:
            error_msg = (
                "Invalid AWS Region Name provided in "
                "the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}"
                f" Error: {error_msg}"
            )
            return ValidationResult(
                success=False, message=error_msg, checkpoint=checkpoint
            )

        # Validate AWS SQS Queue name.
        queue_name = configuration.get("tenantName", "").strip()
        if not queue_name:
            err_msg = (
                "AWS SQS Queue Name is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}" f"Error: {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )
        elif not isinstance(queue_name, str):
            err_msg = (
                "Invalid AWS SQS Queue Name found in the"
                " configuration parameters. SQS Queue Name"
                " should be a valid string."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}" f"Error: {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg, checkpoint=checkpoint
            )

        success, message = self._validate_auth_params(
            configuration, user_agent, queue_name, validation_err_msg
        )

        if not success:
            return ValidationResult(
                success=False,
                message=f"{message}",
                checkpoint=checkpoint,
            )

        # tenent creation and validation
        success, message, checkpoint = self._tenant_creation_and_validation(
            queue_name, checkpoint
        )
        if not success:
            return ValidationResult(
                success=False,
                message=f"{message}",
                checkpoint=checkpoint,
            )

        # validation successful
        validation_msg = f"Validation Successful for {PLATFORM_NAME} plugin."
        self.logger.debug(f"{self.log_prefix}: {validation_msg}")
        return ValidationResult(
            success=True,
            message=validation_msg,
            checkpoint=checkpoint,
        )

    def _get_messages_from_response(self, sqs_client, queue_url):
        """get messages from response
        Args:
            sqs_client: sqs client
            response: response
        """
        messages = []

        try:
            response = sqs_client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=2,
                MessageAttributeNames=["All"],
            )
            sqs_messages = response.get("Messages")
            if sqs_messages and isinstance(sqs_messages, list):
                for msg in sqs_messages:
                    if msg:
                        messages.append(msg)
                        sqs_client.delete_message(
                            QueueUrl=queue_url,
                            ReceiptHandle=msg["ReceiptHandle"]
                        )
        except (requests.exceptions.RequestException, ClientError) as e:
            err_msg = "Error occurred while communicating with SQS queue."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise AWSD2CProviderException(err_msg)
        except Exception as e:
            err_msg = (
                "Unexpected error occurred while receiving "
                "messages from SQS queue."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise AWSD2CProviderException(err_msg)

        return messages

    def _bifurcate_data(self, data_list, object_key, bucket_name):
        """Bifurcate the data.

        Args:
            data (bytes): The json data.
        """
        result = {}
        skip_count = 0
        for data in data_list:
            try:
                record_type = data.get("record_type")
                alert_type = data.get("alert_type")
                if record_type and record_type in NLS_EVENT_MAPPINGS:
                    target_key = NLS_EVENT_MAPPINGS.get(record_type)
                    result.setdefault(target_key, []).append(data)
                elif (
                    record_type
                    and record_type == "alert"
                    and alert_type
                    and alert_type in NLS_EVENT_MAPPINGS
                ):
                    target_key = NLS_EVENT_MAPPINGS.get(alert_type)
                    result.setdefault(target_key, []).append(data)
                elif data.get("x-cs-timestamp"):
                    result.setdefault("NLS WebTx", []).append(data)
                else:
                    skip_count += 1
            except Exception:
                skip_count += 1
                continue

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} out "
                f"of {len(data_list)} logs from file '{object_key}' "
                f"from bucket '{bucket_name}' due to invalid data or "
                "unsupported subtype."
            )

        for subtype, data in result.items():
            if data:
                yield data, subtype

    def _process_gzipped_csv_in_batches(
        self, data, object_key, bucket_name, batch_size
    ):
        """Process the gzipped CSV data in batches.

        Args:
            data (bytes): The gzipped CSV data.
            s3_client (boto3.client): The S3 client.
        """
        try:
            with gzip.GzipFile(fileobj=BytesIO(data), mode="rb") as gz:

                # Read the CSV content
                csv_content = gz.read().decode("utf-8")
                # Automatically detect delimiter
                sniffer = csv.Sniffer()
                # Default delimiter
                delimiter = ","
                try:
                    delimiter = sniffer.sniff(
                        csv_content.split("\n")[0]
                    ).delimiter
                except Exception as e:
                    err_msg = (
                        "Error occurred while detecting delimiter from"
                        " csv file. Using default delimiter ','."
                    )
                    self.logger.error(
                        message=f"{err_msg}. Error: {e}",
                        details=traceback.format_exc(),
                    )
                # batching for the batch size
                for chunk in pd.read_csv(
                    StringIO(csv_content),
                    delimiter=delimiter,
                    engine="python",
                    on_bad_lines="skip",
                    chunksize=batch_size,
                ):
                    chunk.replace(
                        to_replace=r"^-$",
                        value="",
                        regex=True,
                        inplace=True,
                    )

                    file_data = json.loads(chunk.to_json(orient="records"))

                    for data, subtype in self._bifurcate_data(
                        file_data, object_key, bucket_name
                    ):
                        yield data, subtype

        except Exception as e:
            err_msg = (
                "Unexpected error occurred while processing s3 bucket file."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {e}",
                details=traceback.format_exc(),
            )
            raise AWSD2CProviderException(err_msg)

    def _process_messages(self, aws_client, messages: list):
        """Process the messages.

        Args:
            messages (list): List of messages.
            configuration (dict): The configuration dictionary.
        """
        file_data = []
        skip_count = 0
        for msg in messages:
            try:
                body = {}
                if msg.get("Body") and isinstance(msg.get("Body"), str):
                    body = json.loads(msg.get("Body"))

                for record in body.get("Records", []):
                    s3_info = record.get("s3", {})
                    bucket_name = s3_info.get("bucket", {}).get("name")
                    object_key_raw = s3_info.get("object", {}).get("key")
                    object_key = (
                        unquote(object_key_raw) if object_key_raw else ""
                    )

                    if object_key and object_key.endswith(".csv.gz"):
                        self.logger.debug(
                            f"{self.log_prefix}: Fetching '{object_key}'"
                            f" file data from '{bucket_name}' s3 bucket."
                        )
                        aws_client.set_credentials()
                        s3 = aws_client.get_s3_client()

                        response = s3.get_object(
                            Bucket=bucket_name, Key=object_key
                        )

                        data = response["Body"].read()

                        for (
                            file_data,
                            subtype,
                        ) in self._process_gzipped_csv_in_batches(
                            data,
                            object_key,
                            bucket_name,
                            batch_size=BATCH_SIZE,
                        ):
                            yield file_data, subtype
                    else:
                        skip_count += 1
                        continue
            except AWSD2CProviderException:
                skip_count += 1
                continue
            except Exception as e:
                err_msg = (
                    "Error occurred while processing SQS queue messages "
                    f"for {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}. Error: {e}",
                    details=traceback.format_exc(),
                )
                skip_count += 1
                continue

        if skip_count > 0:
            self.logger.debug(
                f"{self.log_prefix}: Skipped processing data for {skip_count}"
                " messages from SQS queue because either the file format"
                " or the data is of unsupported format."
            )

    def _get_bucket_data_in_batches(self, configuration):
        """Get the bucket data in batches.

        Args:
            configuration (dict): The configuration dictionary.
        """
        try:
            queue_name = configuration.get("tenantName", "").strip()
            user_agent = self.aws_d2c_provider_helper._add_user_agent()
            aws_client = AWSD2CProviderClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                user_agent,
            )
            aws_client.set_credentials()
            sqs_client = aws_client.get_sqs_client()

            try:
                response = sqs_client.get_queue_url(QueueName=queue_name)
            except Exception as e:
                err_msg = (
                    "Error occurred while getting SQS queue url "
                    f"for {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}. Error: {e}",
                    details=traceback.format_exc(),
                )
                raise AWSD2CProviderException(err_msg)

            # sqs queue url
            queue_url = response.get("QueueUrl", "").strip()

            # get the messages from the sqs queue
            messages = []
            messages = self._get_messages_from_response(sqs_client, queue_url)

            if len(messages) > 0:
                self.logger.debug(
                    f"{self.log_prefix}: {len(messages)} message(s) from queue"
                    f" '{queue_name}' will be processed."
                )
            else:
                self.logger.debug(
                    f"{self.log_prefix}: No message(s) available to process"
                    f" from queue '{queue_name}'."
                )

            # process the messages
            for batch_data, subtype in self._process_messages(
                aws_client, messages
            ):
                yield batch_data, subtype

        except AWSD2CProviderException:
            raise
        except ClientError as err:
            err_msg = (
                "Error occurred while connecting to "
                "AWS s3 client for {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {err}",
                details=traceback.format_exc(),
            )
            raise AWSD2CProviderException(err_msg)
        except Exception as e:
            err_msg = (
                "Error unexpected occurred while processing"
                f" s3 bucket data for {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {e}",
                details=traceback.format_exc(),
            )
            raise AWSD2CProviderException(err_msg)

    def update_storage_checkpoint(self, end_time):
        """
        Updates the checkpoint in storage for the given tenant.

        Args:
            end_time (datetime or str): The new checkpoint time.

        Returns:
            None
        """
        self.storage["events_checkpoint"] = end_time
        plugin_provider_helper.update_tenant_storage(self.name, self.storage)

    def load_maintenance(self, configuration):
        """maintainence pulling from the sqs queue.

        Args:
            configuration (dict): The configuration dictionary.
        """
        tenant_name = self.name if self.name else ""
        initial_start_time = datetime.datetime.now()

        while True:
            try:
                if not tenant_name:
                    self.logger.error(
                        f"{self.log_prefix}: Tenant with name"
                        f" {tenant_name} no longer exists.",
                        error_code="CE_1030",
                    )
                    return {"success": False}
                if back_pressure.STOP_PULLING:
                    self.logger.debug(
                        f"{self.log_prefix}: {MAINTENANCE_PULL} of "
                        f"event(s) for tenant {tenant_name} "
                        "is paused due to back pressure."
                    )
                    time.sleep(BACK_PRESSURE_WAIT_TIME)
                    continue

                tenant = plugin_provider_helper.get_tenant_details(
                    tenant_name, TYPE_EVENT
                )
            except Exception:
                error_msg = (
                    f"Tenant with name {tenant_name} no longer exists.",
                )
                self.logger.error(
                    f"{self.log_prefix}: {error_msg}",
                    error_code="CE_1030",
                )
                return {"success": False}

            if not (
                plugin_provider_helper.is_netskope_plugin_enabled(
                    tenant.get("name")
                )
                and plugin_provider_helper.is_module_enabled()
            ):
                self.logger.info(
                    f"{self.log_prefix}: The Plugin or the Module is Disabled "
                    "hence pulling will be skipped."
                )
                return {"success": True}

            now = datetime.datetime.now()
            time_delta = now - initial_start_time

            hours = time_delta.total_seconds() // 3600
            if hours >= 1:
                return {"success": True}

            end_time = now

            for file_data, subtype in self._get_bucket_data_in_batches(
                configuration
            ):
                yield file_data, subtype

            self.update_storage_checkpoint(end_time)
            time.sleep(DEFAULT_WAIT_TIME)

    def pull(
        self,
        data_type,
        iterator_name=None,
        pull_type=MAINTENANCE_PULL,
        configuration_name=None,
        start_time=None,
        end_time=None,
        destination_configuration=None,
        business_rule=None,
        override_subtypes=None,
        compress_historical_data=False,
        handle_forbidden=True,
    ):
        """Pull data from s3 bucket using sqs queue.

        Parameters:
            data_type (str): The type of data to pull.
            iterator_name (str, optional): The name of the iterator.
            Defaults to None.
            pull_type (str, optional): The type of pulling.
            Defaults to NetskopeClient.MAINTENANCE_PULLING.
            configuration_name (str, optional): The name of the configuration.
            Defaults to None.
            start_time (datetime, optional): The start time for pulling.
            Defaults to None.
            end_time (datetime, optional): The end time for pulling.
            Defaults to None.
            destination_configuration (str, optional): The destination
            configuration. Defaults to None.
            business_rule (str, optional): The business rule to apply.
            Defaults to None.
            override_subtypes (list, optional): List of overridden subtypes
            (For historical). Defaults to None.

        Returns:
            GeneratorObject: List of indicator objects received from
            Netskope along with types.
        """

        page_data = []
        sub_type_config_mapping = {}
        try:
            tenant_name = self.name if self.name else ""
            if not override_subtypes:
                sub_type_config_mapping, _ = get_sub_type_config_mapping(
                    tenant_name, data_type
                )

            self.should_exit.clear()
            back_pressure_thread = threading.Thread(
                target=back_pressure.should_stop_pulling,
                daemon=True,
                args=(self.should_exit,),
            )
            back_pressure_thread.start()

            for page_data, sub_type in self.load_maintenance(
                self.configuration
            ):
                self.log_message(
                    tenant_name,
                    page_data,
                    sub_type,
                    pull_type,
                    configuration_name,
                    destination_configuration,
                    business_rule,
                )
                page_data = gzip.compress(
                    json.dumps({RESULT: page_data}).encode("utf-8"),
                    compresslevel=3,
                )
                yield page_data, sub_type, sub_type_config_mapping, False

        except AWSD2CProviderException:
            yield page_data, sub_type, sub_type_config_mapping, True
        except Exception as err:
            error_msg = (
                "Error occurred while fetching alerts, events and webtx logs "
                f"from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}. Error: {err}",
                details=traceback.format_exc(),
            )
            raise AWSD2CProviderException(error_msg)

    def log_message(
        self,
        tenant_name,
        data,
        sub_type,
        pull_type,
        configuration_name,
        destination_configuration,
        business_rule,
    ):
        """Log the message for pulling data from Netskope log streaming.

        Args:
            data (List[dict]): List of dictionaries of data pulled from
            Netskope API.
            sub_type (str): Subtype of the data.
            pull_type (str): Type of pulling (maintenance, historical,
            real-time).
            configuration_name (str): Name of the configuration.
            destination_configuration (str): Name of the destination
            configuration.
            business_rule (str): Name of the business rule.
        """
        if configuration_name and destination_configuration and business_rule:
            log_msg = (
                f"Pulled {len(data)} {sub_type} log(s) from for "
                f"tenant {tenant_name} from {pull_type} in JSON format"
                f" for SIEM Mapping {configuration_name} to "
                f"{destination_configuration} according to rule"
                f" business rule {business_rule}."
            )
        else:
            log_msg = (
                f"Pulled {len(data)} {sub_type} log(s) "
                f"for tenant {tenant_name} from {pull_type}"
                " in JSON format."
            )

        self.logger.info(
            message=f"{self.log_prefix}: {log_msg}",
        )

    def extract_and_store_fields(
        self,
        items: List[dict],
        typeOfField=NetskopeFieldType.EVENT,
        sub_type=None,
    ):
        """Extract and store keys from list of dictionaries.

        Args:
            items (List[dict]): List of dictionaries. i.e. alerts, or events.
            typeOfField (str): Alert or Event
            sub_type (str): Subtype of alerts or events.
        """
        typeOfField = typeOfField.rstrip("s")
        fields = set()
        for item in items:
            if not isinstance(item, dict):
                item = item.dict()
            item_id = item.get("_id", None)
            if not sub_type and typeOfField == TYPE_EVENT:
                sub_type = item.get("record_type", None)
            if not item_id:
                item_id = item.get("id")
            for field, field_value in item.items():
                if field in fields:
                    continue
                if not field_value:
                    continue
                field_obj = plugin_provider_helper.get_stored_field(field)
                if not field_obj:
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has detected new "
                        f"field '{field}' in the {sub_type}"
                        f" event with id {item_id}. Configure CLS to use "
                        "this field if you wish to sent it to the SIEM."
                    )
                    notifier.info(
                        f"The CE platform has detected new "
                        f"field '{field}' in the {sub_type}"
                        f" event with id {item_id}. Configure CLS to use this"
                        " field if you wish to sent it to the SIEM."
                    )
                datatype = (
                    FieldDataType.BOOLEAN
                    if isinstance(field_value, bool)
                    else (
                        FieldDataType.NUMBER
                        if isinstance(field_value, int)
                        or isinstance(field_value, float)
                        else FieldDataType.TEXT
                    )
                )
                plugin_provider_helper.store_new_field(
                    field, typeOfField, datatype
                )
            fields = fields.union(item.keys())

    def cleanup(self, configuration, is_validation=False) -> None:
        """Remove all related dependencies of the record before
        its deletion, ensuring data integrity."""
        pass

    def share_analytics_in_user_agent(self, tenant_name, user_agent_analytics):
        """Share analytics data in user agent."""
        pass
