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

AWS Netskope LogStreaming provider validator.
"""

import boto3
import traceback
from .exceptions import AWSD2CProviderException
from botocore.config import Config
from botocore.exceptions import ClientError


class AWSD2CProviderValidator(object):
    """AWS D2C Provider validator class."""

    def __init__(self, region_name, logger, proxy, log_prefix, user_agent):
        """Initialize."""
        super().__init__()
        self.region_name = region_name
        self.logger = logger
        self.proxy = proxy
        self.log_prefix = log_prefix
        self.useragent = user_agent

    def validate_credentials(self, aws_client):
        """Validate credentials.

        Returns:
            Whether the provided value is valid or not. True in case of
            valid value, False otherwise
        """
        try:

            sqs_client = boto3.client(
                "sqs",
                aws_access_key_id=aws_client.aws_public_key,
                aws_secret_access_key=aws_client.aws_private_key,
                aws_session_token=aws_client.aws_session_token,
                region_name=self.region_name,
                config=Config(proxies=self.proxy, user_agent=self.useragent),
            )
            return sqs_client

        except ClientError as err:
            err_msg = "Invalid AWS Credentials provided."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise AWSD2CProviderException(err_msg)

        except Exception as exp:
            err_msg = (
                "Error occurred while validating credentials. "
                "Verify the provided configuration parameters and "
                "make sure all the required SQS Queue permissions "
                "are attached to the user."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AWSD2CProviderException(err_msg)

    def validate_queue_url_using_name(self, sqs_client, queue_name):
        """Validate queue url using queue name.

        Args:
            sqs_client (object): SQS client object.
            queue_name (str): Queue name.

        Returns:
            Whether the provided value is valid or not. True in case of
            valid value, False otherwise
        """
        try:
            # response from sqs client
            response = sqs_client.get_queue_url(QueueName=str(queue_name))

            # Check if the queue exists
            if response and response.get("QueueUrl"):
                queue_url = response.get("QueueUrl")
                response = sqs_client.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=1,
                    WaitTimeSeconds=2,
                    MessageAttributeNames=["All"],
                )
                return True
            else:
                err_msg = (
                    "Invalid AWS SQS Queue Name provided. "
                    f"The provided queue '{queue_name}' does not exist."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise AWSD2CProviderException(err_msg)
        except sqs_client.exceptions.QueueDoesNotExist:
            err_msg = (
                f"Invalid AWS SQS Queue Name '{queue_name}' provided in "
                "the configuration parameters. Make sure the provided "
                "queue exists and has all the required permissions."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise AWSD2CProviderException(err_msg)
        except ClientError as err:
            err_msg = (
                "Error occurred while connecting to AWS SQS Queue "
                f"{queue_name}. Make sure the provided queue exists"
                " and has all the required permissions."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise AWSD2CProviderException(err_msg)
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while "
                f"connecting to AWS SQS Queue {queue_name}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise AWSD2CProviderException(err_msg)
