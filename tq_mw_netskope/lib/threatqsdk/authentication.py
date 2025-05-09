# coding=utf-8
# --------------------------------------------------------------------------------------------------
# ThreatQuotient Proprietary and Confidential
# Copyright ©2020 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from ThreatQuotient, Inc.
# --------------------------------------------------------------------------------------------------

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from netskope.common.utils import add_user_agent

from datetime import datetime
import json
from logging import getLogger

from . import exceptions

_logger = getLogger(__name__)

MODULE_NAME = "cte"
PLUGIN_NAME = "threatq"
PLUGIN_VERSION = "1.1.0"


class TokenHolder(object):
    """Create a token holder, authenticating with the API in thep rocess

    :param str host: Hostname, including protocol name
    :param auth: Authentication information. The expected format
        depends on the value of `private`. When using OAuth, we
        expect a ``dict`` with the format::
            {
                'clientid': 'Client ID from ThreatQ OAuth panel',
                'auth': {
                    'email': 'you@yourcomapny.com',
                    'password': 'your super secret password'
                }
            }

        If `private` is True, we expect a (client_id, client_secret) tuple.
    :param bool private: If True, OAuth private authentication will be
        used.
    :param session: The ``requests`` session to use
    :type session:`~requests.Session`

    :raises: :py:class:`~threatqsdk.exceptions.AuthenticationError` if
        authentication fails
    """

    def __init__(self, host, auth, private, session):
        if not private:
            threatq_clientid = auth["clientid"]
            auth = auth["auth"]

        self.threatq_host = host
        self.auth = auth
        self.private = private
        self.session = session

        headers = {"content-type": "application/json"}
        headers = self._add_user_agent(headers)

        if not private:
            r = self.session.post(
                self.threatq_host + "/api/token",
                params={
                    "grant_type": "password",
                    "client_id": threatq_clientid,
                },
                data=json.dumps(auth),
                headers=headers,
            )
        else:
            r = self.session.post(
                self.threatq_host + "/api/token",
                params={
                    "grant_type": "client_credentials",
                },
                data=json.dumps(auth),
                headers=headers,
                auth=(auth[0], auth[1]),
            )

        if r.status_code == 400:
            # bad loging request
            raise exceptions.AuthenticationError(r)

        r.raise_for_status()

        res = r.json()
        if "access_token" not in res:
            raise exceptions.AuthenticationError(res)

        self.accesstoken = res["access_token"]
        self.refreshtoken = res["refresh_token"]

        self.token_time = datetime.now()

    def _add_user_agent(self, headers=None):
        """Add User-Agent in the headers for threatq requests.

        Args:
            headers (Dict): Dictionary containing headers for any request.
        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME,
            PLUGIN_NAME,
            PLUGIN_VERSION,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def is_token_expired(self):
        """Determine if the access token has expired based on the
        current time.

        Tokens expire every 30 minutes
        """
        now = datetime.now()
        dt = now - self.token_time
        return dt.total_seconds() > (60 * 30)

    def refresh(self):
        """Referesh the access token"""
        _logger.debug("Refreshing acces token")
        params = {
            "grant_type": "refresh_token",
            "refresh_token": self.refreshtoken,
        }
        headers = {
            "Authorization": "Bearer %s" % self.accesstoken,
            "content-type": "application/json",
        }
        headers = self._add_user_agent(headers)

        if not self.private:
            r = self.session.post(
                self.threatq_host + "/api/token",
                headers=headers,
                params=params,
            )
        else:
            r = self.session.post(
                self.threatq_host + "/api/token",
                headers=headers,
                auth=self.auth,
                params=params,
            )

        r.raise_for_status()

        res = r.json()

        self.accesstoken = res["access_token"]
        self.refreshtoken = res["refresh_token"]
        self.token_time = datetime.now()
