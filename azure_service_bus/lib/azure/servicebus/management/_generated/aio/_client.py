# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from copy import deepcopy
from typing import Any, Awaitable, TYPE_CHECKING

from azure.core import AsyncPipelineClient
from azure.core.pipeline import policies
from azure.core.rest import AsyncHttpResponse, HttpRequest

from .. import models as _models
from .._serialization import Deserializer, Serializer
from ._configuration import ServiceBusManagementClientConfiguration
from .operations import (
    EntityOperations,
    NamespaceOperations,
    RuleOperations,
    ServiceBusManagementClientOperationsMixin,
    SubscriptionOperations,
)

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential


class ServiceBusManagementClient(
    ServiceBusManagementClientOperationsMixin
):  # pylint: disable=client-accepts-api-version-keyword
    """Azure Service Bus client for managing Queues, Topics, and Subscriptions.

    :ivar entity: EntityOperations operations
    :vartype entity: azure.servicebus.management._generated.aio.operations.EntityOperations
    :ivar subscription: SubscriptionOperations operations
    :vartype subscription:
     azure.servicebus.management._generated.aio.operations.SubscriptionOperations
    :ivar rule: RuleOperations operations
    :vartype rule: azure.servicebus.management._generated.aio.operations.RuleOperations
    :ivar namespace: NamespaceOperations operations
    :vartype namespace: azure.servicebus.management._generated.aio.operations.NamespaceOperations
    :param endpoint: The Service Bus fully qualified domain name. Required.
    :type endpoint: str
    :param credential: Credential needed for the client to connect to Azure. Required.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :keyword api_version: Api Version. Default value is "2021-05". Note that overriding this
     default value may result in unsupported behavior.
    :paramtype api_version: str
    """

    def __init__(self, endpoint: str, credential: "AsyncTokenCredential", **kwargs: Any) -> None:
        _endpoint = "https://{endpoint}"
        self._config = ServiceBusManagementClientConfiguration(endpoint=endpoint, credential=credential, **kwargs)
        _policies = kwargs.pop("policies", None)
        if _policies is None:
            _policies = [
                policies.RequestIdPolicy(**kwargs),
                self._config.headers_policy,
                self._config.user_agent_policy,
                self._config.proxy_policy,
                policies.ContentDecodePolicy(**kwargs),
                self._config.redirect_policy,
                self._config.retry_policy,
                self._config.authentication_policy,
                self._config.custom_hook_policy,
                self._config.logging_policy,
                policies.DistributedTracingPolicy(**kwargs),
                policies.SensitiveHeaderCleanupPolicy(**kwargs) if self._config.redirect_policy else None,
                self._config.http_logging_policy,
            ]
        self._client: AsyncPipelineClient = AsyncPipelineClient(base_url=_endpoint, policies=_policies, **kwargs)

        client_models = {k: v for k, v in _models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)
        self._serialize.client_side_validation = False
        self.entity = EntityOperations(self._client, self._config, self._serialize, self._deserialize)
        self.subscription = SubscriptionOperations(self._client, self._config, self._serialize, self._deserialize)
        self.rule = RuleOperations(self._client, self._config, self._serialize, self._deserialize)
        self.namespace = NamespaceOperations(self._client, self._config, self._serialize, self._deserialize)

    def send_request(
        self, request: HttpRequest, *, stream: bool = False, **kwargs: Any
    ) -> Awaitable[AsyncHttpResponse]:
        """Runs the network request through the client's chained policies.

        >>> from azure.core.rest import HttpRequest
        >>> request = HttpRequest("GET", "https://www.example.org/")
        <HttpRequest [GET], url: 'https://www.example.org/'>
        >>> response = await client.send_request(request)
        <AsyncHttpResponse: 200 OK>

        For more information on this code flow, see https://aka.ms/azsdk/dpcodegen/python/send_request

        :param request: The network request you want to make. Required.
        :type request: ~azure.core.rest.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to False.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.rest.AsyncHttpResponse
        """

        request_copy = deepcopy(request)
        path_format_arguments = {
            "endpoint": self._serialize.url("self._config.endpoint", self._config.endpoint, "str", skip_quote=True),
        }

        request_copy.url = self._client.format_url(request_copy.url, **path_format_arguments)
        return self._client.send_request(request_copy, stream=stream, **kwargs)  # type: ignore

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "ServiceBusManagementClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details: Any) -> None:
        await self._client.__aexit__(*exc_details)