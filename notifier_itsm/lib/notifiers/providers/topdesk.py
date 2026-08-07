from ..core import Provider, Response
from ..utils import requests
import json

class Topdesk(Provider):
    """Create TOPdesk Incidents"""

    base_url = "https://{domain}/tas/api/incidents"
    site_url = "https://developers.topdesk.com"
    name = "topdesk"

    _required = {"required": ["api_key", "message"]}
    _schema = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "minLength": 1, "title": "TOPdesk SaaS URL (i.e. europe-demo-100.topdesk.net)"},
            "username": {"type": "string", "title": "Username of the API Key}"},
            "api_key": {"type": "string", "title": "your user API key"},
            "message": {"type": "string", "title": "your message"},
        },
        "additionalProperties": False,
    }

    def _prepare_data(self, data: dict) -> dict:
        data['text'] = data.pop("message")
        return data

    def _send_notification(self, data: dict) -> Response:

        username = str(data.pop("username"))
        api_key = str(data.pop("api_key"))
        domain = data.pop("domain")
        url_topdesk = self.base_url.format(domain=domain)
       
        message_json = data['text']

        path_to_errors = ("message",)

        response, errors = requests.post(
            url_topdesk,
            auth=(username, api_key),
            headers={
        "Content-Type": "application/json; charset=utf-8"
            },
            data=message_json,
            path_to_errors=path_to_errors
        )
        return self.create_response(data, response, errors)