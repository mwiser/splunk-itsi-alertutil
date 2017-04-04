import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
class PyHEC:

    def __init__(self, token, uri, port='8088'):
        if not 'http' in uri:
            raise("no http or https found in hostname")
        self.token = token
        self.uri = uri+":"+port+"/services/collector/event"
        self.port = port

    def send(self, event, metadata=None):
        headers = {'Authorization': 'Splunk '+self.token}

        payload = {"host": self.uri,
                   "event": event}

        if metadata:
            payload.update(metadata)
            
        r = requests.post(self.uri, data=json.dumps(payload), headers=headers, verify=False)

        return r.status_code, r.text,
