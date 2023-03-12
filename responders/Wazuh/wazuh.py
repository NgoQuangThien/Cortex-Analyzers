#!/usr/bin/env python3
from cortexutils.responder import Responder
from base64 import b64encode
import requests
import urllib3
import ipaddress
import json


class Wazuh(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.service = self.get_param( "config.service", None, "Service parameter is missing" )

        # Wazuh server access information
        self.wazuh_manager = self.get_param('config.wazuh_manager', None, 'https://localhost:55000')
        self.wazuh_user = self.get_param('config.wazuh_user', None, 'Username missing!')
        self.wazuh_password = self.get_param('config.wazuh_password', None, 'Password missing!')

        # Data from TheHive
        self.wazuh_agent_id = self.get_param('data.case.customFields.wazuh_agent_id.string', None, "Agent ID Missing!")
        self.observable = self.get_param('data.data', None, "Data is empty")
        self.observable_type = self.get_param('data.dataType', None, "Data type is empty")

        # Initializes a new session object
        self.session = requests.Session()

        # Active Response attributes
        self.active_response_params = {
            'agents_list': self.wazuh_agent_id
        }
        self.active_response_payload = {
            'arguments': ['string'],
            'command': 'string',
            'custom': False,
            'alert': {'data': {}}
        }


    def login(self):
        # Disable insecure https warnings (for self-signed SSL certificates)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Configuration
        url_path = 'security/user/authenticate'
        api_url = f"{self.wazuh_manager}/{url_path}"

        basic_auth = f"{self.wazuh_user}:{self.wazuh_password}".encode()
        login_headers = {'Content-Type': 'application/json',
                        'Authorization': f'Basic {b64encode(basic_auth).decode()}'}

        # Session initialization
        try:
            response = self.session.get(
                f"{api_url}", headers=login_headers, verify=False, timeout=3
            )
        except requests.ConnectionError:
            self.error({'message': "Login failed!"})

        if response.status_code == 200:
            token = json.loads(response.content.decode())["data"]["token"]
            self.session.headers.update({'Authorization': f'Bearer {token}'})
        else:
            self.error({'message': "Login failed!"})


    def session_close(self):
        self.session.close()


    def active_response(self):
        url_path = 'active-response'
        api_url = f"{self.wazuh_manager}/{url_path}"
        
        response = self.session.put(
            api_url, params=self.active_response_params, 
            json=self.active_response_payload, 
            verify=False
        )
        return(response)


    def run(self):
        Responder.run(self)
        self.login()

        if self.service == 'block_ip':
            if self.observable_type == "ip":
                try:
                    ipaddress.ip_address(self.observable)
                except ValueError:
                    self.error({'message': "Not a valid IPv4/IPv6 address!"})
            else: 
                self.error({'message': "Not a valid IPv4/IPv6 address!"})

            self.active_response_payload['command'] = '!firewall-drop'
            self.active_response_payload['alert'] = {"data":{"srcip":"10.2.65.68"}}

            ar = self.active_response()
            with open('/opt/Custom-Analyzers/responders/Wazuh/output/test.log', 'w') as f:
                f.write(ar.text)
            self.report({'message': "Added DROP rule for " + self.observable})
            logout_msg = self.logout_current_user()
        
        if self.service == 'delete_file':
            if self.observable_type == "filename":
                parameters = {'agents_list': self.wazuh_agent_id}
                payload = {"arguments": [ "string" ], "command": "!firewall-drop", "custom": False, "alert": {"data":{"srcip":"10.2.65.68"}}}

                ar = self.active_response()
                self.report({'message': "Deleted file: " + '"' + self.observable + '"' + " for agent " + self.wazuh_agent_id})
                logout_msg = self.logout_current_user()
            else: 
                self.error({'message': "Not a file!"})
        
        self.session_close()

   
    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='Wazuh: Blocked IP')] 

if __name__ == '__main__':
    Wazuh().run()
    #-------------------------------------------------------------------------------
    # with open('/opt/Custom-Analyzers/responders/Wazuh/output/test.log', 'w') as f:
    #         f.write(str(raw_token))
    #-------------------------------------------------------------------------------
