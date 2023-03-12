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

        # Service to be executed
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
        except requests.ConnectionError as e:
            self.error("Connection failed: " + str(e))

        if response.status_code == 200:
            token = json.loads(response.content.decode())["data"]["token"]
            self.session.headers.update({'Authorization': f'Bearer {token}'})
        else:
            self.error("Login failed with status code: " + str(response.status_code))


    def session_close(self):
        self.session.close()


    def active_response(self):
        url_path = 'active-response'
        api_url = f"{self.wazuh_manager}/{url_path}"
        
        # Send the active response
        response = self.session.put(
            api_url, params=self.active_response_params, 
            json=self.active_response_payload, 
            verify=False
        )
        return(response)


    def block_ip(self):
        self.active_response_payload['command'] = '!firewall-drop'
        self.active_response_payload['alert'] = {"data":{"srcip":self.observable}}

        ar = self.active_response()
        if ar.status_code == 200:
            message = {'agent_id: ': self.wazuh_agent_id,
                       'message': "Added DROP rule for ip: " + self.observable}
            self.report(message)
        else:
            self.error("Request error with code:" + ar.status_code)
    

    def delete_file(self):
        self.active_response_payload['command'] = '!firewall-drop'
        self.active_response_payload['alert'] = {"data":{"srcip":self.observable}}

        ar = self.active_response()
        if ar.status_code == 200:
            message = {'agent_id: ': self.wazuh_agent_id,
                       'message': "Deleted file: " + self.observable}
            self.report(message)
        else:
            self.error("Request error with code:" + ar.status_code)


    def run(self):
        Responder.run(self)
        self.login()

        if self.service == 'block_ip':
            # Check if the observable is a valid IPv4/IPv6 address
            if self.observable_type == "ip":
                try:
                    ipaddress.ip_address(self.observable)
                except ValueError:
                    self.error("Invalid observable_type: not a valid IPv4/IPv6 address!")
            else: 
                self.error("Invalid observable_type: not a valid IPv4/IPv6 address!")
            # Block the IP
            self.block_ip()
        
        if self.service == 'delete_file':
            if self.observable_type == "filename":
                self.delete_file()
            else: 
                self.error({"Not a file!"})
        
        self.session_close()

   
    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='Wazuh: Blocked IP')]


if __name__ == '__main__':
    Wazuh().run()
    #-------------------------------------------------------------------------------
    # with open('/opt/Custom-Analyzers/responders/Wazuh/output/test.log', 'w') as f:
    #         f.write(str(raw_token))
    #-------------------------------------------------------------------------------
