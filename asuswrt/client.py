import json
from base64 import b64encode
from datetime import datetime
from urllib import parse

import requests

from .model import Client


class AsusWRT:
    _USER_AGENT = 'asusrouter-Android-DUTUtil-1.0.0.3.58-163'

    _CONTENT_TYPE = 'application/x-www-form-urlencoded'

    def __init__(self, url, username, password):
        self._url = url
        self._username = username
        self._password = password
        self._session = requests.Session()

        self.refresh_asus_token()

    def is_asus_token_set(self):
        '''
        Check if authentication token is present
        '''
        return 'asus_token' in self._session.cookies.keys()

    def is_asus_token_valid(self):
        '''
        Check that the asus token is not older than 60 minutes
        '''
        try:
            return (datetime.now() - self._asus_token_timestamp).seconds < 60 * 60
        except:
            return False

    def refresh_asus_token(self):
        '''
        Refresh authentication token
        '''
        response = self.request(
            'POST',
            '/login.cgi',
            {
                'login_authorization': b64encode(('%s:%s' % (self._username, self._password)).encode('utf-8')).decode(
                    'utf-8')
            }
        )

        self._asus_token_timestamp = datetime.now()

    def logout(self):
        '''
        Logout
        '''
        response = self.request(
            'GET',
            '/Logout.asp'
        )

        self._session = requests.Session()

    def get_sys_info(self):
        '''
        Get system information
        '''
        response = self.get('nvram_get(productid);nvram_get(firmver);nvram_get(buildno);nvram_get(extendno)')

        return {
            'model': response.get('productid'),
            'firmware': '%s_%s_%s' % (response.get('firmver'), response.get('buildno'), response.get('extendno'))
        }

    def get_cpu_mem_info(self):
        '''
        Get CPU and memory usage
        '''
        response = self.get('cpu_usage(appobj);memory_usage(appobj);')

        return {
            'cpu': response['cpu_usage'],
            'memory': {
                'total': response['memory_usage']['mem_total'],
                'used': response['memory_usage']['mem_used'],
                'free': response['memory_usage']['mem_free']
            }
        }

    def get_wan_state(self):
        ''''
        Get WAN state
        '''
        return self.get('wanlink_state(appobj)')

    def get_online_clients(self):
        '''
        Get online clients.

        :return: list of Client
        '''

        def get_client(mac):
            return next((client for client in clients if client.mac == mac), None)

        def update_interface(interface, interface_name):
            interface_clients = response.get('wl_sta_list_%s' % interface, {})
            for key, val in interface_clients.items():
                client = get_client(key)
                if client:
                    client.interface = interface_name
                    client.rssi = val.get('rssi')

        def update_custom():
            custom_clients = self.parse_custom_clientlist(response.get('custom_clientlist', ''))
            for key, val in custom_clients.items():
                client = get_client(key)
                if client:
                    client.alias = val.get('alias')

        response = self.get(
            'get_clientlist(appobj);wl_sta_list_2g(appobj);wl_sta_list_5g(appobj);wl_sta_list_5g_2(appobj);nvram_get(custom_clientlist)')

        client_list = response.get('get_clientlist', {})
        client_list.pop('maclist', None)
        clients = list(
            map(
                lambda x: Client(x[1]),
                filter(
                    lambda x: isinstance(x[1], dict),
                    client_list.items()
                )
            ))

        update_interface('2g', '2GHz')
        update_interface('5g', '5GHz')
        update_interface('5g_2', '5GHz-2')
        update_custom()

        return clients

    def parse_custom_clientlist(self, clientlist):
        '''
        Parse user set metadata for clients
        '''
        clientlist = clientlist.replace('&#62', '>').replace('&#60', '<').split('<')
        clientlist = [client.split('>') for client in clientlist]
        clientlist = {client[1]: {'alias': client[0], 'group': client[2], 'type': client[3], 'callback': client[4]} for
                      client in clientlist if len(client) == 6}

        return clientlist

    def restart_service(self, service):
        '''
        Restart service
        '''
        return self.apply({'action_mode': 'apply', 'rc_service': service})

    def get(self, payload):
        '''
        Get
        '''
        response = self.request('POST', '/appGet.cgi', {'hook': payload})
        return response.json()

    def apply(self, payload):
        '''
        Apply
        '''
        return self.request('POST', '/applyapp.cgi', json.dumps(payload)).json()

    def request(self, method, path, payload=None):
        '''
        Make REST API call

        :param str method: http verb
        :param str path: api path
        :param dict|str payload: request payload
        :return: the REST response
        '''
        # if not self.is_asus_token_set() or (self.is_asus_token_set() and not self.is_asus_token_valid()):
        #     self.refresh_asus_token()

        return self._session.request(
            method=method.upper(),
            url=self._url + path,
            headers={
                'User-Agent': self._USER_AGENT,
                'Content-Type': self._CONTENT_TYPE
            },
            data=payload,
            verify=False,
        )

    def start_apply2(self,
                     index=1,
                     wl_closed=False,
                     wl_ssid="ASUS_E8_2G_Guest",
                     wl_auth_mode_x="open",
                     wl_crypto="aes",
                     wl_wpa_psk="",
                     wl_expire_day="0",
                     wl_expire_hr="",
                     wl_expire_min="",
                     wl_bw_dl_x="",
                     wl_bw_ul_x="",
                     wl_lanaccess=False,
                     wl_macmode=None,
                     wl_maclist_x=None,
                     ):

        url = "/start_apply2.htm"
        data = {
            'productid': 'RT-AC88U',
            'current_page': 'Guest_network.asp',
            'next_page': 'Guest_network.asp',
            'modified': '0',
            'action_mode': 'apply_new',
            'action_script': 'restart_wireless;restart_qos;restart_firewall;',
            'action_wait': '15',
            'preferred_lang': 'CN',
            'firmver': '3.0.0.4',
            'wl_ssid_org': 'CMCC%5FDEV',
            'wl_wpa_psk_org': 'wang302302',
            'wl_key1_org': '',
            'wl_key2_org': '',
            'wl_key3_org': '',
            'wl_key4_org': '',
            'wl_phrase_x_org': '',
            'x_RegulatoryDomain': '',
            'wl_nctrlsb_old': '',
            'wl_key_type': '',
            'wl_channel_orig': '',
            'wl_expire': '600',
            'qos_enable': '1',
            'qos_type': '2',
            'wl_bw_enabled': '1',
            'wl_bw_dl': '1024',
            'wl_bw_ul': '1024',
            'wl_mbss': '1',
            'wl_maclist_x': '',
            'wl_ap_isolate': '1',
            'wl_subunit': '1',
            'wl_unit': '0',
            'wl_bss_enabled': '1',
            'wl_closed': '0',
            'wl_ssid': 'ASUS_E8_2G_Guest',
            'wl_gmode_check': '',
            'wl_auth_mode_x': 'open',
            'wl_crypto': 'aes',
            'wl_wpa_psk': '',
            'wl_wep_x': '0',
            'wl_key': '1',
            'wl_key1': '',
            'wl_key2': '',
            'wl_key3': '',
            'wl_key4': '',
            'wl_phrase_x': '',
            'wl_expire_radio': '1',
            'wl_expire_day': '0',
            'wl_expire_hr': '',
            'wl_expire_min': '10',
            'bw_enabled_x': '1',
            'wl_bw_dl_x': '1',
            'wl_bw_ul_x': '1',
            'wl_lanaccess': 'off',
            'wl_sync_node': '0',
            'wl_macmode': 'disabled',
            'wl_maclist_x_0': ''
        }
        if wl_closed:
            wl_closed = "1"
        else:
            wl_closed = "0"
        data["wl_closed"] = wl_closed
        data["wl_ssid"] = wl_ssid

        if wl_auth_mode_x not in ["open", "psk2", "pskpsk2"]:
            raise ValueError("wl_auth_mode_x must be one of open, psk2, pskpsk2")
        if wl_auth_mode_x == "pskpsk2":
            print("自动模式下使用 WEP 或 TKIP 加密时，无线网络最多支持 54 Mbps 的传输速率。")
        data["wl_auth_mode_x"] = wl_auth_mode_x

        if wl_auth_mode_x == "open":
            pass
        elif wl_auth_mode_x == "psk2":
            if not wl_crypto not in ["aes"]:
                raise ValueError("wl_crypto must be one of aes")
        elif wl_auth_mode_x == "pskpsk2":
            if wl_crypto not in ["aes", "tkip+aes"]:
                raise ValueError("wl_crypto must be one of aes, tkip+aes")
        else:
            raise ValueError("un supported auth mode %s crypto %s" % (wl_auth_mode_x, wl_crypto))
        data["wl_crypto"] = wl_crypto
        if all([
            wl_auth_mode_x,
            wl_crypto
        ]):
            data["wl_wpa_psk"] = wl_wpa_psk
        if wl_expire_day:
            if not wl_expire_day.isdigit():
                raise ValueError("wl_expire_day must be a number")
            if int(wl_expire_day) > 30 or int(wl_expire_day) < 0:
                raise ValueError("wl_expire_day must be a number between 0 and 30")
        if wl_expire_hr:
            if not wl_expire_hr.isdigit():
                raise ValueError("wl_expire_hr must be a number")
        if wl_expire_min:
            if not wl_expire_min.isdigit():
                raise ValueError("wl_expire_min must be a number")
        data["wl_expire_day"] = wl_expire_day
        data["wl_expire_hr"] = wl_expire_hr
        data["wl_expire_min"] = wl_expire_min

        data["wl_expire_radio"] = "0"
        if any([
            wl_expire_day != "0" and wl_expire_hr,
            wl_expire_day != "0" and wl_expire_min,
        ]):
            data["wl_expire_radio"] = "1"

        data["wl_bw_dl_x"] = wl_bw_dl_x
        data["wl_bw_ul_x"] = wl_bw_ul_x

        data["bw_enabled_x"] = "0"
        if any([
            wl_bw_ul_x,
            wl_bw_dl_x
        ]):
            data["bw_enabled_x"] = "1"

        data["wl_lanaccess"] = "off"
        if wl_lanaccess:
            data["wl_lanaccess"] = "on"

        data["wl_macmode"] = wl_macmode
        if wl_macmode not in ["disabled", "allow", "deny"]:
            data["wl_macmode"] = "disabled"

        if wl_macmode in ["allow", "deny"] and isinstance(wl_maclist_x, list):
            for i, mac in enumerate(wl_maclist_x):
                data[f"wl_maclist_x_{i}"] = mac

        payload = parse.urlencode(data)
        resp = self.request(
            "POST",
            url,
            payload=payload,
        )
        print(resp.status_code)
        print(resp.text)
