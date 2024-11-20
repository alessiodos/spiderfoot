# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_zoomeye
# Purpose:     Search ZoomEye for information related to the target IP or domain.
#
# Author:      Alessio D'Ospina <alessiodos@gmail.com>
#
# Created:     21/11/2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import requests

from netaddr import IPNetwork
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_zoomeye(SpiderFootPlugin):

    meta = {
        'name': "ZoomEye",
        'summary': "Obtain information from ZoomEye about identified IP addresses and domains.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.zoomeye.org/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://www.zoomeye.org/doc",
            ],
            'apiKeyInstructions': [
                "Visit https://www.zoomeye.org/",
                "Register for a free account",
                "Retrieve your API key from account settings"
            ],
            'favIcon': "Your_Favicon_URL",
            'logo': "Your_Logo_URL",
            'description': ("ZoomEye is a search engine for cyberspace, "
                            "allowing users to find network components "
                            "(ip, services, etc.)."),
        }
    }

    opts = {
        'api_key': "",
        'resource': 'web',
        'facet': 'ip',
        'netblocklookup': True,
        'maxnetblock': 24
    }

    optdescs = {
        "api_key": "ZoomEye API Key.",
        'resource': "Resource type to search [web, host].",
        'facet': "Facet to filter search results, e.g., [ip].",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "DOMAIN_NAME", "NETBLOCK_OWNER"]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "IP_ADDRESS", "DOMAIN_NAME", "TCP_PORT_OPEN", "GEOINFO"]

    def login(self):
        self.debug("Logging in to ZoomEye API")
        headers = {
            'Content-Type': 'application/json'
        }
        data = json.dumps({"username": self.opts['api_key'], "password": ""})
        res = requests.post("https://api.zoomeye.org/user/login", headers=headers, data=data)

        if res.status_code == 200 and 'access_token' in res.json():
            return res.json().get('access_token')
        else:
            self.error("Unable to authenticate with ZoomEye")
            return None

    def queryZoomEye(self, qry, resource, facet):
        self.debug(f"Querying ZoomEye for {qry}")

        token = self.login()
        if token is None:
            self.errorState = True
            return None

        headers = {
            'Authorization': f'JWT {token}'
        }
        params = {
            'query': qry,
            'page': 1,
            'facet': facet
        }

        res = requests.get(f'https://api.zoomeye.org/{resource}/search', headers=headers, params=params)
        time.sleep(1)  # sleep to avoid hitting rate limits

        if res.status_code == 200 and 'matches' in res.json():
            return res.json().get('matches')
        else:
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if not self.opts['api_key']:
            self.error("You enabled sfp_zoomeye but did not set an API key!")
            self.errorState = True
            return

        qry = eventData
        if eventName == "NETBLOCK_OWNER":
            if not self.opts['netblocklookup']:
                return

            if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {self.opts['maxnetblock']}")
                return

            for ip in IPNetwork(eventData):
                qry = str(ip)
                result = self.queryZoomEye(qry, self.opts['resource'], self.opts['facet'])
                self.processZoomEyeResults(result, event)

        else:
            result = self.queryZoomEye(qry, self.opts['resource'], self.opts['facet'])
            self.processZoomEyeResults(result, event)

    def processZoomEyeResults(self, results, parentEvent):
        if not results:
            return

        for result in results:
            ip = result.get('ip')
            port_info = result.get('portinfo')
            geoinfo = result.get('geoinfo')

            if ip:
                evt = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, parentEvent)
                self.notifyListeners(evt)

            if port_info:
                port = port_info.get('port')
                evt = SpiderFootEvent("TCP_PORT_OPEN", f"{ip}:{port}", self.__name__, parentEvent)
                self.notifyListeners(evt)

            if geoinfo:
                country = geoinfo.get('country')
                city = geoinfo.get('city')
                location = ', '.join(filter(None, [city, country]))
                evt = SpiderFootEvent("GEOINFO", location, self.__name__, parentEvent)
                self.notifyListeners(evt)

# End of sfp_zoomeye class
