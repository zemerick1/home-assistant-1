"""
Support for ClearPass Policy Manager.

Allows tracking devices with CPPM.
"""
import logging
import time

import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    PLATFORM_SCHEMA, DeviceScanner, DOMAIN
)
from homeassistant.const import (
    CONF_HOST, CONF_API_KEY
)

REQUIREMENTS = ['clearpasspy==1.1.2']

CLIENT_ID = 'client_id'

GRANT_TYPE = 'client_credentials'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CLIENT_ID): cv.string,
    vol.Required(CONF_API_KEY): cv.string,
})

_LOGGER = logging.getLogger(__name__)


def get_scanner(hass, config):
    """Initialize Scanner."""
    from clearpasspy import ClearPass
    data = {
        'server': config[DOMAIN][CONF_HOST],
        'grant_type': GRANT_TYPE,
        'secret': config[DOMAIN][CONF_API_KEY],
        'client': config[DOMAIN][CLIENT_ID]
    }
    cppm = ClearPass(data)
    if cppm.access_token is None:
        return None
    _LOGGER.debug("Successfully received Access Token")
    return CPPMDeviceScanner(cppm)


class CPPMDeviceScanner(DeviceScanner):
    """Initialize class."""

    def __init__(self, cppm):
        """Initialize class."""
        self._cppm = cppm
        self.results = None

    def scan_devices(self):
        """Initialize scanner."""
        self.get_cppm_data()
        return [device['mac'] for device in self.results]

    def get_device_name(self, device):
        """Retrieve device name."""
        name = next((
            result['name'] for result in self.results
            if result['mac'] == device), None)
        return name

    def get_cppm_data(self):
        """Retrieve data from Aruba Clearpass and return parsed result."""
        endpoints = self._cppm.get_endpoints_time(time.time()-600, time.time())
        devices = []
        for item in endpoints['_embedded']['items']:
            if item['is_online']:
                device = {
                    'mac': item['mac'],
                    'name': item['device_name'],
                    'ip': item['ip'],
                    'device_category': item['device_category']
                }
                devices.append(device)
            else:
                continue
        _LOGGER.debug("Devices: %s", devices)
        self.results = devices
