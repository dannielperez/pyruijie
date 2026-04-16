"""Tests for Pydantic models."""

from pyruijie.models import (
    ClientDevice,
    Device,
    GatewayPort,
    Project,
    SwitchPort,
    parse_vlan_list,
)


class TestProject:
    def test_from_api_payload(self):
        p = Project.model_validate({"name": "Site X", "groupId": "gx-123"})
        assert p.name == "Site X"
        assert p.group_id == "gx-123"

    def test_by_field_name(self):
        p = Project(name="Test", group_id="g1")
        assert p.group_id == "g1"

    def test_numeric_group_id_coerced_to_str(self):
        p = Project.model_validate({"name": "Numeric", "groupId": 6687758})
        assert p.group_id == "6687758"
        assert isinstance(p.group_id, str)

    def test_none_group_id_becomes_empty_str(self):
        p = Project.model_validate({"name": "NoId", "groupId": None})
        assert p.group_id == ""


class TestDevice:
    def test_from_api_payload(self):
        d = Device.model_validate(
            {
                "serialNumber": "SN001",
                "productType": "EGW",
                "productClass": "RG-EG3230",
                "aliasName": "Main GW",
                "onlineStatus": "ONLINE",
                "localIp": "10.0.0.1",
                "cpeIp": "203.0.113.5",
                "mac": "AA:BB:CC:DD:EE:FF",
                "softwareVersion": "11.1(6)B3",
            }
        )
        assert d.serial_number == "SN001"
        assert d.product_type == "EGW"
        assert d.name == "Main GW"
        assert d.is_online is True
        assert d.local_ip == "10.0.0.1"
        assert d.mac == "AA:BB:CC:DD:EE:FF"

    def test_offline_device(self):
        d = Device.model_validate(
            {
                "serialNumber": "SN002",
                "onlineStatus": "OFFLINE",
            }
        )
        assert d.is_online is False

    def test_minimal_device(self):
        d = Device.model_validate({"serialNumber": "SN003"})
        assert d.serial_number == "SN003"
        assert d.product_type is None
        assert d.is_online is False


class TestClientDevice:
    def test_from_api_payload(self):
        c = ClientDevice.model_validate(
            {
                "mac": "AA:BB:CC:DD:EE:01",
                "ip": "192.168.1.100",
                "userName": "phone-01",
                "staOs": "Android",
                "connectType": "wireless",
                "ssid": "OfficeWiFi",
                "linkedDevice": "SN-AP-001",
                "deviceName": "AP-Lobby",
                "clientSource": "AP",
                "manufacturer": "Samsung",
                "onlineTime": 1700000000000,
            }
        )
        assert c.mac == "AA:BB:CC:DD:EE:01"
        assert c.hostname == "phone-01"
        assert c.os_type == "Android"
        assert c.ap_name == "AP-Lobby"
        assert c.ap_mac == "SN-AP-001"
        assert c.switch_name is None
        assert c.is_online is True

    def test_wired_client_properties(self):
        c = ClientDevice.model_validate(
            {
                "mac": "AA:BB:CC:DD:EE:02",
                "clientSource": "Switch",
                "deviceName": "Switch-Floor2",
                "linkedDevice": "SN-SW-001",
            }
        )
        assert c.switch_name == "Switch-Floor2"
        assert c.ap_name is None
        assert c.ap_mac is None

    def test_wifi_traffic_fields(self):
        """WiFi signal and traffic fields from API Section 3.0."""
        c = ClientDevice.model_validate(
            {
                "mac": "AA:BB:CC:DD:EE:03",
                "flowUp": 1024000,
                "flowDown": 5120000,
                "band": "5G",
                "rssi": -45,
                "channel": 36,
            }
        )
        assert c.flow_up == 1024000
        assert c.flow_down == 5120000
        assert c.band == "5G"
        assert c.rssi == -45
        assert c.channel == 36

    def test_wifi_fields_default_none(self):
        c = ClientDevice.model_validate({"mac": "AA:BB:CC:DD:EE:04"})
        assert c.flow_up is None
        assert c.flow_down is None
        assert c.band is None
        assert c.rssi is None
        assert c.channel is None

    def test_wifi_fields_in_model_dump(self):
        c = ClientDevice.model_validate(
            {
                "mac": "AA:BB:CC:DD:EE:05",
                "band": "2.4G",
                "rssi": -72,
                "channel": 6,
            }
        )
        dumped = c.model_dump(by_alias=True)
        assert dumped["band"] == "2.4G"
        assert dumped["rssi"] == -72
        assert dumped["channel"] == 6


class TestGatewayPort:
    def test_from_api_payload(self):
        p = GatewayPort.model_validate(
            {
                "alias": "WAN1",
                "type": "WAN",
                "ipAddr": "203.0.113.5",
                "ipMask": "255.255.255.0",
                "linestatus": "up",
                "speed": "1000M",
                "nextHop": "203.0.113.1",
                "pppoe": "",
            }
        )
        assert p.alias == "WAN1"
        assert p.port_type == "WAN"
        assert p.is_wan is True
        assert p.is_lan is False
        assert p.subnet == "203.0.113.0/24"
        assert p.is_up is True

    def test_lan_port_subnet(self):
        p = GatewayPort.model_validate(
            {
                "alias": "LAN1",
                "type": "LAN",
                "ipAddr": "192.168.1.1",
                "ipMask": "255.255.255.0",
                "linestatus": "up",
            }
        )
        assert p.is_lan is True
        assert p.subnet == "192.168.1.0/24"

    def test_missing_ip_returns_none_subnet(self):
        p = GatewayPort.model_validate({"alias": "WAN2", "type": "WAN"})
        assert p.subnet is None

    def test_minimal_payload(self):
        p = GatewayPort.model_validate({})
        assert p.alias == ""
        assert p.port_type == ""
        assert p.subnet is None
        assert p.is_up is False


class TestSwitchPort:
    def test_from_api_payload(self):
        p = SwitchPort.model_validate(
            {
                "name": "GigabitEthernet0/1",
                "type": "access",
                "vlan": 100,
                "vlanList": "1-4,100,200",
                "status": "up",
                "speed": "1000M",
                "isUplink": True,
                "poeStatus": "delivering",
                "powerUsed": "12.5W",
                "loopState": "normal",
                "enable": "true",
            }
        )
        assert p.name == "GigabitEthernet0/1"
        assert p.vlan == 100
        assert p.is_uplink is True
        assert p.is_up is True
        assert p.allowed_vlans == {1, 2, 3, 4, 100, 200}

    def test_uplink_coercion_string_true(self):
        p = SwitchPort.model_validate({"name": "p1", "isUplink": "true"})
        assert p.is_uplink is True

    def test_uplink_coercion_int_one(self):
        p = SwitchPort.model_validate({"name": "p1", "isUplink": 1})
        assert p.is_uplink is True

    def test_uplink_coercion_string_false(self):
        p = SwitchPort.model_validate({"name": "p1", "isUplink": "false"})
        assert p.is_uplink is False

    def test_empty_vlan_list(self):
        p = SwitchPort.model_validate({"name": "p1"})
        assert p.allowed_vlans == set()

    def test_minimal_payload(self):
        p = SwitchPort.model_validate({"name": "p1"})
        assert p.vlan is None
        assert p.is_up is False


class TestParseVlanList:
    def test_simple_range(self):
        assert parse_vlan_list("1-4") == {1, 2, 3, 4}

    def test_mixed(self):
        assert parse_vlan_list("1-4,100,200") == {1, 2, 3, 4, 100, 200}

    def test_single_value(self):
        assert parse_vlan_list("100") == {100}

    def test_empty(self):
        assert parse_vlan_list("") == set()

    def test_invalid_range(self):
        result = parse_vlan_list("abc-def,100")
        assert result == {100}

    def test_whitespace(self):
        assert parse_vlan_list(" 1 - 3 , 10 ") == {1, 2, 3, 10}
