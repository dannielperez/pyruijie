"""Tests for Pydantic models."""

from pyruijie.models import Device, Project


class TestProject:
    def test_from_api_payload(self):
        p = Project.model_validate({"name": "Site X", "groupId": "gx-123"})
        assert p.name == "Site X"
        assert p.group_id == "gx-123"

    def test_by_field_name(self):
        p = Project(name="Test", group_id="g1")
        assert p.group_id == "g1"


class TestDevice:
    def test_from_api_payload(self):
        d = Device.model_validate({
            "serialNumber": "SN001",
            "productType": "EGW",
            "productClass": "RG-EG3230",
            "aliasName": "Main GW",
            "onlineStatus": "ONLINE",
            "localIp": "10.0.0.1",
            "cpeIp": "203.0.113.5",
            "mac": "AA:BB:CC:DD:EE:FF",
            "softwareVersion": "11.1(6)B3",
        })
        assert d.serial_number == "SN001"
        assert d.product_type == "EGW"
        assert d.name == "Main GW"
        assert d.is_online is True
        assert d.local_ip == "10.0.0.1"
        assert d.mac == "AA:BB:CC:DD:EE:FF"

    def test_offline_device(self):
        d = Device.model_validate({
            "serialNumber": "SN002",
            "onlineStatus": "OFFLINE",
        })
        assert d.is_online is False

    def test_minimal_device(self):
        d = Device.model_validate({"serialNumber": "SN003"})
        assert d.serial_number == "SN003"
        assert d.product_type is None
        assert d.is_online is False
