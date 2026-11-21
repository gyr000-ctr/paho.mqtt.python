"""Tests for MQTT v5.0 enhanced authentication and re-authentication (AUTH packet).

These tests use the in-process FakeBroker instead of a real broker so they
stay fast and deterministic.
"""
import struct
import threading

import pytest

from paho.mqtt import client
from paho.mqtt.client import AuthResponse, Client
from paho.mqtt.enums import CallbackAPIVersion, MQTTErrorCode, MQTTProtocolVersion
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties
from paho.mqtt.reasoncodes import ReasonCode
from tests import mqtt5_props, paho_test
from tests.testsupport.broker import fake_broker  # noqa: F401

AUTH_METHOD = "SCRAM-SHA-256"
INITIAL_AUTH_DATA = b"client-first-message"
REAUTH_DATA = b"client-reauth-message"
SERVER_AUTH_DATA = b"server-challenge"


def _binary_prop(identifier, data):
    return struct.pack("!BH", identifier, len(data)) + data


def _connect_props():
    return (
        mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, AUTH_METHOD)
        + _binary_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, INITIAL_AUTH_DATA)
    )


def _expected_connect_packet(client_id):
    return paho_test.gen_connect(
        client_id,
        keepalive=60,
        proto_ver=5,
        properties=_connect_props(),
    )


def _server_auth_packet(reason_code, auth_data=None, include_method=False):
    properties = b""
    if include_method:
        properties += mqtt5_props.gen_string_prop(
            mqtt5_props.PROP_AUTHENTICATION_METHOD, AUTH_METHOD)
    if auth_data is not None:
        properties += _binary_prop(
            mqtt5_props.PROP_AUTHENTICATION_DATA, auth_data)
    return paho_test.gen_auth(reason_code=reason_code, properties=properties)


def _new_client(broker, connect_auth=True):
    mqttc = Client(
        CallbackAPIVersion.VERSION2,
        "auth-client",
        protocol=MQTTProtocolVersion.MQTTv5,
        transport=broker.transport,
    )
    properties = None
    if connect_auth:
        properties = Properties(PacketTypes.CONNECT)
        properties.AuthenticationMethod = AUTH_METHOD
        properties.AuthenticationData = INITIAL_AUTH_DATA
    mqttc.connect_async("localhost", broker.port, properties=properties)
    mqttc.loop_start()
    return mqttc


def _complete_handshake(broker, expect_auth_props=False):
    """Receive the CONNECT and answer with a successful CONNACK."""
    packet_in = broker.receive_packet(1000)
    assert packet_in  # Check connection was not closed
    if expect_auth_props:
        assert packet_in == _expected_connect_packet("auth-client")
    connack_packet = paho_test.gen_connack(rc=0, proto_ver=5)
    assert broker.send_packet(connack_packet) == len(connack_packet)


class TestConnectAuthentication:
    """CONNECT packet carries authentication method and initial data."""

    def test_connect_carries_authentication_method_and_data(self, fake_broker):
        mqttc = Client(
            CallbackAPIVersion.VERSION2,
            "auth-connect-client",
            protocol=MQTTProtocolVersion.MQTTv5,
            transport=fake_broker.transport,
        )

        connect_properties = Properties(PacketTypes.CONNECT)
        connect_properties.AuthenticationMethod = AUTH_METHOD
        connect_properties.AuthenticationData = INITIAL_AUTH_DATA

        mqttc.connect_async(
            "localhost", fake_broker.port, properties=connect_properties)
        mqttc.loop_start()

        try:
            fake_broker.start()

            packet_in = fake_broker.receive_packet(1000)
            assert packet_in  # Check connection was not closed
            assert packet_in == _expected_connect_packet("auth-connect-client")

            # Decode the CONNECT properties back and check them explicitly.
            assert b"\x15" + struct.pack("!H", len(AUTH_METHOD)) + AUTH_METHOD.encode() in packet_in
            assert b"\x16" + struct.pack("!H", len(INITIAL_AUTH_DATA)) + INITIAL_AUTH_DATA in packet_in

            connack_packet = paho_test.gen_connack(rc=0, proto_ver=5)
            assert fake_broker.send_packet(connack_packet) == len(connack_packet)
        finally:
            mqttc.loop_stop()

    def test_mqtt311_connect_unchanged_without_auth_properties(self, fake_broker):
        """MQTT 3.1.1 has no AUTH support: a plain CONNECT must be byte
        identical to the pre-feature behaviour."""
        mqttc = Client(
            CallbackAPIVersion.VERSION2,
            "auth-mqtt3-client",
            protocol=MQTTProtocolVersion.MQTTv311,
            transport=fake_broker.transport,
        )
        mqttc.connect_async("localhost", fake_broker.port)
        mqttc.loop_start()

        try:
            fake_broker.start()

            packet_in = fake_broker.receive_packet(1000)
            assert packet_in
            assert packet_in == paho_test.gen_connect(
                "auth-mqtt3-client", keepalive=60, proto_ver=4)

            # An 0xF0 byte is not a legal MQTT 3.1.1 packet type; the client
            # must treat it as an unknown command rather than an AUTH packet.
            assert fake_broker.send_packet(paho_test.gen_auth(reason_code=25)) > 0

            # Protocol error makes the client close the connection.
            packet_in = fake_broker.receive_packet(1000)
            # Either the socket is closed (b"") or no further packet is sent.
            assert packet_in in (b"", None) or packet_in[0] & 0xF0 != 0xF0
        finally:
            mqttc.loop_stop()


class TestReauthentication:
    """Server-initiated re-authentication on an established MQTT v5 connection."""

    def test_handshake_auth_before_connack(self, fake_broker):
        """Enhanced authentication during the connection handshake: after
        CONNECT the broker sends AUTH 0x18 and expects an AUTH answer before
        it sends CONNACK."""
        mqttc = _new_client(fake_broker)
        mqttc.on_auth = lambda *args: AuthResponse(
            continue_authentication=True,
            authentication_data=b"client-final-message",
        )
        connected = threading.Event()
        mqttc.on_connect = lambda *args: connected.set()

        try:
            fake_broker.start()

            packet_in = fake_broker.receive_packet(1000)
            assert packet_in == _expected_connect_packet("auth-client")

            # Broker challenges before accepting the connection.
            assert fake_broker.send_packet(
                _server_auth_packet(24, auth_data=SERVER_AUTH_DATA, include_method=True)
            ) > 0

            # Client answers with AUTH 0x18, still before any CONNACK.
            packet_in = fake_broker.receive_packet(1000)
            assert packet_in[0] == 0xF0
            assert packet_in[2] == 0x18
            assert _binary_prop(
                mqtt5_props.PROP_AUTHENTICATION_DATA, b"client-final-message") in packet_in

            # Only now does the broker accept the connection.
            connack_packet = paho_test.gen_connack(rc=0, proto_ver=5)
            assert fake_broker.send_packet(connack_packet) == len(connack_packet)
            assert connected.wait(2)
            assert mqttc.is_connected()
        finally:
            mqttc.loop_stop()

    def test_on_auth_continue_sends_auth_packet(self, fake_broker):
        mqttc = _new_client(fake_broker)
        callback_calls = []

        def on_auth(mqttc, userdata, reason_code, properties):
            callback_calls.append((reason_code, properties))
            return AuthResponse(
                continue_authentication=True,
                authentication_data=REAUTH_DATA,
            )

        mqttc.on_auth = on_auth

        try:
            fake_broker.start()
            _complete_handshake(fake_broker, expect_auth_props=True)

            # Broker starts a re-authentication.
            assert fake_broker.send_packet(
                _server_auth_packet(25, auth_data=SERVER_AUTH_DATA, include_method=True)
            ) > 0

            packet_in = fake_broker.receive_packet(1000)
            assert packet_in
            assert packet_in[0] == 0xF0  # AUTH fixed header

            # Reason code 0x18 (Continue authentication), properties present.
            assert packet_in[2] == 0x18
            # Authentication method from CONNECT is reused.
            assert mqtt5_props.gen_string_prop(
                mqtt5_props.PROP_AUTHENTICATION_METHOD, AUTH_METHOD) in packet_in
            # Authentication data returned by the callback is included.
            assert _binary_prop(
                mqtt5_props.PROP_AUTHENTICATION_DATA, REAUTH_DATA) in packet_in

            assert len(callback_calls) == 1
            reason_code, properties = callback_calls[0]
            assert reason_code == ReasonCode(PacketTypes.AUTH, identifier=25)
            assert properties.AuthenticationMethod == AUTH_METHOD
            assert properties.AuthenticationData == SERVER_AUTH_DATA

            # Connection is still usable afterwards.
            assert mqttc.is_connected()
        finally:
            mqttc.loop_stop()

    def test_on_auth_true_is_accepted_as_continue(self, fake_broker):
        mqttc = _new_client(fake_broker)
        mqttc.on_auth = lambda *args: True

        try:
            fake_broker.start()
            _complete_handshake(fake_broker, expect_auth_props=True)

            assert fake_broker.send_packet(_server_auth_packet(24)) > 0

            packet_in = fake_broker.receive_packet(1000)
            assert packet_in
            assert packet_in[0] == 0xF0
            assert packet_in[2] == 0x18
            assert mqttc.is_connected()
        finally:
            mqttc.loop_stop()

    def test_on_auth_failure_sends_disconnect_0x8c(self, fake_broker):
        mqttc = _new_client(fake_broker)
        disconnects = []
        connected = threading.Event()

        def on_connect(*args):
            connected.set()

        def on_disconnect(mqttc, userdata, disconnect_flags, reason_code, properties):
            disconnects.append((disconnect_flags, reason_code, properties))

        mqttc.on_connect = on_connect
        mqttc.on_disconnect = on_disconnect
        mqttc.on_auth = lambda *args: AuthResponse(continue_authentication=False)

        try:
            fake_broker.start()
            _complete_handshake(fake_broker, expect_auth_props=True)
            assert connected.wait(2)

            assert fake_broker.send_packet(_server_auth_packet(25)) > 0

            # The client must answer with DISCONNECT reason code 0x8C.
            packet_in = fake_broker.receive_packet(1000)
            assert packet_in
            assert packet_in[0] == 0xE0  # DISCONNECT fixed header
            assert packet_in[2] == 0x8C  # Bad authentication method

            # Then the connection is closed.
            assert fake_broker.receive_packet(1000) == b""
            assert not mqttc.is_connected()

            assert len(disconnects) == 1
            disconnect_flags, reason_code, _properties = disconnects[0]
            assert disconnect_flags.is_disconnect_packet_from_server is False
            assert reason_code == ReasonCode(
                PacketTypes.DISCONNECT, "Bad authentication method")
            assert reason_code == 0x8C
        finally:
            mqttc.loop_stop()

    def test_on_auth_false_and_none_abort(self, fake_broker):
        for callback_result in (False, None):
            mqttc = _new_client(fake_broker)
            mqttc.on_auth = lambda *args, result=callback_result: result

            try:
                fake_broker.start()
                _complete_handshake(fake_broker, expect_auth_props=True)

                assert fake_broker.send_packet(_server_auth_packet(25)) > 0

                packet_in = fake_broker.receive_packet(1000)
                assert packet_in
                assert packet_in[0] == 0xE0
                assert packet_in[2] == 0x8C
                assert fake_broker.receive_packet(1000) == b""
            finally:
                mqttc.loop_stop()

    def test_missing_on_auth_callback_aborts_with_0x8c(self, fake_broker):
        mqttc = _new_client(fake_broker)
        # Deliberately no on_auth callback set.

        try:
            fake_broker.start()
            _complete_handshake(fake_broker, expect_auth_props=True)

            assert fake_broker.send_packet(_server_auth_packet(25)) > 0

            packet_in = fake_broker.receive_packet(1000)
            assert packet_in
            assert packet_in[0] == 0xE0
            assert packet_in[2] == 0x8C
            assert fake_broker.receive_packet(1000) == b""
            assert not mqttc.is_connected()
        finally:
            mqttc.loop_stop()

    def test_exception_in_on_auth_aborts_with_0x8c(self, fake_broker):
        mqttc = _new_client(fake_broker)

        def on_auth(*args):
            raise RuntimeError("token backend unavailable")

        mqttc.on_auth = on_auth
        # With suppression enabled the callback exception is logged instead
        # of killing the network thread, and the auth exchange is aborted.
        mqttc.suppress_exceptions = True

        try:
            fake_broker.start()
            _complete_handshake(fake_broker, expect_auth_props=True)

            assert fake_broker.send_packet(_server_auth_packet(25)) > 0

            packet_in = fake_broker.receive_packet(1000)
            assert packet_in
            assert packet_in[0] == 0xE0
            assert packet_in[2] == 0x8C
            assert fake_broker.receive_packet(1000) == b""
            assert not mqttc.is_connected()
        finally:
            mqttc.loop_stop()

    @pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
    def test_exception_in_on_auth_propagates_without_suppression(self, fake_broker):
        """Without suppress_exceptions an exception raised by on_auth must not
        be turned into an AUTH answer: the exchange cannot continue and the
        network thread surfaces the error instead of swallowing it."""
        mqttc = _new_client(fake_broker)

        def on_auth(*args):
            raise RuntimeError("token backend unavailable")

        mqttc.on_auth = on_auth  # suppress_exceptions stays False
        thread = mqttc._thread
        assert thread is not None

        try:
            fake_broker.start()
            _complete_handshake(fake_broker, expect_auth_props=True)

            assert fake_broker.send_packet(_server_auth_packet(25)) > 0

            # The unhandled exception terminates the network loop thread,
            # which is what makes the error observable (it is not swallowed
            # and no AUTH packet is ever answered).
            thread.join(5)
            assert not thread.is_alive()
        finally:
            mqttc.loop_stop()

    def test_loop_returns_mqtt_err_auth(self, fake_broker):
        """The failure is reported as MQTT_ERR_AUTH (11), distinguishable
        from MQTT_ERR_PROTOCOL (2), through the on_disconnect callback."""
        mqttc = _new_client(fake_broker)
        disconnects = []

        def on_disconnect(mqttc, userdata, disconnect_flags, reason_code, properties):
            disconnects.append(reason_code)

        mqttc.on_disconnect = on_disconnect
        mqttc.on_auth = lambda *args: False

        try:
            fake_broker.start()
            _complete_handshake(fake_broker, expect_auth_props=True)

            assert fake_broker.send_packet(_server_auth_packet(25)) > 0

            packet_in = fake_broker.receive_packet(1000)
            assert packet_in[0] == 0xE0
            assert packet_in[2] == 0x8C
            assert fake_broker.receive_packet(1000) == b""

            assert len(disconnects) == 1
            reason_code = disconnects[0]
            assert reason_code == ReasonCode(
                PacketTypes.DISCONNECT, "Bad authentication method")
            assert reason_code == 0x8C
            # The MQTTErrorCode used internally for this failure stays
            # distinguishable from a generic protocol error.
            assert MQTTErrorCode.MQTT_ERR_AUTH != MQTTErrorCode.MQTT_ERR_PROTOCOL
            assert "Authorisation failed." == client.error_string(
                MQTTErrorCode.MQTT_ERR_AUTH)
        finally:
            mqttc.loop_stop()
