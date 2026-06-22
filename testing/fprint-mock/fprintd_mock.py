#!/usr/bin/env python3
"""Deterministic D-Bus mock of the ``net.reactivated.Fprint`` surface for headless verify tests.

This stands in for ``fprintd`` so ``tess-fprint`` can be exercised with no real reader, no real
fprintd, and no libfprint. It mocks only the slice of the D-Bus API the client consumes
(``Manager.GetDefaultDevice`` and ``Device.Claim``/``VerifyStart``/``VerifyStop``/``Release`` plus
the ``VerifyStatus`` signal), built on ``python-dbusmock``.

Run it under a private session bus so nothing leaks onto the developer's real bus::

    dbus-run-session -- python3 fprintd_mock.py <scenario>

It prints the private bus address (``DBUS_SESSION_BUS_ADDRESS``) on the first stdout line, then runs
until terminated. Killing the process (group) tears the whole bus down.

Scenarios driven by argv[1]:

* ``match``    — ``VerifyStart`` immediately emits ``VerifyStatus("verify-match", done=True)``.
* ``no-match`` — ``VerifyStart`` emits ``VerifyStatus("verify-no-match", done=True)``.
* ``stall``    — ``VerifyStart`` returns but never emits, so a bounded client must time out.
"""

import os
import signal
import subprocess
import sys

import dbus
import dbusmock
from gi.repository import GLib

SERVICE = "net.reactivated.Fprint"
MANAGER_PATH = "/net/reactivated/Fprint/Manager"
MANAGER_IFACE = "net.reactivated.Fprint.Manager"
DEVICE_PATH = "/net/reactivated/Fprint/Device/0"
DEVICE_IFACE = "net.reactivated.Fprint.Device"

EMIT = (
    "self.EmitSignal("
    f"'{DEVICE_IFACE}', 'VerifyStatus', 'sb', ['{{token}}', True])"
)
VERIFY_START_BODY = {
    "match": EMIT.format(token="verify-match"),
    "no-match": EMIT.format(token="verify-no-match"),
    "stall": "",
}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in VERIFY_START_BODY:
        print(f"usage: {sys.argv[0]} {{match|no-match|stall}}", file=sys.stderr)
        return 2
    scenario = sys.argv[1]

    bus_address = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if not bus_address:
        print(
            "DBUS_SESSION_BUS_ADDRESS unset — run under `dbus-run-session --`",
            file=sys.stderr,
        )
        return 2

    server = dbusmock.DBusTestCase.spawn_server(
        SERVICE,
        MANAGER_PATH,
        MANAGER_IFACE,
        system_bus=False,
        stdout=subprocess.DEVNULL,
    )

    def reap(*_args: object) -> None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
        sys.exit(0)

    signal.signal(signal.SIGTERM, reap)
    signal.signal(signal.SIGINT, reap)

    bus = dbus.SessionBus()
    dbusmock.DBusTestCase.wait_for_bus_object(SERVICE, MANAGER_PATH)
    manager = dbus.Interface(
        bus.get_object(SERVICE, MANAGER_PATH), dbusmock.MOCK_IFACE
    )
    manager.AddMethod(
        MANAGER_IFACE, "GetDefaultDevice", "", "o", f'ret = "{DEVICE_PATH}"'
    )
    manager.AddMethod(
        MANAGER_IFACE, "GetDevices", "", "ao", f'ret = ["{DEVICE_PATH}"]'
    )

    manager.AddObject(DEVICE_PATH, DEVICE_IFACE, {}, [])
    device = dbus.Interface(
        bus.get_object(SERVICE, DEVICE_PATH), dbusmock.MOCK_IFACE
    )
    device.AddMethod(DEVICE_IFACE, "Claim", "s", "", "")
    device.AddMethod(DEVICE_IFACE, "Release", "", "", "")
    device.AddMethod(DEVICE_IFACE, "VerifyStop", "", "", "")
    device.AddMethod(DEVICE_IFACE, "VerifyStart", "s", "", VERIFY_START_BODY[scenario])

    print(bus_address, flush=True)

    try:
        GLib.MainLoop().run()
    finally:
        reap()
    return 0


if __name__ == "__main__":
    sys.exit(main())
