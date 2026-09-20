"""Local benchmark only: explicitly gate the first projection inside its lock."""

import os
import socket
import threading

from config.wsgi import application as django_application
from forensics import projections

state = threading.local()
original_project_event = projections.project_event


def gated_project_event(event, projection_state=None):
    if getattr(state, "gate", False):
        state.gate = False
        with socket.create_connection(("127.0.0.1", int(os.environ["LAB_GATE_PORT"]))) as sock:
            sock.settimeout(30)
            sock.sendall(b"ready")
            if sock.recv(1) != b"1":
                raise RuntimeError("lab gate closed")
    return original_project_event(event, projection_state)


projections.project_event = gated_project_event


def application(environ, start_response):
    state.gate = environ.get("HTTP_X_LAB_GATE") == "1"
    if state.gate:
        with socket.create_connection(("127.0.0.1", int(os.environ["LAB_GATE_PORT"]))) as sock:
            sock.sendall(b"start")
    try:
        return django_application(environ, start_response)
    finally:
        state.gate = False
