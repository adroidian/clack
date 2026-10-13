"""Bounded serving adapter for reviewed relay; exact operator-owned bind."""
import threading
from http.server import ThreadingHTTPServer
import relay

class Handler(relay.Handler):
    def setup(self):
        self.request.settimeout(10)
        super().setup()

class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self,*args,**kwargs):
        self.slots = threading.BoundedSemaphore(24)
        super().__init__(*args,**kwargs)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request,address)
        except BaseException:
            self.slots.release()
            raise
    def process_request_thread(self,request,address):
        try:
            super().process_request_thread(request,address)
        finally:
            self.slots.release()
    def handle_error(self,request,address):
        pass  # no attacker-controlled request/error strings in service logs

def run(bind='127.0.0.1', port=7331):
    cfg = relay.load_config()
    relay.relay_cfg = cfg  # main() sets this; mint-link needs it for base_url
    # Mirror relay.main() startup sequence: the _init_* calls populate
    # module globals (peer_hashes, identity_pubkeys, reserved names,
    # handshake knobs) that init_db depends on. Skipping them silently
    # revokes hash-only peers (e.g. sigrid) on startup, and leaves
    # relay_cfg unset which crashes /v1/handshakes/mint-link.
    relay._init_reserved_names(cfg)
    relay._init_identity_pubkeys(cfg)
    relay._init_peer_hashes(cfg)
    relay._parse_handshake_knobs(cfg)
    relay.load_identity_key(cfg)
    # candidate-679-py-federation-v1: strict operator config for cross-home
    # forwarding (absent = disabled; malformed = refuse startup).
    relay._init_federation(cfg)
    relay.init_db(cfg)
    # Same maintenance lifecycle as relay.main(): the sweep no longer
    # piggybacks on requests, so without this no expiry/GC or
    # handshake-revoke maintenance ever runs on this entrypoint
    # (safety-audit Round 3: previously missing here entirely).
    relay._start_sweep_thread()
    # candidate-679-py-federation-v1: cross-home forwarder daemon (starts
    # nothing when federation is not configured).
    relay._start_federation_thread()
    with Server((bind, port), Handler) as server:
        server.serve_forever()

if __name__ == '__main__':
    run()
