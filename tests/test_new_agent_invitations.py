"""Never-enrolled recipients: short private capabilities, not public requests."""
import base64
import concurrent.futures
import importlib.util
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
import unittest
import urllib.request
import uuid
from unittest import mock

import test_public_requests as public_fixture


class NewAgentInvitationTests(unittest.TestCase):
    # Reuse real HTTP/signing fixture helpers, not its tests (no duplicate
    # legacy cases or inflated pass counts in this suite).
    setUp = public_fixture.PublicRequestTests.setUp
    stop = public_fixture.PublicRequestTests.stop
    prepared = public_fixture.PublicRequestTests.prepared
    execute = public_fixture.PublicRequestTests.execute
    post = public_fixture.PublicRequestTests.post
    mint = public_fixture.PublicRequestTests.mint
    accept = public_fixture.PublicRequestTests.accept
    state = public_fixture.PublicRequestTests.state
    sql = public_fixture.PublicRequestTests.sql

    def mint_new(self):
        status, out = self.post('/v1/handshakes/invitations', {'enc_v': 1}, 'alice')
        self.assertEqual(status, 200, out)
        self.assertEqual(out['mode'], 'private_invitation')
        self.assertLessEqual(len(out['link']), 120)
        self.assertLessEqual(len(out['link'].replace(self.base, 'https://relay.tryclack.com', 1)), 120)
        return out

    def parts(self, invitation):
        handle, secret = invitation['link'].split('/i/', 1)[1].split('#')
        raw = base64.urlsafe_b64decode(handle + '==')
        return str(uuid.UUID(bytes=raw)), secret

    def fresh_claim(self, invitation, name='fresh-agent', keys=None):
        keys = keys or self.r.ed25519.keygen()
        public = self.r.b64u_encode(keys[1])
        h, k = self.parts(invitation)
        status, challenge = self.post('/v1/enroll/challenge', {'invite_id': h, 'k': k,
                                         'identity_pubkey': public}, peer=None)
        self.assertEqual(status, 200, challenge)
        nonce = self.r.b64u_decode(challenge['nonce'])
        sig = self.r.ed25519.sign(keys[0], nonce + h.encode() + keys[1])
        body = {'h': h, 'k': k, 'identity_pubkey': public, 'requested_name': name,
                'proof': {'nonce': challenge['nonce'], 'signature': self.r.b64u_encode(sig)}}
        return self.post('/v1/handshakes/redeem', body, peer=None), keys

    def test_never_enrolled_recipient_short_url_then_named_consent(self):
        invitation = self.mint_new()
        before = self.state()
        with urllib.request.urlopen(invitation['link']) as page:
            text = page.read().decode()
            self.assertIn('private', text.lower())
            self.assertIn('redeem', text)
            self.assertEqual(page.headers['Referrer-Policy'], 'no-referrer')
        with urllib.request.urlopen(urllib.request.Request(invitation['link'], method='HEAD')) as page:
            self.assertEqual(page.read(), b'')
        self.assertEqual(self.state(), before)
        (status, pending), keys = self.fresh_claim(invitation)
        self.assertEqual(status, 200, pending)
        self.assertEqual(pending['status'], 'pending')
        self.assertEqual(pending['minter_identity'], self.pub['alice'])
        self.assertEqual(self.state(), (4, 1, 1))
        self.keys['fresh-agent'] = keys
        self.tokens['fresh-agent'] = pending['service_token']
        status, active = self.accept(pending, 'fresh-agent')
        self.assertEqual(status, 200, active)
        self.assertEqual((active['status'], active['enc_capable']), ('active', 1))

    def test_response_loss_recovery_keeps_one_identity_pair_and_use(self):
        invitation = self.mint_new()
        (status, lost), keys = self.fresh_claim(invitation)
        self.assertEqual(status, 200)
        (status, recovered), _ = self.fresh_claim(invitation, keys=keys)
        self.assertEqual(status, 200, recovered)
        self.assertEqual(lost['handshake_id'], recovered['handshake_id'])
        self.assertEqual(lost['pending_expires_at'], recovered['pending_expires_at'])
        self.assertEqual(self.state(), (4, 1, 1))
        self.keys['fresh-agent'] = keys
        self.tokens['fresh-agent'] = recovered['service_token']
        self.assertEqual(self.accept(recovered, 'fresh-agent')[0], 200)

    def test_existing_identity_reuses_credentials_and_cannot_swap_claim(self):
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        status, pending = self.post('/v1/handshakes/redeem', {'h': h, 'k': k})
        self.assertEqual(status, 200, pending)
        self.assertNotIn('service_token', pending)
        self.assertEqual(self.state(), (3, 1, 1))
        self.assertEqual(self.accept(pending)[0], 200)
        self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h, 'k': k}, 'eve')[0], 403)
        self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h, 'k': k})[0], 200)
        self.assertEqual(self.state(), (3, 1, 1))

    def test_inviter_cannot_accept_and_revoke_blocks_pending_consent(self):
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        status, pending = self.post('/v1/handshakes/redeem', {'h': h, 'k': k})
        self.assertEqual(status, 200)
        self.assertNotEqual(self.accept(pending, 'alice')[0], 200)
        self.assertEqual(self.post('/v1/invites/revoke', {'invite_id': h}, 'alice')[0], 200)
        self.assertNotEqual(self.accept(pending)[0], 200)
        self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h, 'k': k})[0], 403)

    def test_expiry_blocks_claim_and_pending_accept(self):
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        _, pending = self.post('/v1/handshakes/redeem', {'h': h, 'k': k})
        self.sql('UPDATE invites SET exp=? WHERE invite_id=?', (time.time() - 1, h))
        self.assertNotEqual(self.accept(pending)[0], 200)
        self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h, 'k': k})[0], 403)

    def test_no_claim_in_preview_and_missing_or_wrong_claim_refused(self):
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        before = self.state()
        for body in ({'h': h}, {'h': h, 'k': secrets.token_urlsafe(32)}):
            self.assertNotEqual(self.post('/v1/handshakes/redeem', body)[0], 200)
        with urllib.request.urlopen(invitation['link']) as page:
            self.assertNotIn(k, page.read().decode())
        self.assertEqual(self.state(), before)

    def test_concurrent_distinct_claimants_only_one_pair(self):
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        barrier = threading.Barrier(2)
        def claim(peer):
            barrier.wait()
            return self.post('/v1/handshakes/redeem', {'h': h, 'k': k}, peer)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, ('bob', 'eve')))
        self.assertEqual(sorted(result[0] for result in results), [200, 403])
        self.assertEqual(self.state(), (3, 1, 1))

    def test_concurrent_never_enrolled_keys_one_winner_and_no_orphan_peer(self):
        invitation = self.mint_new()
        original_post = self.post
        barrier = threading.Barrier(2)
        def gated_post(path, body, **options):
            if path == '/v1/handshakes/redeem':
                barrier.wait()
            return original_post(path, body, **options)
        with mock.patch.object(self, 'post', side_effect=gated_post):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda name: self.fresh_claim(invitation, name), ('fresh-one', 'fresh-two')))
        self.assertEqual(sorted(result[0][0] for result in results), [200, 403])
        self.assertEqual(self.state(), (4, 1, 1))
        winner = next(result for result in results if result[0][0] == 200)
        self.assertEqual(self.r.conn.execute(
            'SELECT claimed_identity FROM invites WHERE invite_id=?', (invitation['link_id'],)
        ).fetchone(), (self.r.b64u_encode(winner[1][1]),))

    def test_failed_enrollment_rolls_back_claim_use_and_pair(self):
        invitation = self.mint_new()
        with mock.patch.object(self.r, '_enroll_identity_locked', side_effect=RuntimeError('synthetic write failure')):
            (status, _), keys = self.fresh_claim(invitation)
            self.assertEqual(status, 500)
        self.assertEqual(self.state(), (3, 0, 0))
        self.assertEqual(self.r.conn.execute(
            'SELECT claimed_identity,target_identity FROM invites WHERE invite_id=?', (invitation['link_id'],)
        ).fetchone(), (None, None))
        self.assertEqual(self.fresh_claim(invitation, keys=keys)[0][0], 200)

    def test_concurrent_same_identity_recovers_same_pending_without_extra_use(self):
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        barrier = threading.Barrier(2)
        def claim(_):
            barrier.wait()
            return self.post('/v1/handshakes/redeem', {'h': h, 'k': k})
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, range(2)))
        self.assertEqual([result[0] for result in results], [200, 200])
        self.assertEqual(results[0][1]['handshake_id'], results[1][1]['handshake_id'])
        self.assertEqual(self.state(), (3, 1, 1))

    def test_invite_revalidated_inside_transaction_after_fast_path(self):
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        original = self.r.caller_identity
        def revoke(peer):
            result = original(peer)
            if peer == 'bob':
                self.sql('UPDATE invites SET revoked=1 WHERE invite_id=?', (h,))
            return result
        with mock.patch.object(self.r, 'caller_identity', side_effect=revoke):
            self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h, 'k': k})[0], 403)
        self.assertEqual(self.state(), (3, 0, 0))

    def test_expired_pending_cannot_be_recreated_with_consumed_claim(self):
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h, 'k': k})[0], 200)
        self.sql('UPDATE handshakes SET pending_expires_at=?', (time.time() - 1,))
        self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h, 'k': k})[0], 403)
        self.assertEqual(self.state(), (3, 1, 1))

    def test_mint_signature_and_single_use_scope(self):
        self.assertEqual(self.post('/v1/handshakes/invitations', {'enc_v': 1}, 'alice', signed=False)[0], 401)
        for body in ({'max_uses': 2}, {'target_identity': self.pub['bob']}, {'k': 'chosen'}):
            self.assertEqual(self.post('/v1/handshakes/invitations', body, 'alice')[0], 400)
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        with mock.patch.object(self.r.Handler, '_internal_trusted_source', return_value=True):
            self.assertEqual(self.post('/v1/handshakes/invitations', {'enc_v': 1}, 'alice', signed=False)[0], 401)
            self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h, 'k': k}, signed=False)[0], 401)
        self.assertEqual(self.state(), (3, 0, 0))

    def test_additive_short_migration_and_restart_preserves_current_data(self):
        previous = self.mint()
        self.sql('ALTER TABLE invites DROP COLUMN short_invitation')
        self.sql('ALTER TABLE invites DROP COLUMN claimed_identity')
        self.r.conn.close()
        self.r.init_db(self.cfg)
        self.assertIsNone(self.r._required_schema_ok())
        self.assertEqual(self.r.conn.execute(
            'SELECT short_invitation,claimed_identity FROM invites WHERE invite_id=?',
            (previous['link_id'],)).fetchone(), (0, None))
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        (status, pending), keys = self.fresh_claim(invitation)
        self.assertEqual(status, 200)
        self.r.conn.close()
        self.r.init_db(self.cfg)
        (status, retry), _ = self.fresh_claim(invitation, keys=keys)
        self.assertEqual(status, 200, retry)
        self.assertEqual(retry['pending_expires_at'], pending['pending_expires_at'])
        self.assertEqual(self.state(), (4, 1, 1))
        self.assertEqual(self.r.conn.execute(
            'SELECT claimed_identity,target_identity,uses FROM invites WHERE invite_id=?', (h,)
        ).fetchone(), (self.r.b64u_encode(keys[1]), self.r.b64u_encode(keys[1]), 1))

    def test_short_preview_all_formats_preserves_every_table(self):
        invitation = self.mint_new()
        def snapshot():
            with self.r.db_lock:
                return tuple(tuple(self.r.conn.execute('SELECT * FROM ' + table))
                             for table in self.r.REQUIRED_TABLES)
        before = snapshot()
        for method in ('GET', 'HEAD'):
            for accept in ('application/json', 'text/html', 'text/plain'):
                request = urllib.request.Request(invitation['link'], method=method, headers={'Accept': accept})
                with urllib.request.urlopen(request) as response:
                    data = response.read().decode()
                    self.assertEqual(response.headers['Cache-Control'], 'no-store')
                    self.assertNotIn(self.parts(invitation)[1], data)
                    self.assertNotIn('<script', data)
                    if method == 'HEAD':
                        self.assertEqual(data, '')
        self.assertEqual(snapshot(), before)

    def test_wrong_claim_probes_do_not_poison_private_claimant_budget(self):
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        for _ in range(12):
            self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h, 'k': 'not-the-claim'})[0], 403)
        self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h, 'k': k})[0], 200)

    def test_name_collision_does_not_consume_or_enroll(self):
        invitation = self.mint_new()
        (status, out), _ = self.fresh_claim(invitation, name='bob')
        self.assertEqual((status, out['error']), (409, 'requested_name_unavailable'))
        self.assertEqual(self.state(), (3, 0, 0))
        self.assertEqual(self.fresh_claim(invitation)[0][0], 200)

    def test_predecessor_writer_fails_closed_on_short_claims_and_pending_denial(self):
        # Exercise actual predecessor source against successor-era state, not
        # a simulated old predicate. Pin remains immutable public base.
        root = Path(__file__).resolve().parents[1]
        if not (root / '.git').exists():
            self.skipTest('Exact predecessor source requires Git checkout; native rollback qualification is separate')
        invitation = self.mint_new()
        h, k = self.parts(invitation)
        _, pending = self.post('/v1/handshakes/redeem', {'h': h, 'k': k})
        self.assertEqual(self.post('/v1/invites/revoke', {'invite_id': h}, 'alice')[0], 200)
        unclaimed = self.mint_new()
        h2, k2 = self.parts(unclaimed)
        old_path = Path(self.temp.name) / 'predecessor.py'
        old_path.write_bytes(subprocess.check_output([
            'git', '-C', str(root), 'show', '0c02b037b7c4002a398d3a1de0d2ec5965043842:relay.py']))
        self.r.conn.close()
        with mock.patch.dict(os.environ, {'CLACK_RELAY_BASE': self.temp.name}):
            spec = importlib.util.spec_from_file_location('short_predecessor_relay', old_path)
            old = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(old)
        old._init_identity_pubkeys(self.cfg)
        old.init_db(self.cfg)
        old.relay_cfg = self.cfg
        self.server.RequestHandlerClass = old.Handler
        self.r = old
        self.assertEqual(self.post('/v1/handshakes/redeem', {'h': h2, 'k': k2})[0], 403)
        self.assertNotEqual(self.accept(pending)[0], 200)
        self.assertEqual(self.state(), (3, 1, 1))
