-- Smoke test for the init scripts, run as pv2_core after 00_roles.sh and 10_schema.sql (CI job core-db).
-- Every check raises an exception on failure, so psql -v ON_ERROR_STOP=1 exits non-zero.
\set ON_ERROR_STOP 1

DO $$
DECLARE
    e text := 'elc_' || repeat('0', 26);
    n text := repeat('a', 64);
    r text;
BEGIN
    INSERT INTO credential.elections (election_id, title, candidates, config_window_start, config_window_end,
        time_bucket_seconds, checkpoint_interval_seconds, organizations, approval_threshold, proposal_ttl_hours,
        operator_org, public_key, private_key, config_hash)
    VALUES (e, 'smoke', '[]', '2026-11-03T09:00:00Z', '2026-11-03T10:00:00Z', 60, 60, '[]', 2, 24,
        'org_commission', decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'), repeat('c', 64));

    -- redeem path: register a credential through the SECURITY DEFINER function
    PERFORM ballot.register_nullifier(e, n, 1);

    -- second registration of the same nullifier must fail
    BEGIN
        PERFORM ballot.register_nullifier(e, n, 1);
        RAISE EXCEPTION 'duplicate nullifier was accepted';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;

    -- ballots: unknown credential, first cast, identical retry, different ballot
    r := ballot.cast_ballot(e, repeat('b', 64), repeat('1', 64), '\x00', repeat('2', 64), 1,
                            '2026-11-03T09:00:00Z', 'evr_' || repeat('1', 26));
    IF r <> 'UNKNOWN' THEN RAISE EXCEPTION 'expected UNKNOWN, got %', r; END IF;
    r := ballot.cast_ballot(e, n, repeat('1', 64), '\x00', repeat('2', 64), 1,
                            '2026-11-03T09:00:00Z', 'evr_' || repeat('2', 26));
    IF r <> 'CREATED' THEN RAISE EXCEPTION 'expected CREATED, got %', r; END IF;
    r := ballot.cast_ballot(e, n, repeat('1', 64), '\x00', repeat('2', 64), 1,
                            '2026-11-03T09:00:00Z', 'evr_' || repeat('3', 26));
    IF r <> 'RETRY' THEN RAISE EXCEPTION 'expected RETRY, got %', r; END IF;
    r := ballot.cast_ballot(e, n, repeat('9', 64), '\x01', repeat('2', 64), 1,
                            '2026-11-03T09:00:00Z', 'evr_' || repeat('4', 26));
    IF r <> 'CONFLICT' THEN RAISE EXCEPTION 'expected CONFLICT, got %', r; END IF;

    -- pv2_core must not write ballot tables directly
    BEGIN
        UPDATE ballot.ballot_receipts SET ballot_hash = repeat('f', 64) WHERE election_id = e;
        RAISE EXCEPTION 'pv2_core could update ballot.ballot_receipts';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        DELETE FROM ballot.credential_issuance WHERE election_id = e;
        RAISE EXCEPTION 'pv2_core could delete from ballot.credential_issuance';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;

    -- a USED token can never be revoked
    INSERT INTO credential.roster (election_id, voter_key, name, added_checkpoint)
    VALUES (e, 'vtr_' || repeat('A', 26), 'Voter', 0);
    BEGIN
        INSERT INTO credential.token_status (election_id, token_hash, voter_key, issued_checkpoint, used_checkpoint,
                                             revoked_checkpoint)
        VALUES (e, repeat('d', 64), 'vtr_' || repeat('A', 26), 0, 1, 2);
        RAISE EXCEPTION 'used and revoked token was accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
END;
$$;

-- commit timestamps must stay off (threat-model S2)
DO $$
BEGIN
    IF current_setting('track_commit_timestamp') <> 'off' THEN
        RAISE EXCEPTION 'track_commit_timestamp is on';
    END IF;
END;
$$;

SELECT 'smoke ok' AS result;
