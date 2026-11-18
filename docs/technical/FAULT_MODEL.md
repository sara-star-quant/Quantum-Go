# Datagram fault model and how to reproduce the tests

The datagram transport is tested against a deterministic in-memory network that loses, duplicates and reorders datagrams. This page says what that network does and does not do, which test checks which property, and how to re-run any of it.

## The network

`memPipe(seed, drop, dup, reorder)` in `pkg/tunnel/dgram_handshake_e2e_test.go` returns two connected `net.PacketConn` ends. Each direction has its own fault model, seeded from `seed` and `seed+1`. Each datagram written to an end goes through these steps, in order:

| Fault | What it does |
| --- | --- |
| Loss | Drops the datagram with probability `drop` |
| Reordering | With probability `reorder`, holds one datagram back until the next one overtakes it. Only one datagram is held at a time, so a held tail needs a later datagram to release it |
| Duplication | Delivers a datagram twice with probability `dup` |
| Targeted loss | `setDropFirst(type)` drops exactly the first handshake datagram of one message type, for recovery tests |
| Overflow | A receiver queue holds 256 datagrams and drops the rest, as UDP allows |

Each datagram faces these faults on its own. A ClientHello travels as several fragments, so one fragment can be lost or duplicated while its neighbours arrive.

## What it does not model

- **Delay and jitter.** Reordering stands in for them, but no datagram arrives late by wall-clock time.
- **Corruption.** Bit flips and forged datagrams belong to the tamper tests and the fuzz targets, not to this network.
- **Path MTU and real sockets.** There is no UDP socket, no GSO or GRO, and no kernel buffer.
- **Address changes under faults.** Roaming has deterministic tests (`dgram_roaming_test.go`), not seeded ones.

## What a seed fixes

A seed fixes the sequence of faults each direction applies to its datagrams. It does not fix goroutine scheduling or the retransmit timers (5 to 50 ms), so a run that fails once usually fails again on the same seed but is not bit-for-bit repeatable. Use `-count` to run it many times.

## What each test checks

| Test | Faults | Property |
| --- | --- | --- |
| `TestDgramHandshakeE2E` | loss 0.2, duplication 0.1, reordering 0.15, seeds 1 to 24 | The handshake completes and both ends derive matching keys |
| `TestDatagramHandshakeBranchesUnderFaults` | loss 0.15, duplication 0.1, reordering 0.2, seeds 1 to 16 | The cookie-gated handshake and the HelloRetryRequest handshake complete, land on the suite the server insists on, and carry data both ways |
| `TestDatagramRetryRequestSurvivesEachFault` | loss, duplication, reordering, two together and all three, seeds 1 to 24 each | The HelloRetryRequest handshake completes under each fault alone |
| `TestDatagramDataPlaneProperty` | duplication 0.3 with reordering 0.3, and loss 0.15 with duplication 0.1 and reordering 0.2, seeds 1 to 24 each | Every payload that arrives was sent, none arrives twice, and a loss-free link delivers all 40 messages |
| `TestDatagramRekeyConvergesUnderFaults` | three profiles, seeds 1 to 8 each | A rekey completes or reports failure, and a retry always converges on one epoch |
| `TestDatagramRekeyTargetedLoss` | the first RekeyInit, or the first RekeyResponse, is lost | The retransmit completes the rekey |
| `TestDatagramReplayWindow_AdmissibleAgreesWithCheck` | none: a reference model over reordering, repeats and jumps | The replay window's cheap pre-check and its authoritative check agree and the pre-check records nothing |

## Reproduce

A failing seed is in the subtest name. Re-run one seed many times:

```
go test -run 'TestDatagramDataPlaneProperty/lossy/seed-5' -race -count=20 ./pkg/tunnel
go test -run 'TestDatagramRetryRequestSurvivesEachFault/duplication/seed-2' -count=50 ./pkg/tunnel
```

Run a whole family, with the race detector and in FIPS build mode:

```
go test -race -run 'Datagram|Dgram' ./pkg/tunnel
go test -tags fips -run 'Datagram|Dgram' ./pkg/tunnel
```

Run the tests a change touches under CPU contention, shuffled, with the race detector and again with the FIPS tag, as CI does:

```
scripts/stress-changed-tests.sh origin/main        # COUNT=10 runs per test, HOGS=<n> burners
```

To check that a test would notice a bug, weaken the code and run it. For the replay window, make `Check` and `Admissible` in `pkg/tunnel/replay.go` return `true` on entry. `TestDatagramDataPlaneProperty` then fails every one of its 48 subtests.

## What the faults found

A duplicated or reordered datagram broke the HelloRetryRequest handshake. The reassembler keyed fragment buffers by sender and message type, and the retry handshake sends two ClientHellos of different sizes under that key, so a late fragment of the first blocked the second until the reassembly timeout. Before the fix, a probe of 24 seeds per profile failed 9 on a link that only duplicated, 6 on one that only reordered, 7 on both and 2 on loss only. After it, `TestDatagramRetryRequestSurvivesEachFault` passes all 24 seeds for every profile. The fix keys buffers by declared size too.

## Not covered yet

Delay, and seeded roaming under faults. Issue #275 tracks them.
