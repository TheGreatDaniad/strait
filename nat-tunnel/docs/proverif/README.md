# ProVerif model of the join handshake

`strait_nkpsk0.pv` models the join (Noise `NKpsk0` with the personal-invite token in message 1)
against an attacker who controls the network and holds the invite (the psk and `hk`), but not the
host key or the honest guest's token. See the comments in the file for what is left out.

Run with ProVerif 2.05 (`opam install proverif`):

```sh
proverif strait_nkpsk0.pv | grep RESULT
```

Results:

```text
RESULT not attacker(token[]) is true.
RESULT not attacker(secret_data[]) is true.
RESULT inj-event(GuestDone(hk_2,eg_1,eh_1,k_2)) ==> inj-event(HostAccepted(hk_2,eg_1,eh_1,k_2)) is true.
RESULT event(HostSawToken(token[])) ==> event(GuestSentToken(token[])) is true.
RESULT not event(GuestDone(hk_2,eg_1,eh_1,k_2)) is false.
```

1. The guest's personal token stays secret, so it also hides who is joining.
2. Traffic the guest sends under the session key stays secret.
3. A guest that finishes a join talked to the holder of the host key, and both agree on the two
   ephemeral keys and the session key (injective: one host run per guest run).
4. A host that sees the guest's token got it from that guest.
5. Sanity check: a join can complete, so 1 to 4 do not hold for an empty reason.
