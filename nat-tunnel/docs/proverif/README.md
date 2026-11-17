# ProVerif model of the join handshake

`strait_nkpsk0.pv` models the join (Noise `NKpsk0` with the personal-invite token in message 1)
against an attacker who controls the network and holds the invite (the psk and `hk`), but not the
host key or the honest guest's token. In a second phase, after every session, the attacker also
gets the host key: this checks forward secrecy. The header of the file lists what the model leaves
out or simplifies.

Run with ProVerif 2.05 (`opam install proverif`):

```sh
proverif strait_nkpsk0.pv | grep RESULT
```

Results (`attacker_p1` is the attacker's knowledge after the host key leaked):

```text
RESULT not attacker(token[]) is true.
RESULT not attacker_p1(g2h[]) is true.
RESULT not attacker_p1(h2g[]) is true.
RESULT inj-event(GuestDone(hk_2,eg_1,eh_1,k_2)) ==> inj-event(HostAccepted(hk_2,eg_1,eh_1,k_2)) is true.
RESULT not (event(HostAcceptedTok(token[],eg_1,eh_1,k_2)) && attacker_p1(k_2)) is true.
RESULT event(HostAcceptedTok(token[],eg_1,eh_1,k_2)) ==> event(GuestStarted(eg_1)) is true.
RESULT not attacker_p1(token[]) is false.
RESULT not event(GuestDone(hk_2,eg_1,eh_1,k_2)) is false.
RESULT not event(HostAcceptedTok(token[],eg_1,eh_1,k_2)) is false.
```

1. The guest's personal token stays secret while the host key does, so it also hides who is joining.
2. Traffic the guest sends stays secret, even after the host key leaks (forward secrecy).
3. Traffic the host sends in the honest guest's sessions stays secret, even after the host key leaks.
4. A guest that finishes a join talked to the holder of the host key, and both agree on the two
   ephemeral keys and the session key (injective: one host run per guest run).
5. Host side: every session the host accepts under the honest guest's token has a key the attacker
   never learns, whether the attacker replays the guest's message 1 or later steals the host key.
6. Host side: a message 1 carrying the honest guest's token was made by that guest (its ephemeral
   key). Not injective: replays are bounded by the host's replay memory, which is not modelled.
7. Expected false, a documented limit: the token is not forward secret. It travels under the `es`
   key only, so whoever records a join and later gets the host key learns the token (not the
   traffic).
8. and 9. Sanity checks: a join completes on both sides with the honest token, so 1 to 6 do not hold
   for an empty reason.
