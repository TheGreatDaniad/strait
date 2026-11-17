# Strait security measures

Strait lets one person (the host) share their internet connection with people they trust (guests). Only the two devices ever see the tunnel. Holding an invite lets a guest in, but never lets anyone pose as the host, read another person's traffic, or reach the host's computer and home network. This file covers version 0.6.0; the protocol details are in [nat-tunnel/docs/HANDSHAKE.md](../nat-tunnel/docs/HANDSHAKE.md), and problems are reported as described in [SECURITY.md](../SECURITY.md).

## Who is involved

Every protection below is about what one of these parties can or cannot do to another.

| Party | What it holds | Trusted with |
| --- | --- | --- |
| Host | its private host key (made on first use, owner-only file), the invite key of the current sharing session | being the guests' exit to the internet, like a VPN server |
| Guest | an invite: the invite key, the host's public key (`hk=`), and for a personal invite a token with an id and an end date | nothing beyond using the host's connection |
| Another guest of the same host | its own invite | nothing about you |
| Someone who copied an invite | the same invite as a guest | nothing: this is who the limits on invites are for |
| Meeting services (Nostr relays, DHT, ntfy, MQTT, an optional signal server) | sealed records whose names change every day | only passing a sealed address between the two devices, never the traffic |
| The network in between (ISP, Wi-Fi, a router) | the packets on the wire | nothing: everything it carries is encrypted |

## How a connection is protected, layer by layer

A guest goes through these layers in order; each one stops a different kind of attacker.

1. **The invite names the host.** Every invite carries the host's public key (`hk=`). A guest refuses an invite without one, or with a damaged one, at once. So a copied invite lets someone in as a guest, but never lets them answer as the host.
2. **Finding each other.** When the host has no reachable address, both devices leave a note on public meeting services. The note is encrypted with a key from the invite, the host's note is also signed with its host key, and it is refused 2 minutes after it was signed. The names the notes are stored under change every day. Services see that two addresses met, never what they say to each other.
3. **The join handshake** (Noise `NKpsk0`, X25519, ChaCha20-Poly1305, SHA-256). The guest proves it holds the invite; only the holder of the host key can read the guest's message or answer it. Both sides add a fresh one-time key, so every session has its own keys, and a recorded session stays unreadable even if the invite or the host key leaks later. A [ProVerif model](../nat-tunnel/docs/proverif) proves these properties against an attacker who holds the invite.
4. **The session.** Every packet is encrypted and authenticated (ChaCha20-Poly1305). Keys are replaced every two minutes in both directions, a replayed packet is dropped (sliding window), and a key read from a device later does not open earlier traffic.
5. **Who may come in.** A personal invite carries a token only the host can make, bound to the host key and to the invite it was made from. The host sees who is connected, can remove one person (the removal survives a restart), and with **Change every invite** cancels every old invite at once. A personal invite works on one device at a time.
6. **What a guest can reach.** Only the public internet over IPv4. The host itself, its home network, its router, other guests, cloud metadata addresses (169.254.0.0/16, 168.63.129.16, 100.100.100.200) and mail port 25 are refused before a packet leaves the host. The kernel and the userspace exit apply the same rule set.
7. **What the host can send the guest.** The guest accepts only packets addressed to its own tunnel address that answer something it sent: a new TCP connection is dropped, and UDP reaches only a port the guest used through the tunnel in the last 3 minutes. The host cannot open connections to the guest's device or reach its home network.
8. **How the traffic looks.** Plain encrypted UDP, or one of Shadowsocks, an obfuscated UDP format, WebSocket over TLS (its TLS is signed with the host key, too) or Xray REALITY, for networks that block or inspect UDP. These change the look only; layer 4 protects the content either way.
9. **Privileges.** Sharing runs as an ordinary user on macOS and Linux. A guest's full tunnel needs administrator rights to change routes: only that small tunnel process runs as root, from a copy root installed and checked itself, it gets the invite through a private file, and it writes only into a folder root created. On Windows the app runs as administrator; it loads only the pinned `wintun.dll` and runs system tools by full path.
10. **Limits against abuse.** 20 new handshakes per 10 s per network, three quarters of the slots per network, 64 open TCP connections per guest and 512 in total, the host answering at most 16 new guest addresses an hour, and the guest's port scan capped as described below.

## The attack surface and how it is covered

Each row is one way into a Strait device or session; the last column is what is left after the protection.

| Way in | Who could try | What stops it | What is left |
| --- | --- | --- | --- |
| Sending packets to the host's port | anyone on the internet | every packet must carry a tag made with the invite key; without it the host does no work and sends nothing back | the host's port is visible to scanners |
| Joining | anyone with the invite | personal-invite tokens, "personal invites only", removal, a limit of 20 new handshakes per 10 s per network | the shared invite admits whoever holds it, until the host switches it off or changes every invite |
| Posing as the host | an invite holder on the network path | the host key in every invite, the Noise handshake, signed meeting notes, the WebSocket TLS signed with the host key | none known; proven in the formal model |
| Replaying a recorded join | an invite holder | a timestamp in every join, a memory of every join seen, a join holds a slot only after its first real packet | each replay costs the host one key exchange |
| Flooding joins | an invite holder | per-network limits on handshakes and slots, a full host never pushes out someone else's fresh join | a flood from many networks can still fill free slots |
| Reaching the host, its LAN or router | a connected guest | one exit rule set on every system: public IPv4 internet only | none for the host's own addresses; `--allow-lan` opens the LAN on purpose |
| Reaching other guests | a connected guest | the tunnel network is refused at the exit; each guest has its own keys | none |
| Reaching the guest's device or LAN | the host | the guest drops packets not addressed to it, new TCP connections, and UDP to ports it did not use | the host can ping the guest's tunnel address |
| Using the guest as a port scanner | a malicious host | the scan only targets addresses in the host's signed note, ports 1024 and up, at most 2 addresses for 3 minutes, 3 times an hour per address | within those limits, yes |
| Using the host as a scanner | an invite holder | the host only answers sealed guest notes, at most 16 new addresses an hour | within that limit, yes |
| Fake meeting notes | meeting-service operators, anyone on their path | sealed notes, host notes signed and valid for 2 minutes, unsigned addresses never scanned | the operators see who meets whom and when |
| Local attacks on the guest computer | other programs or users on the same computer | invite never on the command line, root writes only into its own folder, verified copy of the tunnel program, settings and keys owner-only, no links followed | a program running as you can still read your own settings |
| Bugs in Strait's own code | anyone who can send it packets | written in Rust (no buffer overflows in safe code), parsers checked against hostile input, sharing runs without root on macOS and Linux | not audited by an outside party |

## What each side can do

### I host for my friend. What can my friend do?

**Can my friend use my internet connection?**
Yes, that is the point. Everything they do online leaves from your connection with your IP address, so websites and your provider see it as yours. Share only with people you trust. You can cap how much bandwidth guests may use in the app.

**Can my friend open my computer, its files or the apps running on it?**
No. The host refuses every packet a guest sends to the host's own addresses: its tunnel address (10.7.0.1), its local network address and its public address. The only exception is ping to 10.7.0.1, so the guest can check the tunnel works. The rule is the same in the kernel and the userspace exit, on Linux, macOS and Windows.

**Can my friend reach my printer, my NAS, my cameras or my router's settings page?**
No. Private ranges (10/8, 172.16/12, 192.168/16), link-local addresses, multicast and every IPv6 destination are refused. Your router's public address is refused too, so your friend cannot reach its admin page or your port forwards from the outside. You can open the local network on purpose with `--allow-lan`; the app never does it for you.

**Can my friend see or reach my other guests?**
No. Each guest gets its own address, packets between guest addresses are refused at the host, and each session has its own keys. Even with the same shared invite, one guest cannot read another's traffic.

**Can my friend see my own traffic?**
No. Only the guest's own packets travel through the tunnel. Your browsing does not go anywhere near it.

**Can my friend send spam from my connection?**
Not to mail servers directly: outgoing TCP port 25 is blocked, the port spam goes out on. Ordinary email through a mail provider (port 587) works. If you host on a cloud server, its internal metadata addresses are blocked as well.

**Can my friend give my invite to someone else?**
A shared invite works for anyone who has it, up to the number of guests you allow. That is why personal invites exist: one per person, each with its own id. A personal invite works on one device at a time: a copy is refused as "full" while its owner is connected. A copy can still be used while the owner is offline, and you see it under that person's name.

**Can I throw my friend out for good?**
Yes. **Remove** disconnects them, withdraws their personal invite, and switches on "personal invites only" so they cannot come back with the shared invite. The removal survives restarts. **Change every invite** goes further: it starts a new sharing session with a new invite key, so every old invite, shared or personal, stops working. A removed person then cannot even read where you can be found.

**Can my friend pretend to be me to my other guests?**
No. Every invite names your host key, and only your device holds the private half. The handshake, the signed meeting notes and the WebSocket TLS all check it, so a guest refuses anyone else.

**Can my friend overload my computer?**
There are limits: each guest may keep 64 TCP connections open through you and all guests together 512, a network may start 20 new handshakes every 10 seconds, and one network cannot take more than three quarters of your guest slots. A determined friend can still use the bandwidth you allow.

**Can my friend break into my computer through Strait?**
Only through a bug in Strait's own code, which is written in Rust and checks every packet before it acts on it. On macOS and Linux sharing runs as your ordinary user, so even a bug would not give administrator rights. On Windows the app runs as administrator. Strait has not been audited by an outside party.

**Can my friend find out my IP address?**
Yes. The two devices connect directly, so each sees the other's public address.

### My friend hosts for me. What can the host do?

**Can the host see what I do online?**
Partly, the same way any VPN provider can. The host can see which addresses you connect to, when, and how much, and the names you look up when your DNS is not encrypted. The content of encrypted connections (HTTPS, messaging apps, other VPNs) stays unreadable to the host. Use the host the way you would use a VPN you trust.

**Can the host change what I download?**
Only unencrypted traffic, such as plain `http://` pages. Anything over HTTPS is protected by the website's certificate, which the host cannot fake.

**Can the host get into my computer?**
No. Your device accepts from the tunnel only packets addressed to its own tunnel address that answer something it sent. A new TCP connection from the host is dropped, and UDP is accepted only on ports your device used through the tunnel in the last 3 minutes. Services on your computer (file sharing, SSH, a development server) are not reachable through the tunnel. The host can only ping your tunnel address.

**Can the host reach my home network?**
No. Packets for any address other than your tunnel address are dropped, so even a computer that forwards packets (Docker turns this on) cannot be used as a door into your LAN. Your own local network (10/8, 172.16/12, 192.168/16) stays outside the tunnel: printers and NAS keep working directly.

**Can someone pretend to be my friend's host?**
No. The invite names the host's key, and your device checks it in the handshake, in the meeting notes and in the WebSocket TLS. Someone who has the same invite, or who controls a meeting service, still cannot answer for the host. A forged "host is full" or "refused" answer is impossible too: those answers come inside the encrypted handshake.

**Can other guests of the same host see my traffic or my computer?**
No. Each guest has its own session keys, and the host refuses traffic between guests.

**Can the host make my computer attack someone?**
Only in a narrow way. A host behind a strict router (a symmetric NAT) needs guests to try many ports of its address to get through. A malicious host could name someone else's address in its signed note. That scan is limited to ports 1024 and up, at most 2 addresses for 3 minutes, and 3 times an hour per address, so services on the low ports, such as web (80, 443), mail and SSH, are never touched.

**Can the host learn who I am?**
The host learns your public IP address (the devices connect directly), when you connect, and, with a personal invite, which invite you used. Nothing else about you is sent.

**What runs with administrator rights on my computer?**
To send all your traffic through the tunnel, Strait has to change routes, which needs your password once per connection. Only the small tunnel process runs as root: it is a copy root installed and checked against the program you opened, it receives the invite through a private file (never the command line, where other users could read it), and it writes its log only into a folder root created. The window itself stays an ordinary program on macOS and Linux.

**What happens if the tunnel drops?**
Your normal connection is used again. Strait has no kill switch yet, so in that moment your traffic leaves from your own address. While connected, IPv6 is switched off on every network adapter (Windows) or refused by routes (macOS, Linux), because the tunnel carries IPv4 only.

### What can everyone else do?

**Can my internet provider or someone on the Wi-Fi read the tunnel?**
No. They see encrypted packets between two addresses, how many and when. With one of the other transports the packets also look like Shadowsocks, random UDP, an HTTPS connection or an Xray REALITY connection. They can block the connection; they cannot read it, change it unnoticed, or join it.

**Can someone who scans the internet find a Strait host?**
They can see that a UDP port answers nothing: a host ignores every packet without a valid invite tag. A WebSocket host shows a self-signed certificate to anyone who connects; where that matters, Xray REALITY or a real certificate (`tls=ca`) hides it.

**Can the meeting services (Nostr relays, the DHT, ntfy, MQTT) see my traffic or my invite?**
No. They only carry the sealed note with each device's address, and only until the tunnel is up. They do see the IP addresses that publish and read, and when. The names notes are stored under change every day, so a service cannot easily link one day's meetings to the next. Trackers, which cannot seal anything, are not offered in the app.

**Can a meeting service send me to a fake host?**
No. A guest accepts only host notes signed with the key in its invite, and refuses a note older than 2 minutes. An unsigned address is never scanned.

**Can someone who stole an invite read my sessions?**
No. Every session has its own keys from both sides' one-time keys, so a stolen invite (or even a stolen host key) does not open recorded or current sessions of other people. With a shared invite they can join as a new guest until the host switches to personal invites only or changes every invite.

**Can another program on my computer steal the invite?**
Not from the process list: the invite is never on the command line, which every user of the computer can read. It comes from the window, a private file, the environment or standard input. A program running as your own user can read your own files, as it can for any app.

## What is not covered

These are known and stated in the design notes; none of them lets anyone read a session or reach a device's own network.

- **No kill switch.** If Strait stops or the tunnel drops, the guest's traffic uses its normal connection again.
- **The host is an exit.** It sees where its guests' traffic goes and any unencrypted content, as any VPN provider does. Guests should trust the host that much.
- **Hosting shares your IP.** What a guest does online appears to come from the host.
- **A copied personal invite works while its owner is offline.** The host sees it under that person's name and can remove it.
- **A malicious host can aim its guests' port scan** at an address of its choice, within the limits above.
- **A signed host note can be replayed for 2 minutes** by an invite holder.
- **Windows runs the whole app as administrator.** macOS and Linux run only the tunnel with administrator rights.
- **No outside audit.** The design has a formal model and two rounds of review, but no independent security firm has checked it.
- **Not tested by a person at the screen:** the macOS password prompt for the tunnel process, and the Windows window on a real desktop.

## How this was checked

- **Code review:** an outside critique of the handshake, then two full reviews of the codebase (handshake and crypto, rendezvous and transports, operating system and privileges). Every finding is fixed or listed under "What is not covered".
- **Formal model:** [ProVerif](../nat-tunnel/docs/proverif) proves token secrecy, traffic secrecy, host authentication with injective agreement, and that a host seeing a guest's token got it from that guest.
- **Tests:** about 590 unit and integration tests, among them forged and replayed handshakes, withdrawn and copied personal invites, the exit rules, the guest's inbound rule and hostile input to every parser.
- **AWS lab:** real machines behind different NAT types in three regions, plus public Linux and Windows hosts, check each rule end to end on every release: what a guest can reach, invites and removals, forward mode, key rotation under load, Windows as host and guest, and a traffic-inspection simulator.

Results for 0.6.0 on the lab: invites 10 of 10; every exit rule holds on the kernel and the userspace exit; a host could reach a web server and SSH on a 0.5.0 guest and cannot on a 0.6.0 guest; a second forward-mode guest was refused 24 times while the first guest's connection sat idle for 75 s; direct connections 12 of 12; through meeting services 17 of 20 (WebSocket with a symmetric NAT is the known gap); key rotation over 290 s with 0% loss; Windows guest at 275 Mbit/s with IPv6 off during the session and restored after.
