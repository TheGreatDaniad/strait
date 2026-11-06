/* Strait C ABI (nat-tunnel, feature "ffi"). Hand-written; keep in sync with src/ffi.rs.
 *
 * Threading: every function is thread-safe and catches Rust panics (returns an error value).
 * strait_client_start never blocks. strait_probe / strait_check_host block up to ~10 s: call them
 * off the main thread. The status callback runs on a Strait thread, never on the caller's.
 * Only ONE client may run per process. The TUN fd is never closed by Strait.
 */
#ifndef STRAIT_H
#define STRAIT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status JSON (UTF-8, valid only during the call), same payload as Android's StraitStatus:
 *   {"state":"connecting|connected|failed|idle", "message"?:str, "ip"?:"10.7.0.x",
 *    "prefix"?:16, "gateway"?:"10.7.0.1", "path"?:"direct|signal", "bytesIn":n, "bytesOut":n,
 *    "clients":0, "needTun"?:true}
 * "needTun":true means: the host assigned `ip`; apply setTunnelNetworkSettings for it, then call
 * strait_client_set_fd (unless an fd >= 0 was given to strait_client_start). */
typedef void (*strait_status_cb)(const char *json, void *user);

/* Static NUL-terminated crate version. */
const char *strait_version(void);

/* Writes 32 lowercase hex chars + NUL into out[33]. 0 ok, -1 error. */
int32_t strait_generate_key(char *out);

/* Probe rendezvous services without publishing. ids_csv: "sig,trk,..." or NULL/"" for all
 * compiled-in. out_json = JSON array like `rv-test --json`:
 * [{"id":"trk","status":"reachable|blocked|error","rtt_ms"?:n,"detail"?:str}]. Returns bytes written (excl. NUL), -1 error, -2 cap too small. */
int32_t strait_probe(const char *ids_csv, char *out_json, size_t cap);

/* Preflight like `check-host --json`. key and rv_csv may be NULL. Same return codes. */
int32_t strait_check_host(uint16_t port, const char *key, const char *rv_csv, char *out_json, size_t cap);

/* Start the client. tun_fd: utun fd (datagram, 4-byte AF header per packet), or -1 to deliver
 * it later via strait_client_set_fd after the address is known. rv_disable_csv may be NULL.
 * Returns a handle, or NULL for a bad invite / missing callback / client already running. */
void *strait_client_start(const char *invite, int32_t tun_fd, const char *rv_disable_csv,
                         strait_status_cb status_cb, void *user);

/* Hand over the utun fd. 0 ok, -1 bad handle. */
int32_t strait_client_set_fd(void *handle, int32_t fd);

/* Graceful stop: BYE to the host, cleanup, waits up to 2 s, frees the handle. Call once.
 * 0 stopped in time, 1 timed out (worker detached), -1 bad handle. */
int32_t strait_client_stop(void *handle);

#ifdef __cplusplus
}
#endif
#endif
