/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 Andong Hu. All rights reserved.
 *
 *   NVMe-oF OFI transport — sideband control protocol (design §5.2).
 *
 *   The wire structs and validators are lifted verbatim from the prototype
 *   (prototype/lib/ofi_sb.c) — they are pure and carrier-agnostic. Only the
 *   logging macros change (OFI_*LOG -> SPDK_*LOG). The prototype's blocking
 *   POSIX framing I/O is NOT lifted: in SPDK the framing is driven from a
 *   reactor sock callback (non-blocking, buffer-and-advance) in ofi.c. A
 *   blocking-style framed writer is provided here for the small, bounded
 *   handshake responses where a single spdk_sock_writev suffices.
 */

#include "ofi_internal.h"

#include "spdk/sock.h"
#include "spdk/log.h"

/* The 4 wire magic bytes. Compared byte-wise (memcmp), never as a uint32, so
 * the value is identical on big- and little-endian peers (design v1.1 note). */
const char ofi_sb_magic[OFI_SB_MAGIC_LEN] = OFI_SB_MAGIC_BYTES;

/* Compile-time wire-layout guarantees. If any of these ever fire, the on-wire
 * format has drifted from the design and every existing peer is now
 * incompatible — fail the build rather than ship a silent mismatch. */
SPDK_STATIC_ASSERT(sizeof(struct ofi_sb_hdr) == 20,
		   "ofi_sb_hdr must be exactly 20 bytes on the wire");
SPDK_STATIC_ASSERT(sizeof(struct ofi_sb_hello) == OFI_SB_MAX_HELLO_PAYLOAD,
		   "ofi_sb_hello must be exactly 496 bytes on the wire");
SPDK_STATIC_ASSERT(sizeof(struct ofi_sb_addr) == 64,
		   "ofi_sb_addr fixed part must be 64 bytes on the wire");
SPDK_STATIC_ASSERT(sizeof(struct ofi_sb_teardown) == OFI_SB_MAX_TEARDOWN_PAYLOAD,
		   "ofi_sb_teardown must be 4 bytes");
SPDK_STATIC_ASSERT(sizeof(struct ofi_sb_error) == OFI_SB_MAX_ERROR_PAYLOAD,
		   "ofi_sb_error must be 256 bytes");

/* --------------------------------------------------------------- validator */

int
ofi_sb_hdr_validate(const struct ofi_sb_hdr *h,
		    uint16_t *out_msg_type,
		    uint32_t *out_payload_len,
		    uint32_t *out_status)
{
	uint32_t plen;
	uint16_t mt;

	/* magic: byte-wise compare against the fixed 'O','F','I','S'. */
	if (memcmp(h->magic, ofi_sb_magic, OFI_SB_MAGIC_LEN) != 0) {
		SPDK_WARNLOG("sideband: bad magic %02x%02x%02x%02x\n",
			     h->magic[0], h->magic[1], h->magic[2], h->magic[3]);
		return -1;
	}
	if (ofi_le16_to_cpu(h->version_le) != OFI_SB_VERSION) {
		SPDK_WARNLOG("sideband: bad version %u (expected %d)\n",
			     ofi_le16_to_cpu(h->version_le), OFI_SB_VERSION);
		return -1;
	}
	/* reserved must be zero on the wire — a non-zero reserved can only mean a
	 * buggy/foreign peer, so reject early rather than carry garbage forward. */
	if (h->reserved_le != 0) {
		SPDK_WARNLOG("sideband: reserved field non-zero (0x%08x)\n",
			     ofi_le32_to_cpu(h->reserved_le));
		return -1;
	}

	plen = ofi_le32_to_cpu(h->payload_len_le);
	if (plen > OFI_SB_MAX_TOTAL_PAYLOAD) {
		SPDK_WARNLOG("sideband: payload_len %u > total cap %u\n",
			     plen, OFI_SB_MAX_TOTAL_PAYLOAD);
		return -1;
	}

	mt = ofi_le16_to_cpu(h->msg_type_le);
	switch (mt) {
	case OFI_SB_HELLO:
		if (plen > OFI_SB_MAX_HELLO_PAYLOAD) {
			SPDK_WARNLOG("sideband: HELLO payload %u > %u\n",
				     plen, OFI_SB_MAX_HELLO_PAYLOAD);
			return -1;
		}
		break;
	case OFI_SB_ADDR_EXCHANGE:
		if (plen > OFI_SB_MAX_ADDR_EXCHANGE_PAYLOAD) {
			SPDK_WARNLOG("sideband: ADDR_EXCHANGE payload %u > %u\n",
				     plen, OFI_SB_MAX_ADDR_EXCHANGE_PAYLOAD);
			return -1;
		}
		break;
	case OFI_SB_TEARDOWN:
		/* TEARDOWN carries a 4-byte reason, NOT payload_len==0 (P0-5). */
		if (plen != sizeof(struct ofi_sb_teardown)) {
			SPDK_WARNLOG("sideband: TEARDOWN payload %u != %zu\n",
				     plen, sizeof(struct ofi_sb_teardown));
			return -1;
		}
		break;
	case OFI_SB_HEARTBEAT:
		if (plen != 0) {
			SPDK_WARNLOG("sideband: HEARTBEAT payload %u != 0\n", plen);
			return -1;
		}
		break;
	case OFI_SB_ERROR:
		if (plen > OFI_SB_MAX_ERROR_PAYLOAD) {
			SPDK_WARNLOG("sideband: ERROR payload %u > %u\n",
				     plen, OFI_SB_MAX_ERROR_PAYLOAD);
			return -1;
		}
		break;
	case OFI_SB_HELLO_ACK:
	case OFI_SB_ADDR_ACK:
		if (plen != 0) {
			SPDK_WARNLOG("sideband: ACK msg_type %u payload %u != 0\n", mt, plen);
			return -1;
		}
		break;
	default:
		SPDK_WARNLOG("sideband: unknown msg_type %u\n", mt);
		return -1;
	}

	if (out_msg_type) {
		*out_msg_type = mt;
	}
	if (out_payload_len) {
		*out_payload_len = plen;
	}
	if (out_status) {
		*out_status = ofi_le32_to_cpu(h->status_le);
	}
	return 0;
}

/* ----------------------------------------------------------------- inits */

void
ofi_sb_hdr_init(struct ofi_sb_hdr *h, uint16_t msg_type,
		uint32_t payload_len, uint32_t status)
{
	memset(h, 0, sizeof(*h));
	memcpy(h->magic, ofi_sb_magic, OFI_SB_MAGIC_LEN);
	h->version_le     = ofi_cpu_to_le16(OFI_SB_VERSION);
	h->msg_type_le    = ofi_cpu_to_le16(msg_type);
	h->payload_len_le = ofi_cpu_to_le32(payload_len);
	h->status_le      = ofi_cpu_to_le32(status);
	h->reserved_le    = 0;
}

void
ofi_sb_hello_init(struct ofi_sb_hello *p,
		  const char *hostnqn, const char *subnqn,
		  uint16_t qid, uint16_t qdepth,
		  uint32_t max_io_size, uint32_t io_unit_size,
		  uint32_t in_capsule_data_size,
		  const char *host_provider)
{
	memset(p, 0, sizeof(*p));
	/* snprintf always NUL-terminates within the buffer, and memset already
	 * zeroed everything, so the receiver's NUL-termination check passes by
	 * construction. Truncation is silent and intentional. */
	snprintf(p->hostnqn, sizeof(p->hostnqn), "%s", hostnqn ? hostnqn : "");
	snprintf(p->subnqn, sizeof(p->subnqn), "%s", subnqn ? subnqn : "");
	snprintf(p->host_provider, sizeof(p->host_provider), "%s",
		 host_provider ? host_provider : "");
	p->qid_le                  = ofi_cpu_to_le16(qid);
	p->qdepth_le               = ofi_cpu_to_le16(qdepth);
	p->max_io_size_le          = ofi_cpu_to_le32(max_io_size);
	p->io_unit_size_le         = ofi_cpu_to_le32(io_unit_size);
	p->in_capsule_data_size_le = ofi_cpu_to_le32(in_capsule_data_size);
}

int
ofi_sb_hello_validate(const struct ofi_sb_hello *p, const char **errstr)
{
#define BAD(msg) do { \
		if (errstr) { *errstr = (msg); } \
		SPDK_WARNLOG("sideband HELLO: %s\n", (msg)); \
		return -1; \
	} while (0)

	if (p->hostnqn[sizeof(p->hostnqn) - 1] != '\0') {
		BAD("hostnqn not NUL-terminated");
	}
	if (p->subnqn[sizeof(p->subnqn) - 1] != '\0') {
		BAD("subnqn not NUL-terminated");
	}
	if (p->host_provider[sizeof(p->host_provider) - 1] != '\0') {
		BAD("host_provider not NUL-terminated");
	}
	/* Negotiation fields (design §5.2.2 v1.1): all must be non-zero so the
	 * peer can size its recv buffers. Zero is a protocol violation. */
	if (ofi_le32_to_cpu(p->max_io_size_le) == 0) {
		BAD("max_io_size == 0");
	}
	if (ofi_le32_to_cpu(p->io_unit_size_le) == 0) {
		BAD("io_unit_size == 0");
	}
	if (ofi_le32_to_cpu(p->in_capsule_data_size_le) == 0) {
		BAD("in_capsule_data_size == 0");
	}
#undef BAD
	return 0;
}

/* --------------------------------------------------- peer-gone classifier */

bool
ofi_sb_is_peer_gone(int rc)
{
	/* recv()==0 (peer FIN) and TCP RST both surface as connection-gone errnos.
	 * §5.4 says treat as a peer crash. EPROTO/EMSGSIZE are deliberately NOT
	 * here (protocol violation, different §5.4 row, but still close). */
	switch (rc) {
	case -ECONNRESET:
	case -ECONNABORTED:
	case -ECONNREFUSED:
	case -ENOTCONN:
	case -ETIMEDOUT:
	case -EPIPE:
	case -ESHUTDOWN:
		return true;
	default:
		return false;
	}
}
