/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 Andong Hu. All rights reserved.
 *
 *   NVMe-oF OFI transport — internal header.
 *
 *   Sideband control-channel wire format (design §5.2), lifted verbatim from
 *   the prototype (prototype/lib/ofi_sb.h). The wire structs and validators are
 *   carrier-agnostic and shared between the target (lib/nvmf/ofi.c) and the
 *   future host (lib/nvme/nvme_ofi.c) sides — design §3.1.
 *
 *   Wire-format invariants (design §5.2.1):
 *     - all multi-byte integers are explicitly little-endian
 *     - structs are __attribute__((packed)); never assume native alignment
 *     - every message is: 20-byte hdr + 0..MAX_PAYLOAD(msg_type) bytes
 *     - receiver MUST validate magic / version / payload_len before parsing the
 *       payload (design §5.6 anti-DoS)
 */

#ifndef SPDK_NVMF_OFI_INTERNAL_H
#define SPDK_NVMF_OFI_INTERNAL_H

#include "spdk/stdinc.h"

/* ------------------------------------------------------------- wire magic */

/*
 * Magic is the 4 bytes {'O','F','I','S'} compared byte-wise. Stored as a char
 * array (not a uint32) on purpose: a uint32 constant reinterprets differently
 * on big-endian, so a memcmp against 4 fixed bytes is the only portable form
 * (design v1.1 note).
 */
#define OFI_SB_MAGIC_BYTES	{'O', 'F', 'I', 'S'}
#define OFI_SB_MAGIC_LEN	4
extern const char ofi_sb_magic[OFI_SB_MAGIC_LEN];

#define OFI_SB_VERSION		1

/* ------------------------------------------------------------- msg types */

enum ofi_sb_msg_type {
	OFI_SB_HELLO		= 1,
	OFI_SB_HELLO_ACK	= 2,
	OFI_SB_ADDR_EXCHANGE	= 3,
	OFI_SB_ADDR_ACK		= 4,
	OFI_SB_TEARDOWN		= 5,
	OFI_SB_ERROR		= 6,
	OFI_SB_HEARTBEAT	= 7,
};

/* status codes that may appear in hdr.status (design §5.2.1 + §9). */
enum ofi_sb_status {
	OFI_SB_STAT_OK		= 0,
	OFI_SB_STAT_ENOENT	= 2,	/* subnqn / hostnqn not found */
	OFI_SB_STAT_EINVAL	= 22,	/* validation failure */
	OFI_SB_STAT_E2BIG	= 7,	/* payload too large */
	OFI_SB_STAT_ENOMEM	= 12,	/* out of resources */
	OFI_SB_STAT_EACCES	= 13,	/* hostnqn not allowed */
	OFI_SB_STAT_ETRANSIENT	= 200,	/* transient; retry */
};

/* per-msg_type payload caps. Receiver rejects anything bigger (design §5.2.1). */
#define OFI_SB_MAX_HELLO_PAYLOAD		496
#define OFI_SB_MAX_ADDR_EXCHANGE_PAYLOAD	1100
#define OFI_SB_MAX_TEARDOWN_PAYLOAD		4
#define OFI_SB_MAX_ERROR_PAYLOAD		256
#define OFI_SB_MAX_HEARTBEAT_PAYLOAD		0
#define OFI_SB_MAX_TOTAL_PAYLOAD		(16384 - 20)

/* ----------------------------------------------------------- wire structs */

/* Common header — exactly 20 bytes on the wire. Layout MUST stay packed and
 * field order MUST NOT change after the first deployment. */
struct ofi_sb_hdr {
	uint8_t		magic[OFI_SB_MAGIC_LEN];	/* 'O','F','I','S' */
	uint16_t	version_le;			/* == OFI_SB_VERSION */
	uint16_t	msg_type_le;			/* enum ofi_sb_msg_type */
	uint32_t	payload_len_le;			/* byte count of payload that follows */
	uint32_t	status_le;			/* enum ofi_sb_status (0 = OK) */
	uint32_t	reserved_le;			/* must be 0; receiver rejects non-0 */
} __attribute__((packed));

/* HELLO payload — exactly 496 bytes (design §5.2.2). */
struct ofi_sb_hello {
	char		hostnqn[224];			/* NUL-terminated; receiver forces [223]=0 */
	char		subnqn[224];			/* same */
	uint16_t	qid_le;				/* 0 = admin */
	uint16_t	qdepth_le;
	uint32_t	max_io_size_le;
	uint32_t	io_unit_size_le;
	uint32_t	in_capsule_data_size_le;
	char		host_provider[32];		/* NUL-terminated; receiver forces [31]=0 */
} __attribute__((packed));

/* ADDR_EXCHANGE payload — fixed part is 64 bytes, then ep_addr[] (design §5.2.3). */
#define OFI_SB_ADDR_FLAG_RMA_CAPABLE	(1u << 0)
struct ofi_sb_addr {
	char		provider[32];			/* NUL-terminated */
	uint32_t	ep_addr_len_le;
	uint32_t	mtu_le;
	uint32_t	flags_le;			/* bit0 = RMA-capable (V2) */
	uint32_t	data_buf_count_le;		/* V2 only */
	uint64_t	data_buf_addr_le;		/* V2 only */
	uint64_t	data_buf_key_le;		/* V2 only */
	/* followed by uint8_t ep_addr[ep_addr_len] */
} __attribute__((packed));

struct ofi_sb_teardown {
	uint32_t	reason_le;			/* 1=normal, 2=qpair_fini, 3=oom */
} __attribute__((packed));

struct ofi_sb_error {
	uint32_t	err_code_le;
	char		err_msg[252];			/* NUL-terminated */
} __attribute__((packed));				/* 256 bytes */

/* --------------------------------------------------------- little-endian
 *
 * The prototype shipped value-style identity helpers (x86/ARM are LE). SPDK's
 * spdk/endian.h provides pointer-style accessors (to_le16(out,in)/from_le16(ptr))
 * with a different calling convention. To keep the lifted validators/inits
 * byte-for-byte identical to the proven prototype code, we keep the value-style
 * identity helpers here. On a hypothetical big-endian build these would need to
 * byte-swap; the wire is LE by spec and the only deployment targets (x86_64,
 * aarch64) are little-endian, so identity is correct in practice. A big-endian
 * port replaces just these six inlines.
 */
static inline uint16_t ofi_cpu_to_le16(uint16_t v) { return v; }
static inline uint32_t ofi_cpu_to_le32(uint32_t v) { return v; }
static inline uint64_t ofi_cpu_to_le64(uint64_t v) { return v; }
static inline uint16_t ofi_le16_to_cpu(uint16_t v) { return v; }
static inline uint32_t ofi_le32_to_cpu(uint32_t v) { return v; }
static inline uint64_t ofi_le64_to_cpu(uint64_t v) { return v; }

/* --------------------------------------------------------------- API */

/*
 * Validate a freshly-read header. Returns 0 on accept; -1 on any reject (bad
 * magic / version / payload_len vs MAX_PAYLOAD(msg_type) / reserved non-zero).
 * On -1 the receiver MUST close the sideband without reading any payload
 * (design §5.4 rows 6,7).
 *
 * On success, *out_payload_len gives the byte count the caller must still read;
 * *out_msg_type and *out_status are also returned.
 */
int ofi_sb_hdr_validate(const struct ofi_sb_hdr *h,
			uint16_t *out_msg_type,
			uint32_t *out_payload_len,
			uint32_t *out_status);

/* Initialise a header in-place. payload_len excludes the header itself. */
void ofi_sb_hdr_init(struct ofi_sb_hdr *h, uint16_t msg_type,
		     uint32_t payload_len, uint32_t status);

/* Initialise a HELLO payload to safe defaults then fill the given fields. */
void ofi_sb_hello_init(struct ofi_sb_hello *p,
		       const char *hostnqn, const char *subnqn,
		       uint16_t qid, uint16_t qdepth,
		       uint32_t max_io_size, uint32_t io_unit_size,
		       uint32_t in_capsule_data_size,
		       const char *host_provider);

/*
 * Receiver-side HELLO validation (design §5.2.2 v1.1):
 *   - hostnqn / subnqn / host_provider NUL-terminated
 *   - max_io_size, io_unit_size, in_capsule_data_size all non-zero
 * Returns 0 on accept; -1 with *errstr filled otherwise.
 */
int ofi_sb_hello_validate(const struct ofi_sb_hello *p, const char **errstr);

/*
 * Classify a negative recv return as "the peer's TCP connection dropped"
 * (design §5.4). Protocol violations (-EPROTO / -EMSGSIZE) are NOT peer-gone:
 * different §5.4 row, but the caller still closes the sideband.
 */
bool ofi_sb_is_peer_gone(int recv_rc);

#endif /* SPDK_NVMF_OFI_INTERNAL_H */
