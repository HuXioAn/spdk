/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 Andong Hu. All rights reserved.
 *
 *   Frozen sideband wire definitions shared by the NVMe/OFI host and
 *   NVMe-oF/OFI target. Multi-byte fields are little-endian, structures are
 *   packed, and deployed field order and sizes must not change.
 */

#ifndef SPDK_INTERNAL_OFI_WIRE_H
#define SPDK_INTERNAL_OFI_WIRE_H

#include "spdk/assert.h"
#include "spdk/stdinc.h"

#define OFI_SB_MAGIC_BYTES	{'O', 'F', 'I', 'S'}
#define OFI_SB_MAGIC_LEN	4
#define OFI_SB_VERSION		1

enum ofi_sb_msg_type {
	OFI_SB_HELLO		= 1,
	OFI_SB_HELLO_ACK	= 2,
	OFI_SB_ADDR_EXCHANGE	= 3,
	OFI_SB_ADDR_ACK		= 4,
	OFI_SB_TEARDOWN		= 5,
	OFI_SB_ERROR		= 6,
	OFI_SB_HEARTBEAT	= 7,
};

enum ofi_sb_status {
	OFI_SB_STAT_OK		= 0,
	OFI_SB_STAT_ENOENT	= 2,	/* requested NQN was not found */
	OFI_SB_STAT_E2BIG	= 7,	/* payload exceeds the per-message cap */
	OFI_SB_STAT_ENOMEM	= 12,	/* target resource exhaustion */
	OFI_SB_STAT_EACCES	= 13,	/* host NQN is not allowed */
	OFI_SB_STAT_EINVAL	= 22,	/* malformed or unsupported request */
	OFI_SB_STAT_ETRANSIENT	= 200,	/* caller may retry */
};

#define OFI_SB_MAX_HELLO_PAYLOAD		496
#define OFI_SB_MAX_ADDR_EXCHANGE_PAYLOAD	1100
#define OFI_SB_MAX_TEARDOWN_PAYLOAD		4
#define OFI_SB_MAX_ERROR_PAYLOAD		256
#define OFI_SB_MAX_HEARTBEAT_PAYLOAD		0
#define OFI_SB_MAX_TOTAL_PAYLOAD		(16384 - 20)

struct ofi_sb_hdr {
	uint8_t		magic[OFI_SB_MAGIC_LEN];	/* byte string "OFIS" */
	uint16_t	version_le;			/* OFI_SB_VERSION */
	uint16_t	msg_type_le;			/* enum ofi_sb_msg_type */
	uint32_t	payload_len_le;			/* bytes following this header */
	uint32_t	status_le;			/* enum ofi_sb_status */
	uint32_t	reserved_le;			/* receiver requires zero */
} __attribute__((packed));

struct ofi_sb_hello {
	char		hostnqn[224];			/* NUL-terminated */
	char		subnqn[224];			/* NUL-terminated */
	uint16_t	qid_le;				/* zero is the admin queue */
	uint16_t	qdepth_le;
	uint32_t	max_io_size_le;
	uint32_t	io_unit_size_le;
	uint32_t	in_capsule_data_size_le;
	char		host_provider[32];		/* NUL-terminated */
} __attribute__((packed));

#define OFI_SB_ADDR_FLAG_RMA_CAPABLE	(1u << 0)
struct ofi_sb_addr {
	char		provider[32];			/* NUL-terminated */
	uint32_t	ep_addr_len_le;
	uint32_t	mtu_le;
	uint32_t	flags_le;			/* OFI_SB_ADDR_FLAG_* */
	uint32_t	data_buf_count_le;		/* reserved; preserve wire layout */
	uint64_t	data_buf_addr_le;		/* reserved; preserve wire layout */
	uint64_t	data_buf_key_le;		/* reserved; preserve wire layout */
} __attribute__((packed));

struct ofi_sb_teardown {
	uint32_t	reason_le;
} __attribute__((packed));

struct ofi_sb_error {
	uint32_t	err_code_le;
	char		err_msg[252];
} __attribute__((packed));

SPDK_STATIC_ASSERT(sizeof(struct ofi_sb_hdr) == 20, "OFI sideband header size");
SPDK_STATIC_ASSERT(sizeof(struct ofi_sb_hello) == OFI_SB_MAX_HELLO_PAYLOAD,
		   "OFI sideband HELLO size");
SPDK_STATIC_ASSERT(sizeof(struct ofi_sb_addr) == 64, "OFI sideband address size");
SPDK_STATIC_ASSERT(sizeof(struct ofi_sb_teardown) == OFI_SB_MAX_TEARDOWN_PAYLOAD,
		   "OFI sideband teardown size");
SPDK_STATIC_ASSERT(sizeof(struct ofi_sb_error) == OFI_SB_MAX_ERROR_PAYLOAD,
		   "OFI sideband error size");

/* The deployed x86_64 and aarch64 systems are little-endian. A big-endian port
 * must replace these value-style helpers with byte-swapping implementations. */
static inline uint16_t ofi_cpu_to_le16(uint16_t v) { return v; }
static inline uint32_t ofi_cpu_to_le32(uint32_t v) { return v; }
static inline uint64_t ofi_cpu_to_le64(uint64_t v) { return v; }
static inline uint16_t ofi_le16_to_cpu(uint16_t v) { return v; }
static inline uint32_t ofi_le32_to_cpu(uint32_t v) { return v; }
static inline uint64_t ofi_le64_to_cpu(uint64_t v) { return v; }

#endif /* SPDK_INTERNAL_OFI_WIRE_H */
