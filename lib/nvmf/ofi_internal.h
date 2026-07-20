/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 Andong Hu. All rights reserved.
 *
 *   NVMe-oF OFI transport — internal header.
 *
 *   The carrier-agnostic sideband wire format is shared with the host through
 *   spdk_internal/ofi_wire.h. This header adds the target-side validation API.
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
#include "spdk_internal/ofi_wire.h"

/* ------------------------------------------------------------- wire magic */

/*
 * Magic is the 4 bytes {'O','F','I','S'} compared byte-wise. Stored as a char
 * array (not a uint32) on purpose: a uint32 constant reinterprets differently
 * on big-endian, so a memcmp against 4 fixed bytes is the only portable form
 * (design v1.1 note).
 */
extern const char ofi_sb_magic[OFI_SB_MAGIC_LEN];

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
