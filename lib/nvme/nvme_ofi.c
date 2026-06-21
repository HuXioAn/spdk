/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 Andong Hu. All rights reserved.
 *
 *   NVMe-oF OFI (libfabric) HOST (initiator) transport — P1c-2.
 *
 *   Mirrors the SPDK nvme_tcp/nvme_rdma host-transport shape: registers a
 *   spdk_nvme_transport_ops named "OFI", constructs controllers/qpairs, and
 *   connects each qpair by running the §5.3 sideband handshake (host/active
 *   role) + bringing up a libfabric EP, then hands the qpair to the SPDK core
 *   which drives the Fabrics CONNECT (and all subsequent NVMe IO) through
 *   qpair_submit_request / qpair_process_completions.
 *
 *   Data path (design §6, V1 = pure FI_MSG): each NVMe command is a single
 *   libfabric MSG carrying a 64-byte SQE [+ HOST_TO_CONTROLLER in-capsule data
 *   appended]; each completion is a single MSG carrying a 16-byte CQE [+
 *   CONTROLLER_TO_HOST data appended]. The NVMe CID rides the CQ immediate-data
 *   field as a 64-bit tag (cid<<8 | type) via FI_REMOTE_CQ_DATA — no FI_TAGGED.
 *   V1 is single-segment, single-message per IO (CXI iov_limit=1): an IO whose
 *   data exceeds in_capsule_data_size is rejected (use V2 RMA — future).
 *
 *   The sideband wire format is the frozen design §5.2 layout, duplicated here
 *   (lib/nvme and lib/nvmf are separate libraries; SPDK_STATIC_ASSERT guards
 *   against drift vs the target's copy in lib/nvmf/ofi_internal.h). The blocking
 *   framing helpers are NOT lifted — the host handshake is a non-blocking state
 *   machine driven from ctrlr_connect_qpair (called repeatedly by the core until
 *   it returns 0), mirroring the reactor-driven target.
 *
 *   Design: docs/design/ofi_transport_design.md (host callbacks §4.3, lifecycle
 *   §3.4/§9, sideband §5.2/§5.3, data path §6). fi_getinfo hints are runtime-
 *   adaptive per provider (§3.4.1) — NOT hardcoded to CXI.
 */

#include "spdk/stdinc.h"
#include "spdk/sock.h"
#include "spdk/string.h"
#include "spdk/util.h"
#include "spdk/log.h"
#include "spdk/dma.h"
#include "spdk/trace.h"
#include "spdk_internal/trace_defs.h"

#include "nvme_internal.h"

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>		/* fi_getname */
#include <rdma/fi_rma.h>		/* keyed SGL → target-initiated RMA (V2) */
#include <rdma/fi_errno.h>

/* -------------------------------------------------------------------------- */
/* Defaults + libfabric version                                               */
/* -------------------------------------------------------------------------- */

#define NVME_OFI_DEFAULT_PROVIDER	"tcp"
#define NVME_OFI_PROVIDER_ENV		"OFI_PROVIDER"
/* OFI_RMA=0 forces the V1 in-capsule data path; unset/non-zero = V2 target RMA. */
#define NVME_OFI_RMA_ENV		"OFI_RMA"
#define NVME_OFI_FI_VERSION		FI_VERSION(1, 22)

/* Spin cap for fi_injectdata/fi_sendmsg on -FI_EAGAIN, draining our own CQ
 * between attempts. This CANNOT be small: the first send to a freshly-enabled EP
 * (the Fabrics CONNECT) returns -FI_EAGAIN while ofi_rxm establishes the RC
 * connection, and the core's async-connect submits exactly once — returning
 * -EAGAIN there (or in the core's resubmit path) puts the controller in an error
 * state. So the spin must run until success; 100000 is a safety cap that is
 * rarely approached (the CQ drain frees send slots, so it self-resolves in a
 * few iterations). Tried bounding to 128 — connect failed deterministically. */
#define NVME_OFI_SEND_SPIN_MAX	100000

/* V1 in-capsule data ceiling. An IO whose data exceeds this is rejected (V2
 * RMA handles large IO). Sized to hold a Fabrics CONNECT data struct and an
 * Identify response, the largest admin payloads. */
#define NVME_OFI_IN_CAPSULE_DATA_SIZE	4096

/* V2 RMA single-transfer ceiling — MUST match the target's per-req bounce buffer
 * (NVMF_OFI_RMA_DATA_SIZE in lib/nvmf/ofi.c). */
#define NVME_OFI_RMA_DATA_SIZE		131072
/* Max SGL segments the V2 path accepts per command. Multi-segment payloads are gathered
 * into one bounce buffer (one keyed SGL), so this is independent of the provider's
 * iov_limit — set high enough to avoid the core splitting typical IOs. */
#define NVME_OFI_MAX_SGES		32

/* CQ entries reaped per fi_cq_read call. Batching amortizes the per-completion
 * libfabric call overhead (vs reading one at a time). */
#define NVME_OFI_CQ_BATCH		16

/* Per-qpair recv/send slot counts == submission-queue depth. The host pre-posts
 * `qdepth` recv buffers (one per possible outstanding CID) and has `qdepth`
 * send slots. */
#define NVME_OFI_SEND_BUF_SIZE		(sizeof(struct spdk_nvme_cmd) + NVME_OFI_IN_CAPSULE_DATA_SIZE)
#define NVME_OFI_RECV_BUF_SIZE		(sizeof(struct spdk_nvme_cpl) + NVME_OFI_IN_CAPSULE_DATA_SIZE)

/* Sideband framing scratch: largest handshake frame is hdr + ADDR_EXCHANGE. */
#define NVME_OFI_SB_BUF_SIZE		(sizeof(struct nvme_ofi_sb_hdr) + NVME_OFI_SB_MAX_ADDR_PAYLOAD)

/* -------------------------------------------------------------------------- */
/* Sideband wire format (frozen design §5.2 — MUST match lib/nvmf/ofi_internal.h) */
/* -------------------------------------------------------------------------- */

#define NVME_OFI_SB_MAGIC	{'O', 'F', 'I', 'S'}
#define NVME_OFI_SB_MAGIC_LEN	4
#define NVME_OFI_SB_VERSION	1

enum nvme_ofi_sb_msg {
	NVME_OFI_SB_HELLO	= 1,
	NVME_OFI_SB_HELLO_ACK	= 2,
	NVME_OFI_SB_ADDR_EXCH	= 3,
	NVME_OFI_SB_ADDR_ACK	= 4,
	NVME_OFI_SB_ERROR	= 6,
};

enum nvme_ofi_sb_status {
	NVME_OFI_SB_STAT_OK	= 0,
	NVME_OFI_SB_STAT_EINVAL	= 22,
};

struct nvme_ofi_sb_hdr {
	uint8_t		magic[NVME_OFI_SB_MAGIC_LEN];
	uint16_t	version_le;
	uint16_t	msg_type_le;
	uint32_t	payload_len_le;
	uint32_t	status_le;
	uint32_t	reserved_le;
} __attribute__((packed));
#define NVME_OFI_SB_HDR_SIZE	(sizeof(struct nvme_ofi_sb_hdr))

#define NVME_OFI_SB_MAX_HELLO_PAYLOAD	496
#define NVME_OFI_SB_MAX_ADDR_PAYLOAD	1100

struct nvme_ofi_sb_hello {
	char		hostnqn[224];
	char		subnqn[224];
	uint16_t	qid_le;
	uint16_t	qdepth_le;
	uint32_t	max_io_size_le;
	uint32_t	io_unit_size_le;
	uint32_t	in_capsule_data_size_le;
	char		host_provider[32];
} __attribute__((packed));

#define NVME_OFI_SB_ADDR_FLAG_RMA	(1u << 0)
struct nvme_ofi_sb_addr {
	char		provider[32];
	uint32_t	ep_addr_len_le;
	uint32_t	mtu_le;
	uint32_t	flags_le;
	uint32_t	data_buf_count_le;
	uint64_t	data_buf_addr_le;
	uint64_t	data_buf_key_le;
	/* followed by uint8_t ep_addr[ep_addr_len] */
} __attribute__((packed));

SPDK_STATIC_ASSERT(sizeof(struct nvme_ofi_sb_hdr) == 20, "sb hdr size");
SPDK_STATIC_ASSERT(sizeof(struct nvme_ofi_sb_hello) == NVME_OFI_SB_MAX_HELLO_PAYLOAD, "sb hello size");
SPDK_STATIC_ASSERT(sizeof(struct nvme_ofi_sb_addr) == 64, "sb addr size");

/* The two deployment targets (x86_64, aarch64) are little-endian, so identity
 * LE helpers are correct (matches lib/nvmf/ofi_internal.h). */
static inline uint16_t nvme_ofi_cpu_to_le16(uint16_t v) { return v; }
static inline uint32_t nvme_ofi_cpu_to_le32(uint32_t v) { return v; }
static inline uint16_t nvme_ofi_le16_to_cpu(uint16_t v) { return v; }
static inline uint32_t nvme_ofi_le32_to_cpu(uint32_t v) { return v; }

/* -------------------------------------------------------------------------- */
/* V1 data-path framing (design §6.1)                                         */
/* -------------------------------------------------------------------------- */

enum nvme_ofi_msg_type {
	NVME_OFI_MSG_SQE	= 1,	/* host->target: 64B SQE [+ WRITE data] */
	NVME_OFI_MSG_CQE	= 4,	/* target->host: 16B CQE [+ READ data]  */
};

#define NVME_OFI_TAG(cid, type)	(((uint64_t)(cid) << 8) | (uint64_t)(type))
#define NVME_OFI_TAG_CID(tag)	((uint16_t)(((tag) >> 8) & 0xffff))
#define NVME_OFI_TAG_TYPE(tag)	((uint8_t)((tag) & 0xff))

/* -------------------------------------------------------------------------- */
/* Data structures                                                            */
/* -------------------------------------------------------------------------- */

const struct spdk_nvme_transport_ops nvme_ofi_ops;

/* Host-side sideband handshake state (design §5.3, active role). */
enum nvme_ofi_sb_state {
	NVME_OFI_SB_INIT = 0,		/* connect the sideband socket */
	NVME_OFI_SB_HELLO_SEND,		/* send HELLO */
	NVME_OFI_SB_HELLO_ACK_RECV,	/* recv HELLO_ACK */
	NVME_OFI_SB_EP_CREATE,		/* bring up the libfabric EP, fi_getname */
	NVME_OFI_SB_ADDR_SEND,		/* send ADDR_EXCHANGE (our addr) */
	NVME_OFI_SB_ADDR_RECV,		/* recv ADDR_EXCHANGE (peer addr), fi_av_insert */
	NVME_OFI_SB_ADDR_ACK_XCHG,	/* send+recv ADDR_ACK (dual-ACK) */
	NVME_OFI_SB_READY,		/* transport connected; core does Fabrics CONNECT */
	NVME_OFI_SB_FABRIC_CONNECT_POLL,	/* polling nvme_fabric_qpair_connect_poll */
	NVME_OFI_SB_FAILED,
};

/* A pre-posted recv slot. op_context passed to fi_recv points here so a CQ
 * entry maps back to the buffer (and the qpair via tqpair). */
struct nvme_ofi_recv_slot {
	struct nvme_ofi_qpair	*tqpair;
	void			*buf;		/* NVME_OFI_RECV_BUF_SIZE */
	void			*desc;		/* MR desc (FI_MR_LOCAL) or NULL */
	struct fid_mr		*mr;		/* MR handle when mr_local */
	bool			posted;
	TAILQ_ENTRY(nvme_ofi_recv_slot) link;	/* on tqpair->pending_recvs when re-post deferred */
};

/* A send slot. Holds the SQE [+ in-capsule data] being transmitted; the CID
 * of the in-flight request is recorded so the tx completion can recycle it. */
struct nvme_ofi_send_slot {
	struct nvme_ofi_qpair	*tqpair;
	void			*buf;		/* NVME_OFI_SEND_BUF_SIZE */
	void			*desc;
	struct fid_mr		*mr;
	uint16_t		cid;		/* CID of the request in this slot (tx in flight) */
	TAILQ_ENTRY(nvme_ofi_send_slot) link;	/* on tqpair->send_free when idle (H1 O(1) alloc) */
};

/*
 * Per-qpair remote-data MR cache (V2 RMA). For each IO the host registers the
 * data buffer ONCE and advertises {addr,key} in the keyed SGL; the target RMAs
 * directly into/out of it (zero-copy on the host). Steady-state must NOT
 * re-register per IO (p0b_findings MR-cache), so cache by buffer vaddr. The
 * spdk_nvme_perf buffer pool is small + reused, so a flat linear cache suffices.
 */
#ifndef NVME_OFI_MR_CACHE_INIT
#define NVME_OFI_MR_CACHE_INIT	256	/* test override: -DNVME_OFI_MR_CACHE_INIT=8 forces eviction */
#endif
struct nvme_ofi_mr_cache_entry {
	void		*buf;
	size_t		len;
	struct fid_mr	*mr;
	uint64_t	addr;	/* advertised remote addr: vaddr (FI_MR_VIRT_ADDR) or 0 */
	uint64_t	key;	/* fi_mr_key */
	uint16_t	refcnt;	/* outstanding V2 RMAs referencing this MR; eviction skips until 0 */
	uint32_t	next_free;	/* free-list link (valid only when mr==NULL); UINT32_MAX = tail */
};

/* Gap B: bounce buffer for a multi-segment SGL payload, gathered into one contiguous
 * DMA buffer so a single keyed SGL (one MR) can be advertised. Individually malloc'd so
 * outstanding requests can hold a stable pointer (the pool never realloc's). */
struct nvme_ofi_bounce {
	void			*buf;	/* NVME_OFI_RMA_DATA_SIZE bytes, DMA-able */
	struct nvme_ofi_bounce	*next;	/* free-list link */
};

/* Per-outstanding-CID transport-private state (parallel to req_table, indexed by cid). */
struct nvme_ofi_outstanding {
	uint32_t		mr_idx;		/* MR cache slot of this req's data MR; UINT32_MAX = none */
	struct nvme_ofi_bounce	*bounce;	/* multi-seg bounce buf; NULL if contiguous */
	bool			need_scatter;	/* CONTROLLER_TO_HOST into bounce → scatter on completion */
};

struct nvme_ofi_qpair {
	struct spdk_nvme_qpair		qpair;		/* must be first */

	struct nvme_ofi_ctrlr		*tctrlr;
	struct spdk_nvme_ctrlr		*ctrlr;		/* back-pointer for core helpers */

	/* libfabric endpoint + peer (created in connect_qpair). */
	struct fid_ep			*ep;
	struct fid_cq			*cq;		/* per-qpair tx+rx CQ */
	struct fid_domain		*domain;	/* #45: per-qpair. Each qpair runs on its own core; sharing one ctrlr->domain violated FI_THREAD_DOMAIN and serialized ofi_rxm MANUAL progress across cores. */
	struct fid_av			*av;		/* per-qpair AV on that domain */
	fi_addr_t			peer_fi_addr;
	bool				ep_enabled;
	bool				mr_local;

	/* Sideband socket + handshake state machine. */
	struct spdk_sock			*sb_sock;
	enum nvme_ofi_sb_state		sb_state;
	bool				in_connect_poll;	/* re-entry guard (nvme_fabric_qpair_connect_poll re-enters process_completions) */
	uint8_t				sb_rx[NVME_OFI_SB_BUF_SIZE];
	size_t				sb_rx_off;
	uint8_t				sb_tx[NVME_OFI_SB_BUF_SIZE];
	size_t				sb_tx_off;	/* bytes not yet written */
	size_t				sb_tx_len;	/* total bytes queued in sb_tx */

	/* local EP address (fi_getname), exchanged in ADDR_EXCHANGE. */
	uint8_t				local_ep_addr[256];
	size_t				local_ep_addr_len;
	/* peer EP address (from ADDR_EXCHANGE), fi_av_insert'd. */
	uint8_t				peer_ep_addr[256];
	size_t				peer_ep_addr_len;

	/* V1 data-path pools. */
	struct nvme_ofi_recv_slot	*recv_slots;
	struct nvme_ofi_send_slot	*send_slots;
	uint32_t			num_slots;	/* == sq depth */
	TAILQ_HEAD(, nvme_ofi_recv_slot) pending_recvs; /* recv re-posts deferred on -FI_EAGAIN */
	/* H1: idle send slots, O(1) pop/push (was an O(num_slots) linear scan per submit).
	 * Only the fi_sendmsg path takes a slot; the inject path holds none. */
	TAILQ_HEAD(, nvme_ofi_send_slot) send_free;

	/* outstanding requests indexed by CID (matches the SQ). The core owns the
	 * nvme_request objects; we keep a pointer here to complete on CQE. */
	struct nvme_request		**req_table;
	uint32_t			req_table_sz;
	/* H2: free-cid stack, O(1) pop/push (was an O(req_table_sz) scan per submit).
	 * A cid is in use while req_table[cid] != NULL; pushed back at the single
	 * NULL-ing point (nvme_ofi_complete_request) and on submit rollback. */
	uint16_t			*cid_free;
	uint32_t			cid_free_n;

	/* V2 RMA: when set, non-CONNECT data commands advertise a keyed SGL and the
	 * target moves the data over RMA instead of in-capsule. */
	bool				use_rma;
	/* V2 remote-data MR cache: a growable, indexed pool (no compaction on eviction, so
	 * slot indices stay stable across realloc and can be held by outstanding requests).
	 * #3: an entry is reclaimed only when refcnt==0 — an MR whose {addr,key} is still in
	 * flight on the target is never fi_close'd. */
	struct nvme_ofi_mr_cache_entry	*mr_cache;
	uint32_t			mr_cache_cap;
	uint32_t			mr_free_head;	/* first free slot, or UINT32_MAX */
	uint64_t			mr_reg;		/* stat: registrations (cache miss) */
	uint64_t			mr_hit;		/* stat: cache hits */
	uint64_t			mr_evict;	/* stat: cold entries reclaimed */
	uint64_t			mr_grow;	/* stat: pool grew (all entries in-flight) */

	/* Gap B: multi-segment bounce-buffer free-list (lazy, bounded by QD in-flight). */
	struct nvme_ofi_bounce		*bounce_free;

	/* Per-CID outstanding state (parallel to req_table). */
	struct nvme_ofi_outstanding	*outstanding;
};

struct nvme_ofi_ctrlr {
	struct spdk_nvme_ctrlr		ctrlr;		/* must be first */

	struct fi_info			*info;
	struct fid_fabric		*fabric;

	char				provider[32];
	bool				use_rma;	/* OFI_RMA env: V2 data path (default on) */
	/* RMA MR keys are per-DOMAIN (shared by every qpair on this ctrlr), so the
	 * requested-key counter for non-PROV_KEY providers must live here, not on the
	 * qpair — else two qpairs both start at 1 and collide (-FI_EKEYREJECTED). */
	uint64_t			mr_next_key;
};

static inline struct nvme_ofi_qpair *
nvme_ofi_qpair(struct spdk_nvme_qpair *qpair)
{
	assert(qpair->trtype == SPDK_NVME_TRANSPORT_CUSTOM_FABRICS);
	return SPDK_CONTAINEROF(qpair, struct nvme_ofi_qpair, qpair);
}

static inline struct nvme_ofi_ctrlr *
nvme_ofi_ctrlr(struct spdk_nvme_ctrlr *ctrlr)
{
	assert(ctrlr->trid.trtype == SPDK_NVME_TRANSPORT_CUSTOM_FABRICS);
	return SPDK_CONTAINEROF(ctrlr, struct nvme_ofi_ctrlr, ctrlr);
}

/* Forward declarations (ctrlr_construct calls create_io_qpair/destruct). */
static struct spdk_nvme_qpair *nvme_ofi_ctrlr_create_io_qpair(struct spdk_nvme_ctrlr *ctrlr,
		uint16_t qid, const struct spdk_nvme_io_qpair_opts *opts);
static int nvme_ofi_ctrlr_destruct(struct spdk_nvme_ctrlr *ctrlr);
static void nvme_ofi_qpair_free_res(struct nvme_ofi_qpair *tqpair);
static int32_t nvme_ofi_qpair_process_completions(struct spdk_nvme_qpair *qpair,
		uint32_t max_completions);
static int nvme_ofi_post_recv(struct nvme_ofi_qpair *tqpair,
			      struct nvme_ofi_recv_slot *slot);

/* -------------------------------------------------------------------------- */
/* Runtime-adaptive fi_getinfo (mirrors lib/nvmf/ofi.c §3.4.1)                */
/* -------------------------------------------------------------------------- */

static int
nvme_ofi_getinfo(const char *prov, struct fi_info **out_info)
{
	struct fi_info *hints, *info, *i;
	int rc;

	hints = fi_allocinfo();
	if (hints == NULL) {
		return -ENOMEM;
	}

	hints->mode = 0;
	hints->ep_attr->type = FI_EP_RDM;
	hints->domain_attr->threading = FI_THREAD_DOMAIN;
	hints->domain_attr->control_progress = FI_PROGRESS_MANUAL;
	hints->domain_attr->data_progress = FI_PROGRESS_MANUAL;
	hints->tx_attr->msg_order = FI_ORDER_SAS;
	hints->rx_attr->msg_order = FI_ORDER_SAS;
	hints->tx_attr->op_flags = FI_COMPLETION;
	hints->rx_attr->op_flags = FI_COMPLETION;

	if (strcmp(prov, "cxi") == 0) {
		hints->caps = FI_MSG | FI_RMA | FI_REMOTE_CQ_DATA | FI_READ | FI_WRITE;
		hints->addr_format = FI_ADDR_CXI;
		hints->domain_attr->mr_mode = FI_MR_PROV_KEY | FI_MR_ALLOCATED | FI_MR_ENDPOINT;
	} else {
		/* sockets/tcp/verbs;ofi_rxm: FI_READ|FI_WRITE keeps ofi_rxm in the
		 * filter; FI_REMOTE_CQ_DATA is deliberately NOT in caps (rejected by
		 * dev providers at the hint filter) — it's requested at send time. */
		hints->caps = FI_MSG | FI_RMA | FI_READ | FI_WRITE;
		hints->addr_format = FI_SOCKADDR_IN;
		hints->domain_attr->mr_mode =
			FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY;
	}

	info = NULL;
	rc = fi_getinfo(NVME_OFI_FI_VERSION, NULL, NULL, 0, hints, &info);
	fi_freeinfo(hints);
	if (rc != 0) {
		SPDK_ERRLOG("ofi host: fi_getinfo failed for '%s': %s\n", prov, fi_strerror(-rc));
		return rc;
	}

	for (i = info; i != NULL; i = i->next) {
		if (i->fabric_attr->prov_name != NULL &&
		    strcmp(i->fabric_attr->prov_name, prov) == 0) {
			*out_info = fi_dupinfo(i);
			fi_freeinfo(info);
			return *out_info == NULL ? -ENOMEM : 0;
		}
	}

	fi_freeinfo(info);
	SPDK_ERRLOG("ofi host: provider '%s' not offered\n", prov);
	return -ENOENT;
}

/* -------------------------------------------------------------------------- */
/* Sideband framing helpers (non-blocking)                                    */
/* -------------------------------------------------------------------------- */

static void
nvme_ofi_sb_hdr_init(struct nvme_ofi_sb_hdr *h, uint16_t msg_type,
		     uint32_t payload_len, uint32_t status)
{
	static const char magic[NVME_OFI_SB_MAGIC_LEN] = NVME_OFI_SB_MAGIC;
	memset(h, 0, sizeof(*h));
	memcpy(h->magic, magic, NVME_OFI_SB_MAGIC_LEN);
	h->version_le = nvme_ofi_cpu_to_le16(NVME_OFI_SB_VERSION);
	h->msg_type_le = nvme_ofi_cpu_to_le16(msg_type);
	h->payload_len_le = nvme_ofi_cpu_to_le32(payload_len);
	h->status_le = nvme_ofi_cpu_to_le32(status);
}

/* Validate a fully-buffered header. Returns 0 ok, -1 reject. */
static int
nvme_ofi_sb_hdr_validate(const struct nvme_ofi_sb_hdr *h, uint16_t *msg_type,
			 uint32_t *payload_len, uint32_t *status)
{
	static const char magic[NVME_OFI_SB_MAGIC_LEN] = NVME_OFI_SB_MAGIC;
	uint32_t plen;
	uint16_t mt;

	if (memcmp(h->magic, magic, NVME_OFI_SB_MAGIC_LEN) != 0) {
		return -1;
	}
	if (nvme_ofi_le16_to_cpu(h->version_le) != NVME_OFI_SB_VERSION) {
		return -1;
	}
	if (h->reserved_le != 0) {
		return -1;
	}
	plen = nvme_ofi_le32_to_cpu(h->payload_len_le);
	mt = nvme_ofi_le16_to_cpu(h->msg_type_le);

	switch (mt) {
	case NVME_OFI_SB_HELLO:
		if (plen > NVME_OFI_SB_MAX_HELLO_PAYLOAD) { return -1; }
		break;
	case NVME_OFI_SB_ADDR_EXCH:
		if (plen > NVME_OFI_SB_MAX_ADDR_PAYLOAD) { return -1; }
		break;
	case NVME_OFI_SB_HELLO_ACK:
	case NVME_OFI_SB_ADDR_ACK:
		if (plen != 0) { return -1; }
		break;
	default:
		return -1;
	}
	if (msg_type) { *msg_type = mt; }
	if (payload_len) { *payload_len = plen; }
	if (status) { *status = nvme_ofi_le32_to_cpu(h->status_le); }
	return 0;
}

/* Queue a frame (hdr + optional payload) into sb_tx for later non-blocking write. */
static void
nvme_ofi_sb_queue(struct nvme_ofi_qpair *tqpair, uint16_t msg_type,
		  const void *payload, uint32_t payload_len, uint32_t status)
{
	struct nvme_ofi_sb_hdr *h = (struct nvme_ofi_sb_hdr *)tqpair->sb_tx;

	assert(payload_len + sizeof(*h) <= sizeof(tqpair->sb_tx));
	nvme_ofi_sb_hdr_init(h, msg_type, payload_len, status);
	if (payload_len > 0) {
		memcpy(tqpair->sb_tx + sizeof(*h), payload, payload_len);
	}
	tqpair->sb_tx_off = 0;
	tqpair->sb_tx_len = sizeof(*h) + payload_len;
}

/* Drain the queued sb_tx bytes. Returns 0 once fully flushed, -EAGAIN if the
 * socket is not yet writable (partial write), other negative on error. */
static int
nvme_ofi_sb_flush(struct nvme_ofi_qpair *tqpair)
{
	while (tqpair->sb_tx_off < tqpair->sb_tx_len) {
		struct iovec iov = {
			.iov_base = tqpair->sb_tx + tqpair->sb_tx_off,
			.iov_len = tqpair->sb_tx_len - tqpair->sb_tx_off,
		};
		ssize_t n = spdk_sock_writev(tqpair->sb_sock, &iov, 1);

		if (n == 0 || (n < 0 && n == -EAGAIN)) {
			return -EAGAIN;
		}
		if (n < 0) {
			SPDK_ERRLOG("ofi host: sb write: %s\n", spdk_strerror(-n));
			return (int)n;
		}
		tqpair->sb_tx_off += n;
	}
	tqpair->sb_tx_len = 0;
	return 0;
}

/* Pull readable bytes into sb_rx. Returns 0 if a full frame of the expected
 * payload_len is buffered, -EAGAIN if not enough yet, other negative on error. */
static int
nvme_ofi_sb_recv(struct nvme_ofi_qpair *tqpair, uint32_t want_payload)
{
	size_t want = NVME_OFI_SB_HDR_SIZE + want_payload;
	ssize_t n;

	while (tqpair->sb_rx_off < want) {
		n = spdk_sock_recv(tqpair->sb_sock, tqpair->sb_rx + tqpair->sb_rx_off,
				   sizeof(tqpair->sb_rx) - tqpair->sb_rx_off);
		if (n == 0) {
			return -ECONNRESET;
		}
		if (n < 0 && n == -EAGAIN) {
			return -EAGAIN;
		}
		if (n < 0) {
			return n;
		}
		tqpair->sb_rx_off += n;
	}
	return 0;
}

/* Reset sb_rx after consuming one frame. */
static void
nvme_ofi_sb_rx_consume(struct nvme_ofi_qpair *tqpair, size_t frame_len)
{
	assert(tqpair->sb_rx_off >= frame_len);
	memmove(tqpair->sb_rx, tqpair->sb_rx + frame_len, tqpair->sb_rx_off - frame_len);
	tqpair->sb_rx_off -= frame_len;
}

/* -------------------------------------------------------------------------- */
/* EP bring-up + teardown                                                     */
/* -------------------------------------------------------------------------- */

static void
nvme_ofi_ep_teardown(struct nvme_ofi_qpair *tqpair)
{
	if (tqpair->peer_fi_addr != FI_ADDR_NOTAVAIL && tqpair->av != NULL) {
		fi_av_remove(tqpair->av, &tqpair->peer_fi_addr, 1, 0);
		tqpair->peer_fi_addr = FI_ADDR_NOTAVAIL;
	}
	if (tqpair->ep != NULL) {
		fi_close(&tqpair->ep->fid);
		tqpair->ep = NULL;
	}
	tqpair->ep_enabled = false;
}

/* Bring up the per-qpair EP on the ctrlr's domain, P0-1 order (bind CQ before
 * enable; getname after enable). Runs synchronously in connect_qpair (local,
 * fast, on the qpair's thread). Returns 0 / -fi_errno. */
static int
nvme_ofi_ep_create(struct nvme_ofi_qpair *tqpair)
{
	struct nvme_ofi_ctrlr *tctrlr = tqpair->tctrlr;
	size_t addrlen;
	int rc;

	rc = fi_endpoint(tqpair->domain, tctrlr->info, &tqpair->ep, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("ofi host: fi_endpoint: %s\n", fi_strerror(-rc));
		return rc;
	}
	/* Pin the EP's source to the NIC we reached the target on (the sideband
	 * socket's local IP). fi_getinfo(node=NULL) otherwise lets the tcp/sockets
	 * provider pick an arbitrary interface the target cannot route back to.
	 * This is a tcp/sockets-only workaround: verbs;ofi_rxm and cxi resolve the
	 * EP address from the device themselves, and forcing a sockaddr source
	 * breaks ofi_rxm's RC-connection setup (-FI_ECANCELED on the first send). */
	if (tqpair->sb_sock != NULL &&
	    tctrlr->info->addr_format == FI_SOCKADDR_IN &&
	    (strncmp(tctrlr->provider, "tcp", 3) == 0 ||
	     strncmp(tctrlr->provider, "sockets", 7) == 0)) {
		char laddr[64] = {0}, raddr[64] = {0};
		uint16_t lport, rport;
		if (spdk_sock_getaddr(tqpair->sb_sock, laddr, sizeof(laddr), &lport,
				      raddr, sizeof(raddr), &rport) == 0) {
			struct sockaddr_in src = {0};
			src.sin_family = AF_INET;
			src.sin_port = 0;
			if (inet_pton(AF_INET, laddr, &src.sin_addr) == 1) {
				rc = fi_setname(&tqpair->ep->fid, &src, sizeof(src));
				if (rc != 0) {
					SPDK_WARNLOG("ofi host: fi_setname(%s): %s (continuing)\n",
						     laddr, fi_strerror(-rc));
				}
			}
		}
	}
	rc = fi_ep_bind(tqpair->ep, &tqpair->av->fid, 0);
	if (rc != 0) { goto err; }
	/* The host uses a single CQ for tx and rx (a host qpair has its own completion
	 * stream; binding both flags to one CQ is fine for manual poll). A target
	 * fi_write carrying CQ immediate data (#46: the folded READ completion) is an
	 * incoming-data event, so it lands on this same RECV CQ with entry.flags =
	 * FI_REMOTE_WRITE — distinguished from FI_RECV MSGs in the drain loop. (Note:
	 * FI_REMOTE_WRITE is NOT a valid fi_ep_bind flag; it is a CQ-entry op flag.) */
	rc = fi_ep_bind(tqpair->ep, &tqpair->cq->fid, FI_TRANSMIT | FI_RECV);
	if (rc != 0) { goto err; }

	rc = fi_enable(tqpair->ep);
	if (rc != 0) { goto err; }
	tqpair->ep_enabled = true;

	addrlen = sizeof(tqpair->local_ep_addr);
	rc = fi_getname(&tqpair->ep->fid, tqpair->local_ep_addr, &addrlen);
	if (rc != 0) {
		SPDK_ERRLOG("ofi host: fi_getname: %s\n", fi_strerror(-rc));
		goto err;
	}
	tqpair->local_ep_addr_len = addrlen;
	return 0;

err:
	nvme_ofi_ep_teardown(tqpair);
	return rc;
}

/* -------------------------------------------------------------------------- */
/* V1 data-path send / recv                                                   */
/* -------------------------------------------------------------------------- */

/* Pre-post (or re-post) a recv slot. Returns 0 / -fi_errno. */
static int
nvme_ofi_post_recv(struct nvme_ofi_qpair *tqpair, struct nvme_ofi_recv_slot *slot)
{
	ssize_t rc;

	for (;;) {
		rc = fi_recv(tqpair->ep, slot->buf, NVME_OFI_RECV_BUF_SIZE, slot->desc,
			     tqpair->peer_fi_addr, slot);
		if (rc == -FI_EAGAIN) {
			return -EAGAIN;
		}
		if (rc != 0) {
			SPDK_ERRLOG("ofi host: fi_recv: %s\n", fi_strerror(-(int)rc));
			return (int)rc;
		}
		slot->posted = true;
		return 0;
	}
}

/* Drop one outstanding reference on a cached MR (#3). Called when the request that
 * advertised {addr,key} completes — by then the target's RMA is done, so the entry is
 * safe to reclaim. */
static void
nvme_ofi_mr_put(struct nvme_ofi_qpair *tqpair, uint32_t idx)
{
	struct nvme_ofi_mr_cache_entry *e;

	if (idx == UINT32_MAX || idx >= tqpair->mr_cache_cap) {
		return;
	}
	e = &tqpair->mr_cache[idx];
	assert(e->mr != NULL);
	assert(e->refcnt > 0);
	e->refcnt--;
}

/* H2: return a cid to the free stack. Single-threaded with submit/complete (poll
 * thread), so no locking. Bounded by req_table_sz (every live cid has a req_table slot). */
static inline void
nvme_ofi_cid_put(struct nvme_ofi_qpair *tqpair, uint16_t cid)
{
	assert(tqpair->cid_free_n < tqpair->req_table_sz);
	tqpair->cid_free[tqpair->cid_free_n++] = cid;
}

/* Gap B: borrow a max_io_size DMA bounce buffer from the lazy per-qpair pool. */
static struct nvme_ofi_bounce *
nvme_ofi_bounce_get(struct nvme_ofi_qpair *tqpair)
{
	struct nvme_ofi_bounce *b = tqpair->bounce_free;

	if (b != NULL) {
		tqpair->bounce_free = b->next;
		return b;
	}
	b = calloc(1, sizeof(*b));
	if (b == NULL) {
		return NULL;
	}
	b->buf = spdk_zmalloc(NVME_OFI_RMA_DATA_SIZE, 0, NULL, SPDK_ENV_LCORE_ID_ANY,
			      SPDK_MALLOC_DMA);
	if (b->buf == NULL) {
		free(b);
		return NULL;
	}
	return b;
}

static void
nvme_ofi_bounce_put(struct nvme_ofi_qpair *tqpair, struct nvme_ofi_bounce *b)
{
	b->next = tqpair->bounce_free;
	tqpair->bounce_free = b;
}

/* Gather an SGL payload into one contiguous buffer (NVMe WRITE direction). Mirrors the
 * reset_sgl_fn + next_sge_fn walk nvme_rdma.c does (nvme_rdma.c:1625). */
static int
nvme_ofi_sgl_to_buf(const struct nvme_payload *p, uint32_t payload_offset,
		    uint32_t payload_size, void *out)
{
	void *addr;
	uint32_t len, off = 0;
	int rc;

	p->reset_sgl_fn(p->contig_or_cb_arg, payload_offset);
	while (off < payload_size) {
		rc = p->next_sge_fn(p->contig_or_cb_arg, &addr, &len);
		if (rc != 0) {
			return rc;
		}
		len = spdk_min(len, payload_size - off);
		memcpy((char *)out + off, addr, len);
		off += len;
	}
	return 0;
}

/* Scatter one contiguous buffer into an SGL payload (NVMe READ direction). */
static int
nvme_ofi_buf_to_sgl(const struct nvme_payload *p, uint32_t payload_offset,
		    uint32_t payload_size, const void *in)
{
	void *addr;
	uint32_t len, off = 0;
	int rc;

	p->reset_sgl_fn(p->contig_or_cb_arg, payload_offset);
	while (off < payload_size) {
		rc = p->next_sge_fn(p->contig_or_cb_arg, &addr, &len);
		if (rc != 0) {
			return rc;
		}
		len = spdk_min(len, payload_size - off);
		memcpy(addr, (const char *)in + off, len);
		off += len;
	}
	return 0;
}

static void
nvme_ofi_complete_request(struct nvme_ofi_qpair *tqpair, uint16_t cid,
			  const struct spdk_nvme_cpl *cpl, const void *data, uint32_t data_len)
{
	struct nvme_ofi_outstanding *o;
	struct nvme_request *req;
	struct spdk_nvme_cpl rsp;

	if (cid >= tqpair->req_table_sz || tqpair->req_table[cid] == NULL) {
		SPDK_ERRLOG("ofi host: CQE for unknown cid %u\n", cid);
		return;
	}
	req = tqpair->req_table[cid];
	o = &tqpair->outstanding[cid];
	tqpair->req_table[cid] = NULL;
	nvme_ofi_cid_put(tqpair, cid);	/* H2: cid is now free (response consumed) */

	/* Gap B: a multi-seg READ landed its data in a bounce buffer — scatter it back into
	 * the caller's SGL before completing. (V2 RMA path, data==NULL here.) */
	if (o->bounce != NULL && o->need_scatter && req->payload.reset_sgl_fn != NULL) {
		nvme_ofi_buf_to_sgl(&req->payload, req->payload_offset, req->payload_size,
				    o->bounce->buf);
	}
	/* Return the bounce buffer (if any) to the pool, then drop the data-MR reference
	 * held since submit (#3) — by now the target's RMA is done. */
	if (o->bounce != NULL) {
		nvme_ofi_bounce_put(tqpair, o->bounce);
		o->bounce = NULL;
	}
	nvme_ofi_mr_put(tqpair, o->mr_idx);
	o->mr_idx = UINT32_MAX;

	/* CONTROLLER_TO_HOST data (READ): copy the in-capsule data into the req payload
	 * before completing. (V1 single-segment contig only; multi-seg is V2/bounce above.) */
	if (data != NULL && data_len > 0 &&
	    spdk_nvme_opc_get_data_transfer(req->cmd.opc) == SPDK_NVME_DATA_CONTROLLER_TO_HOST &&
	    req->payload.reset_sgl_fn == NULL) {
		memcpy(req->payload.contig_or_cb_arg, data,
		       spdk_min(data_len, req->payload_size));
	}

	spdk_trace_record(TRACE_NVME_OFI_HOST_COMPLETE, tqpair->qpair.id, 0, (uintptr_t)req,
			  (uintptr_t)req->cb_arg, (uint32_t)cid, (uint32_t)cpl->status.sc);

	rsp = *cpl;
	/* nvme_complete_request invokes the user callback (right signature) + frees req. */
	nvme_complete_request(req->cb_fn, req->cb_arg, req->qpair, req, &rsp);
}

/* -------------------------------------------------------------------------- */
/* ctrlr_construct / destruct / enable                                        */
/* -------------------------------------------------------------------------- */

static struct spdk_nvme_ctrlr *
nvme_ofi_ctrlr_construct(const struct spdk_nvme_transport_id *trid,
			 const struct spdk_nvme_ctrlr_opts *opts, void *devhandle)
{
	struct nvme_ofi_ctrlr *tctrlr;
	const char *prov;
	int rc;

	tctrlr = calloc(1, sizeof(*tctrlr));
	if (tctrlr == NULL) {
		SPDK_ERRLOG("ofi host: ctrlr alloc failed\n");
		return NULL;
	}
	tctrlr->ctrlr.opts = *opts;
	tctrlr->ctrlr.trid = *trid;

	/* The Fabrics CONNECT carries hostnqn; if the caller left it empty, fill the
	 * default so the target's access check (allow-any still validates non-empty)
	 * passes. Mirrors what the core does for other fabrics transports. */
	if (tctrlr->ctrlr.opts.hostnqn[0] == '\0') {
		nvme_get_default_hostnqn(tctrlr->ctrlr.opts.hostnqn,
					 sizeof(tctrlr->ctrlr.opts.hostnqn));
	}
	prov = getenv(NVME_OFI_PROVIDER_ENV);
	if (prov == NULL || prov[0] == '\0') {
		prov = NVME_OFI_DEFAULT_PROVIDER;
	}
	snprintf(tctrlr->provider, sizeof(tctrlr->provider), "%s", prov);

	/* V2 RMA data path on by default; OFI_RMA=0 selects the V1 in-capsule path
	 * (used for A/B comparison — the target adapts per-command from the SGL type,
	 * so only the host chooses). */
	{
		const char *rma = getenv(NVME_OFI_RMA_ENV);
		tctrlr->use_rma = (rma == NULL || rma[0] == '\0') ? true : (atoi(rma) != 0);
		tctrlr->mr_next_key = 1;	/* domain-wide requested_key allocator (non-PROV_KEY) */
		SPDK_INFOLOG(nvme_ofi, "ofi host: data path = %s\n",
			     tctrlr->use_rma ? "V2 (target RMA)" : "V1 (in-capsule)");
	}

	/* Per-ctrlr libfabric: just the info + fabric. The domain + AV are per-QPAIR
	 * now (created in create_io_qpair): a controller's IO qpairs run on separate
	 * cores, and sharing one ctrlr->domain both violated the FI_THREAD_DOMAIN
	 * contract (provider assumes single-threaded domain access) and serialized
	 * ofi_rxm's MANUAL progress across cores (#45). Each qpair owning its domain
	 * restores independent per-core progress. */
	rc = nvme_ofi_getinfo(tctrlr->provider, &tctrlr->info);
	if (rc != 0) {
		goto err_info;
	}
	rc = fi_fabric(tctrlr->info->fabric_attr, &tctrlr->fabric, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("ofi host: fi_fabric: %s\n", fi_strerror(-rc));
		goto err_fabric;
	}

	rc = nvme_ctrlr_construct(&tctrlr->ctrlr);
	if (rc != 0) {
		goto err_core;
	}

	tctrlr->ctrlr.flags |= SPDK_NVME_CTRLR_ACCEL_SEQUENCE_SUPPORTED;
	tctrlr->ctrlr.adminq = nvme_ofi_ctrlr_create_io_qpair(&tctrlr->ctrlr, 0, NULL);
	if (tctrlr->ctrlr.adminq == NULL) {
		SPDK_ERRLOG("ofi host: admin qpair create failed\n");
		nvme_ofi_ctrlr_destruct(&tctrlr->ctrlr);
		return NULL;
	}

	if (nvme_ctrlr_add_process(&tctrlr->ctrlr, 0) != 0) {
		SPDK_ERRLOG("ofi host: nvme_ctrlr_add_process failed\n");
		nvme_ofi_ctrlr_destruct(&tctrlr->ctrlr);
		return NULL;
	}

	SPDK_NOTICELOG("*** OFI host ctrlr constructed (provider=%s) ***\n", tctrlr->provider);
	return &tctrlr->ctrlr;

err_core:
	fi_close(&tctrlr->fabric->fid);
err_fabric:
	fi_freeinfo(tctrlr->info);
err_info:
	free(tctrlr);
	return NULL;
}

static int
nvme_ofi_ctrlr_destruct(struct spdk_nvme_ctrlr *ctrlr)
{
	struct nvme_ofi_ctrlr *tctrlr = nvme_ofi_ctrlr(ctrlr);

	/* The core closes qpairs (each owns its domain + AV) first; here we drop the
	 * per-ctrlr fabric + info. */
	if (tctrlr->fabric) { fi_close(&tctrlr->fabric->fid); }
	if (tctrlr->info) { fi_freeinfo(tctrlr->info); }

	nvme_ctrlr_destruct_finish(&tctrlr->ctrlr);
	free(tctrlr);
	return 0;
}

static int
nvme_ofi_ctrlr_enable(struct spdk_nvme_ctrlr *ctrlr)
{
	/* Nothing transport-specific: the core enables the controller state. */
	return 0;
}

static uint32_t
nvme_ofi_ctrlr_get_max_xfer_size(struct spdk_nvme_ctrlr *ctrlr)
{
	/* V2 carries up to the RMA ceiling (131072) in ONE keyed-SGL command; V1 is
	 * capped at in-capsule (4096). The core splits any IO exceeding this into
	 * child requests, so advertising the V1 ceiling in V2 mode fragmented every
	 * large IO into 4K RMAs — defeating V2's single-RMA large-IO path (measured
	 * 128K QD1: 29µs fragmented → 17µs single RMA, +67% IOPS). Must match the
	 * target's max_io_size (131072) so the target accepts the un-split command. */
	struct nvme_ofi_ctrlr *tctrlr = nvme_ofi_ctrlr(ctrlr);
	return tctrlr->use_rma ? NVME_OFI_RMA_DATA_SIZE : NVME_OFI_IN_CAPSULE_DATA_SIZE;
}

static uint16_t
nvme_ofi_ctrlr_get_max_sges(struct spdk_nvme_ctrlr *ctrlr)
{
	struct nvme_ofi_ctrlr *tctrlr = nvme_ofi_ctrlr(ctrlr);

	/* V1 = single-segment. V2 gathers multi-segment payloads into one bounce buffer
	 * (design §6.3.2) and advertises a single keyed SGL, so the per-command segment
	 * count is independent of the provider's iov_limit / rma_iov_limit — let the core
	 * pass multi-segment IOs through instead of splitting them. */
	return tctrlr->use_rma ? NVME_OFI_MAX_SGES : 1;
}

static int
nvme_ofi_ctrlr_get_memory_domains(const struct spdk_nvme_ctrlr *ctrlr,
				  struct spdk_memory_domain **domains, int array_size)
{
	/* Advertise the system memory domain (normal memory we fi_mr_reg by vaddr).
	 * Returning 0 makes the bdev layer think the transport accepts no memory
	 * domain, disabling zero-copy matching — mirrors nvme_tcp.c. */
	if (domains && array_size > 0) {
		domains[0] = spdk_memory_domain_get_system_domain();
	}
	return 1;
}

/* -------------------------------------------------------------------------- */
/* qpair create / delete                                                      */
/* -------------------------------------------------------------------------- */

static struct spdk_nvme_qpair *
nvme_ofi_ctrlr_create_io_qpair(struct spdk_nvme_ctrlr *ctrlr, uint16_t qid,
			       const struct spdk_nvme_io_qpair_opts *opts)
{
	struct nvme_ofi_ctrlr *tctrlr = nvme_ofi_ctrlr(ctrlr);
	struct nvme_ofi_qpair *tqpair;
	enum spdk_nvme_qprio qprio = SPDK_NVME_QPRIO_URGENT;
	uint32_t qsize, num_requests;
	bool async = true;
	struct fi_cq_attr cq_attr = {0};
	uint32_t i;
	int rc;

	if (opts != NULL) {
		qsize = opts->io_queue_size;
		qprio = opts->qprio;
		num_requests = opts->io_queue_requests;
		async = opts->async_mode;
	} else {
		/* admin qpair, created in ctrlr_construct */
		qsize = ctrlr->opts.admin_queue_size;
		num_requests = ctrlr->opts.admin_queue_size;
	}

	tqpair = calloc(1, sizeof(*tqpair));
	if (tqpair == NULL) {
		return NULL;
	}

	/* Initialise the base qpair: sets trtype/ctrlr/transport + builds the core's
	 * free_req pool (num_requests entries). MUST precede any qpair use. */
	rc = nvme_qpair_init(&tqpair->qpair, qid, ctrlr, qprio, num_requests, async);
	if (rc != 0) {
		free(tqpair);
		return NULL;
	}

	tqpair->tctrlr = tctrlr;
	tqpair->ctrlr = ctrlr;
	tqpair->peer_fi_addr = FI_ADDR_NOTAVAIL;
	tqpair->num_slots = qsize;
	tqpair->req_table_sz = num_requests;
	tqpair->use_rma = tctrlr->use_rma;

	/* #45: per-qpair domain + AV (see ctrlr_construct). Must precede the CQ and
	 * the EP (which binds both). */
	rc = fi_domain(tctrlr->fabric, tctrlr->info, &tqpair->domain, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("ofi host: fi_domain: %s\n", fi_strerror(-rc));
		goto err;
	}
	struct fi_av_attr av_attr = {0};
	av_attr.type = FI_AV_MAP;
	rc = fi_av_open(tqpair->domain, &av_attr, &tqpair->av, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("ofi host: fi_av_open: %s\n", fi_strerror(-rc));
		goto err;
	}

	/* One CQ per qpair (tx+rx bound to it). */
	cq_attr.size = qsize * 2;
	cq_attr.format = FI_CQ_FORMAT_DATA;	/* need .data for the cid tag */
	cq_attr.wait_obj = FI_WAIT_NONE;
	rc = fi_cq_open(tqpair->domain, &cq_attr, &tqpair->cq, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("ofi host: fi_cq_open: %s\n", fi_strerror(-rc));
		goto err;
	}
	tqpair->mr_local = (tctrlr->info->domain_attr->mr_mode & FI_MR_LOCAL) != 0;

	/* Allocate + (conditionally) MR-register the recv/send slot buffers. */
	tqpair->recv_slots = calloc(qsize, sizeof(*tqpair->recv_slots));
	tqpair->send_slots = calloc(qsize, sizeof(*tqpair->send_slots));
	tqpair->req_table = calloc(num_requests, sizeof(*tqpair->req_table));
	tqpair->outstanding = calloc(num_requests, sizeof(*tqpair->outstanding));
	tqpair->cid_free = calloc(num_requests, sizeof(*tqpair->cid_free));	/* H2 */
	/* V2 MR cache pool (growable; #3 refcounted, evict-only-cold). */
	tqpair->mr_cache_cap = NVME_OFI_MR_CACHE_INIT;
	tqpair->mr_cache = calloc(tqpair->mr_cache_cap, sizeof(*tqpair->mr_cache));
	if (tqpair->recv_slots == NULL || tqpair->send_slots == NULL ||
	    tqpair->req_table == NULL || tqpair->outstanding == NULL ||
	    tqpair->cid_free == NULL || tqpair->mr_cache == NULL) {
		goto err;
	}
	TAILQ_INIT(&tqpair->pending_recvs);
	TAILQ_INIT(&tqpair->send_free);		/* H1: filled in the slot loop below */
	tqpair->bounce_free = NULL;
	/* H2: prime the free-cid stack with every cid (pop order is irrelevant). */
	for (i = 0; i < num_requests; i++) {
		tqpair->cid_free[i] = (uint16_t)(num_requests - 1 - i);
	}
	tqpair->cid_free_n = num_requests;
	/* Chain every MR slot into the free list; mark every outstanding slot empty. */
	for (i = 0; i < tqpair->mr_cache_cap; i++) {
		tqpair->mr_cache[i].next_free = (i + 1 < tqpair->mr_cache_cap) ? (i + 1) : UINT32_MAX;
	}
	tqpair->mr_free_head = 0;
	for (i = 0; i < num_requests; i++) {
		tqpair->outstanding[i].mr_idx = UINT32_MAX;
	}
	for (i = 0; i < qsize; i++) {
		tqpair->recv_slots[i].tqpair = tqpair;
		tqpair->recv_slots[i].buf = spdk_zmalloc(NVME_OFI_RECV_BUF_SIZE, 0, NULL,
					  SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
		tqpair->send_slots[i].tqpair = tqpair;
		tqpair->send_slots[i].buf = spdk_zmalloc(NVME_OFI_SEND_BUF_SIZE, 0, NULL,
					  SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
		if (tqpair->recv_slots[i].buf == NULL || tqpair->send_slots[i].buf == NULL) {
			goto err;
		}
		TAILQ_INSERT_TAIL(&tqpair->send_free, &tqpair->send_slots[i], link);	/* H1 */
		if (tqpair->mr_local) {
			rc = fi_mr_reg(tqpair->domain, tqpair->recv_slots[i].buf,
				       NVME_OFI_RECV_BUF_SIZE, FI_RECV, 0, 0, 0,
				       &tqpair->recv_slots[i].mr, NULL);
			if (rc != 0) {
				SPDK_ERRLOG("ofi host: fi_mr_reg(recv): %s\n", fi_strerror(-rc));
				goto err;
			}
			rc = fi_mr_reg(tqpair->domain, tqpair->send_slots[i].buf,
				       NVME_OFI_SEND_BUF_SIZE, FI_SEND, 0, 0, 0,
				       &tqpair->send_slots[i].mr, NULL);
			if (rc != 0) {
				SPDK_ERRLOG("ofi host: fi_mr_reg(send): %s\n", fi_strerror(-rc));
				goto err;
			}
			tqpair->recv_slots[i].desc = fi_mr_desc(tqpair->recv_slots[i].mr);
			tqpair->send_slots[i].desc = fi_mr_desc(tqpair->send_slots[i].mr);
		}
	}

	SPDK_INFOLOG(nvme_ofi, "ofi host qpair %u created (qsize=%u mr_local=%d)\n",
		     qid, qsize, tqpair->mr_local);
	spdk_trace_record(TRACE_NVME_OFI_HOST_QP_CREATE, tqpair->qpair.id, 0, 0, qsize);
	return &tqpair->qpair;

err:
	SPDK_ERRLOG("ofi host: qpair create failed\n");
	nvme_ofi_qpair_free_res(tqpair);
	return NULL;
}

static void
nvme_ofi_qpair_free_res(struct nvme_ofi_qpair *tqpair)
{
	uint32_t i;

	spdk_trace_record(TRACE_NVME_OFI_HOST_QP_DESTROY, tqpair->qpair.id, 0, 0, tqpair->qpair.id);

	if (tqpair->recv_slots) {
		for (i = 0; i < tqpair->num_slots; i++) {
			if (tqpair->mr_local && tqpair->recv_slots[i].mr) {
				fi_close(&tqpair->recv_slots[i].mr->fid);
			}
			spdk_free(tqpair->recv_slots[i].buf);
		}
		free(tqpair->recv_slots);
	}
	if (tqpair->send_slots) {
		for (i = 0; i < tqpair->num_slots; i++) {
			if (tqpair->mr_local && tqpair->send_slots[i].mr) {
				fi_close(&tqpair->send_slots[i].mr->fid);
			}
			spdk_free(tqpair->send_slots[i].buf);
		}
		free(tqpair->send_slots);
	}
	free(tqpair->req_table);
	free(tqpair->cid_free);		/* H2 */
	/* Post-mortem MR-cache summary — the host has no RPC server, so qpair teardown is
	 * the only window to read the #3 counters (visible at --log-level notice). */
	SPDK_NOTICELOG("ofi host qpair torn down: MR cache reg=%lu hit=%lu evict=%lu grow=%lu (final cap=%u)\n",
		       tqpair->mr_reg, tqpair->mr_hit, tqpair->mr_evict, tqpair->mr_grow,
		       tqpair->mr_cache_cap);
	/* Close the V2 remote-data MRs (registered lazily by nvme_ofi_mr_get). EP is torn
	 * down before free_res (delete_io_qpair → ep_teardown), so no RMA is in flight. */
	for (i = 0; i < tqpair->mr_cache_cap; i++) {
		if (tqpair->mr_cache[i].mr) {
			fi_close(&tqpair->mr_cache[i].mr->fid);
		}
	}
	free(tqpair->mr_cache);
	/* Free all multi-seg bounce buffers: the free-list plus any still referenced by
	 * outstanding requests the disconnect drain didn't complete (defensive — completion
	 * clears outstanding[i].bounce first, so no double-free). */
	if (tqpair->outstanding != NULL) {
		for (i = 0; i < tqpair->req_table_sz; i++) {
			if (tqpair->outstanding[i].bounce != NULL) {
				spdk_free(tqpair->outstanding[i].bounce->buf);
				free(tqpair->outstanding[i].bounce);
				tqpair->outstanding[i].bounce = NULL;
			}
		}
	}
	{
		struct nvme_ofi_bounce *b = tqpair->bounce_free, *bn;
		while (b != NULL) { bn = b->next; spdk_free(b->buf); free(b); b = bn; }
	}
	free(tqpair->outstanding);
	if (tqpair->cq) { fi_close(&tqpair->cq->fid); }
	if (tqpair->av) { fi_close(&tqpair->av->fid); }
	if (tqpair->domain) { fi_close(&tqpair->domain->fid); }
	free(tqpair);
}

static int
nvme_ofi_ctrlr_delete_io_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct nvme_ofi_qpair *tqpair = nvme_ofi_qpair(qpair);

	nvme_ofi_ep_teardown(tqpair);
	if (tqpair->sb_sock) {
		spdk_sock_close(&tqpair->sb_sock);
	}
	nvme_ofi_qpair_free_res(tqpair);
	return 0;
}

/* -------------------------------------------------------------------------- */
/* connect: sideband handshake + EP bring-up, driven from process_completions */
/* -------------------------------------------------------------------------- */

/* Retry recv slots whose re-post hit -FI_EAGAIN (queued in drain_cq's recv
 * branch). Called at the top of drain_cq so re-posted buffers can receive. */
static void
nvme_ofi_drain_pending_recv(struct nvme_ofi_qpair *tqpair)
{
	struct nvme_ofi_recv_slot *slot;

	while ((slot = TAILQ_FIRST(&tqpair->pending_recvs)) != NULL) {
		if (nvme_ofi_post_recv(tqpair, slot) != 0) {
			break;	/* still -FI_EAGAIN; retry next drain_cq */
		}
		TAILQ_REMOVE(&tqpair->pending_recvs, slot, link);
	}
}

/*
 * Drain the per-qpair CQ: complete recv'd CQEs (match by cid tag) and recycle
 * send slots on tx completions. Shared by the connect poll (reaps the Fabrics
 * CONNECT response) and the steady-state data path.
 */
static int
nvme_ofi_drain_cq(struct nvme_ofi_qpair *tqpair, uint32_t max_completions)
{
	struct fi_cq_data_entry entries[NVME_OFI_CQ_BATCH];
	struct fi_cq_err_entry err;
	uint32_t reaped = 0;
	ssize_t rc, k;

	if (!tqpair->ep_enabled) {
		return 0;
	}
	nvme_ofi_drain_pending_recv(tqpair);
	if (max_completions == 0) {
		max_completions = tqpair->num_slots;
	}

	while (reaped < max_completions) {
		uint32_t want = spdk_min(NVME_OFI_CQ_BATCH, max_completions - reaped);

		rc = fi_cq_read(tqpair->cq, entries, want);
		if (rc == -FI_EAGAIN) {
			break;
		}
		if (rc == -FI_EAVAIL) {
			memset(&err, 0, sizeof(err));
			fi_cq_readerr(tqpair->cq, &err, 0);
			SPDK_ERRLOG("ofi host: CQ error err=%d(%s) prov=%d flags=0x%lx len=%zu olen=%zu\n",
				    err.err, fi_strerror(err.err), err.prov_errno,
				    (unsigned long)err.flags, err.len, err.olen);
			spdk_trace_record(TRACE_NVME_OFI_HOST_CQ_ERROR, tqpair->qpair.id, 0, 0, err.err);
			nvme_ctrlr_disconnect_qpair(&tqpair->qpair);
			return -ENXIO;
		}
		if (rc < 0) {
			SPDK_ERRLOG("ofi host: fi_cq_read: %zd\n", rc);
			break;
		}

		for (k = 0; k < rc; k++) {
			struct fi_cq_data_entry *e = &entries[k];

			if (e->flags & FI_RECV) {
				struct nvme_ofi_recv_slot *slot = e->op_context;
				uint16_t cid = NVME_OFI_TAG_CID(e->data);
				const struct spdk_nvme_cpl *cpl;
				const void *data = NULL;
				uint32_t data_len = 0;

				if (e->len >= sizeof(struct spdk_nvme_cpl)) {
					cpl = (const struct spdk_nvme_cpl *)slot->buf;
					if (e->len > sizeof(struct spdk_nvme_cpl)) {
						data = (const char *)slot->buf + sizeof(struct spdk_nvme_cpl);
						data_len = e->len - sizeof(struct spdk_nvme_cpl);
					}
					nvme_ofi_complete_request(tqpair, cid, cpl, data, data_len);
				}
				slot->posted = false;
				if (nvme_ofi_post_recv(tqpair, slot) != 0) {
					/* Provider recv resources exhausted (-FI_EAGAIN). Queue instead
					 * of dropping — a dropped slot permanently shrinks the recv pool
					 * and starves the qpair. Retried at the top of the next drain_cq. */
					TAILQ_INSERT_TAIL(&tqpair->pending_recvs, slot, link);
				}
			} else if (e->flags & FI_REMOTE_WRITE) {
				/* #46: folded READ completion — the target's fi_write carried the CID
				 * as CQ immediate data and the read data landed in our payload MR.
				 * Synthesize a success CQE (fabrics ignores sqhd/phase; only cid +
				 * success status matter) and complete. No recv buffer was consumed,
				 * so nothing to re-post. */
				uint16_t cid = NVME_OFI_TAG_CID(e->data);
				struct spdk_nvme_cpl cpl = {};

				cpl.cid = cid;
				cpl.status.sct = SPDK_NVME_SCT_GENERIC;
				cpl.status.sc = SPDK_NVME_SC_SUCCESS;
				nvme_ofi_complete_request(tqpair, cid, &cpl, NULL, 0);
			} else {
				/* TX completion (fi_sendmsg only — injects produce none): the slot
				 * is done transmitting, return it to the free list (H1). */
				struct nvme_ofi_send_slot *slot = e->op_context;
				TAILQ_INSERT_HEAD(&tqpair->send_free, slot, link);
			}
			reaped++;
		}
	}
	return (int)reaped;
}

/*
 * Advance the sideband handshake + EP bring-up as far as non-blocking I/O
 * allows. Called from qpair_process_completions while the core keeps the qpair
 * in NVME_QPAIR_CONNECTING. Returns 0 (still connecting, or just finished) or
 * -EIO (failed). On Fabrics-CONNECT completion it sets the qpair to CONNECTED.
 */
static int
nvme_ofi_connect_poll(struct nvme_ofi_qpair *tqpair)
{
	struct spdk_nvme_qpair *qpair = &tqpair->qpair;
	uint16_t mt;
	uint32_t plen, status;
	int rc;

	while (tqpair->sb_state != NVME_OFI_SB_READY &&
	       tqpair->sb_state != NVME_OFI_SB_FAILED) {
		switch (tqpair->sb_state) {
		case NVME_OFI_SB_HELLO_SEND:
			rc = nvme_ofi_sb_flush(tqpair);
			if (rc == -EAGAIN) { return 0; }
			if (rc != 0) { goto fail; }
			tqpair->sb_state = NVME_OFI_SB_HELLO_ACK_RECV;
			continue;

		case NVME_OFI_SB_HELLO_ACK_RECV:
			rc = nvme_ofi_sb_recv(tqpair, 0);
			if (rc == -EAGAIN) { return 0; }
			if (rc != 0) { goto fail; }
			if (nvme_ofi_sb_hdr_validate((struct nvme_ofi_sb_hdr *)tqpair->sb_rx,
						     &mt, &plen, &status) != 0 ||
			    mt != NVME_OFI_SB_HELLO_ACK || status != NVME_OFI_SB_STAT_OK) {
				SPDK_ERRLOG("ofi host: HELLO_ACK rejected\n");
				goto fail;
			}
			nvme_ofi_sb_rx_consume(tqpair, NVME_OFI_SB_HDR_SIZE);
			tqpair->sb_state = NVME_OFI_SB_EP_CREATE;
			continue;

		case NVME_OFI_SB_EP_CREATE: {
			uint8_t abuf[sizeof(struct nvme_ofi_sb_addr) + 256];
			struct nvme_ofi_sb_addr *ah = (struct nvme_ofi_sb_addr *)abuf;

			rc = nvme_ofi_ep_create(tqpair);
			if (rc != 0) { goto fail; }
			memset(ah, 0, sizeof(*ah));
			snprintf(ah->provider, sizeof(ah->provider), "%s", tqpair->tctrlr->provider);
			ah->ep_addr_len_le = nvme_ofi_cpu_to_le32((uint32_t)tqpair->local_ep_addr_len);
			memcpy(abuf + sizeof(*ah), tqpair->local_ep_addr, tqpair->local_ep_addr_len);
			nvme_ofi_sb_queue(tqpair, NVME_OFI_SB_ADDR_EXCH, abuf,
					  sizeof(*ah) + (uint32_t)tqpair->local_ep_addr_len,
					  NVME_OFI_SB_STAT_OK);
			tqpair->sb_state = NVME_OFI_SB_ADDR_RECV;
			continue;
		}

		case NVME_OFI_SB_ADDR_RECV: {
			struct nvme_ofi_sb_addr *pa;

			rc = nvme_ofi_sb_flush(tqpair);	/* send our ADDR_EXCHANGE */
			if (rc == -EAGAIN) { return 0; }
			if (rc != 0) { goto fail; }

			if (tqpair->sb_rx_off < NVME_OFI_SB_HDR_SIZE) {
				rc = nvme_ofi_sb_recv(tqpair, 0);
				if (rc == -EAGAIN) { return 0; }
				if (rc != 0) { goto fail; }
			}
			if (nvme_ofi_sb_hdr_validate((struct nvme_ofi_sb_hdr *)tqpair->sb_rx,
						     &mt, &plen, &status) != 0 ||
			    mt != NVME_OFI_SB_ADDR_EXCH) {
				SPDK_ERRLOG("ofi host: ADDR_EXCHANGE malformed\n");
				goto fail;
			}
			rc = nvme_ofi_sb_recv(tqpair, plen);
			if (rc == -EAGAIN) { return 0; }
			if (rc != 0) { goto fail; }
			pa = (struct nvme_ofi_sb_addr *)(tqpair->sb_rx + NVME_OFI_SB_HDR_SIZE);
			tqpair->peer_ep_addr_len = nvme_ofi_le32_to_cpu(pa->ep_addr_len_le);
			if (tqpair->peer_ep_addr_len > sizeof(tqpair->peer_ep_addr) ||
			    plen < sizeof(*pa) + tqpair->peer_ep_addr_len) {
				SPDK_ERRLOG("ofi host: bad peer ep_addr_len\n");
				goto fail;
			}
			memcpy(tqpair->peer_ep_addr,
			       tqpair->sb_rx + NVME_OFI_SB_HDR_SIZE + sizeof(*pa),
			       tqpair->peer_ep_addr_len);
			{
				fi_addr_t peer = FI_ADDR_NOTAVAIL;
				ssize_t ni = fi_av_insert(tqpair->av, tqpair->peer_ep_addr,
							  1, &peer, 0, NULL);
				if (ni != 1) {
					SPDK_ERRLOG("ofi host: fi_av_insert: %zd\n", ni);
					goto fail;
				}
				tqpair->peer_fi_addr = peer;
			}
			nvme_ofi_sb_rx_consume(tqpair, NVME_OFI_SB_HDR_SIZE + plen);
			nvme_ofi_sb_queue(tqpair, NVME_OFI_SB_ADDR_ACK, NULL, 0, NVME_OFI_SB_STAT_OK);
			tqpair->sb_state = NVME_OFI_SB_ADDR_ACK_XCHG;
			continue;
		}

		case NVME_OFI_SB_ADDR_ACK_XCHG: {
			uint32_t i, num_entries;

			rc = nvme_ofi_sb_flush(tqpair);	/* send our ADDR_ACK */
			if (rc == -EAGAIN) { return 0; }
			if (rc != 0) { goto fail; }
			rc = nvme_ofi_sb_recv(tqpair, 0);	/* recv peer's ADDR_ACK */
			if (rc == -EAGAIN) { return 0; }
			if (rc != 0) { goto fail; }
			if (nvme_ofi_sb_hdr_validate((struct nvme_ofi_sb_hdr *)tqpair->sb_rx,
						     &mt, &plen, &status) != 0 ||
			    mt != NVME_OFI_SB_ADDR_ACK) {
				SPDK_ERRLOG("ofi host: ADDR_ACK malformed\n");
				goto fail;
			}
			nvme_ofi_sb_rx_consume(tqpair, NVME_OFI_SB_HDR_SIZE);

			/* Transport connected: pre-post recv buffers, then send the Fabrics
			 * CONNECT (the core built it via nvme_fabric_qpair_connect_async). */
			for (i = 0; i < tqpair->num_slots; i++) {
				nvme_ofi_post_recv(tqpair, &tqpair->recv_slots[i]);
			}
			/* Fabrics CONNECT carries SQSIZE = num_entries - 1 (0-based). Our
			 * queue holds num_slots entries, so SQSIZE must be num_slots - 1,
			 * i.e. pass num_entries = num_slots. (nvme_rdma reaches the same
			 * result by keeping num_entries = qsize-1 then passing +1.) Passing
			 * num_slots+1 here overshoots SQSIZE by one and the target rejects
			 * the IO qpair with "Invalid SQSIZE" / sc=0x82 once num_slots == MQES+1. */
			num_entries = tqpair->num_slots;
			rc = nvme_fabric_qpair_connect_async(qpair, num_entries);
			if (rc != 0) {
				SPDK_ERRLOG("ofi host: fabric connect_async: %d\n", rc);
				goto fail;
			}
			tqpair->sb_state = NVME_OFI_SB_FABRIC_CONNECT_POLL;
			continue;
		}

		case NVME_OFI_SB_FABRIC_CONNECT_POLL:
			/* Reap the CONNECT response from the CQ, then check the fabrics poll. */
			nvme_ofi_drain_cq(tqpair, tqpair->num_slots);
			rc = nvme_fabric_qpair_connect_poll(qpair);
			if (rc == -EAGAIN) { return 0; }
			if (rc != 0) {
				SPDK_ERRLOG("ofi host: fabric connect_poll: %d\n", rc);
				goto fail;
			}
			nvme_qpair_set_state(qpair, NVME_QPAIR_CONNECTED);
			SPDK_NOTICELOG("ofi host qpair %u CONNECTED (fabrics connect ok)\n", qpair->id);
			spdk_trace_record(TRACE_NVME_OFI_HOST_CONNECT, tqpair->qpair.id, 0, 0, qpair->id);
			tqpair->sb_state = NVME_OFI_SB_READY;
			return 0;

		default:
			return -EIO;
		}
	}

	if (tqpair->sb_state == NVME_OFI_SB_FAILED) {
		return -EIO;
	}
	return 0;

fail:
	tqpair->sb_state = NVME_OFI_SB_FAILED;
	nvme_ofi_ep_teardown(tqpair);
	if (tqpair->sb_sock) {
		spdk_sock_close(&tqpair->sb_sock);
	}
	return -EIO;
}

/*
 * Initiate a connect: open the sideband TCP socket and queue HELLO. Returns 0
 * (connect initiated) — the core then polls qpair_process_completions, which
 * drives nvme_ofi_connect_poll to finish the handshake + Fabrics CONNECT.
 */
static int
nvme_ofi_ctrlr_connect_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct nvme_ofi_qpair *tqpair = nvme_ofi_qpair(qpair);
	const struct spdk_nvme_transport_id *trid = &ctrlr->trid;
	struct nvme_ofi_sb_hello hello;

	if (tqpair->sb_state == NVME_OFI_SB_FAILED) {
		return -EIO;
	}
	if (tqpair->sb_sock != NULL) {
		return 0;	/* already initiating (e.g. reconnect) */
	}

	tqpair->sb_sock = spdk_sock_connect(trid->traddr, atoi(trid->trsvcid), NULL);
	if (tqpair->sb_sock == NULL) {
		SPDK_ERRLOG("ofi host: sb connect failed: %s\n", spdk_strerror(errno));
		return -errno;
	}

	memset(&hello, 0, sizeof(hello));
	snprintf(hello.hostnqn, sizeof(hello.hostnqn), "%s", ctrlr->opts.hostnqn);
	snprintf(hello.subnqn, sizeof(hello.subnqn), "%s", trid->subnqn);
	hello.qid_le = nvme_ofi_cpu_to_le16(qpair->id);
	hello.qdepth_le = nvme_ofi_cpu_to_le16((uint16_t)tqpair->num_slots);
	hello.max_io_size_le = nvme_ofi_cpu_to_le32(NVME_OFI_IN_CAPSULE_DATA_SIZE);
	hello.io_unit_size_le = nvme_ofi_cpu_to_le32(NVME_OFI_IN_CAPSULE_DATA_SIZE);
	hello.in_capsule_data_size_le = nvme_ofi_cpu_to_le32(NVME_OFI_IN_CAPSULE_DATA_SIZE);
	snprintf(hello.host_provider, sizeof(hello.host_provider), "%s", tqpair->tctrlr->provider);
	nvme_ofi_sb_queue(tqpair, NVME_OFI_SB_HELLO, &hello, sizeof(hello), NVME_OFI_SB_STAT_OK);
	tqpair->sb_state = NVME_OFI_SB_HELLO_SEND;
	return 0;
}

static void
nvme_ofi_ctrlr_disconnect_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct nvme_ofi_qpair *tqpair = nvme_ofi_qpair(qpair);

	/* The core polls process_completions while the qpair is DISCONNECTING and
	 * waits for it to reach DISCONNECTED (nvme_ctrlr.c:618). Our EP teardown is
	 * synchronous, so tear everything down and advance straight to DISCONNECTED
	 * before returning — otherwise the core spins forever. */
	nvme_qpair_set_state(qpair, NVME_QPAIR_DISCONNECTING);
	nvme_ofi_ep_teardown(tqpair);
	if (tqpair->sb_sock) {
		spdk_sock_close(&tqpair->sb_sock);
		tqpair->sb_sock = NULL;
	}
	tqpair->sb_state = NVME_OFI_SB_INIT;
	nvme_qpair_set_state(qpair, NVME_QPAIR_DISCONNECTED);
}

/* -------------------------------------------------------------------------- */
/* qpair_submit_request / qpair_process_completions (V1 data path)            */
/* -------------------------------------------------------------------------- */

/*
 * Look up (or register) a remote-data MR for a host buffer and return the
 * {addr,key} the target needs to RMA into/out of it, plus the cache slot index
 * (*out_idx) the caller holds until the request completes — so the MR cannot be
 * reclaimed while its {addr,key} is still in flight on the target (#3). Registered
 * with both remote READ (target fi_read for NVMe WRITE) and remote WRITE (target
 * fi_write for NVMe READ) so one MR serves either direction. bind/enable only on
 * FI_MR_ENDPOINT (CXI).
 *
 * The cache is a growable, indexed pool with a free-list. On overflow the oldest
 * entry with refcnt==0 (cold) is reclaimed; if EVERY entry is in flight the pool
 * grows. An MR is therefore never fi_close'd while an outstanding RMA references it.
 *
 * Key handling: when the negotiated mr_mode has FI_MR_PROV_KEY (verbs;ofi_rxm,
 * CXI — AND tcp here, because the transport requests PROV_KEY in its getinfo
 * hints to satisfy verbs) the PROVIDER assigns the key, so requested_key MUST be
 * 0 — passing a caller key gets -FI_EKEYREJECTED. Only when PROV_KEY is absent
 * does the caller supply a unique key per MR. (The prototype passed caller keys
 * on tcp because it never requested PROV_KEY in hints — see p0b_findings #3.)
 */
static int
nvme_ofi_mr_get(struct nvme_ofi_qpair *tqpair, void *buf, size_t len,
		uint64_t *out_addr, uint64_t *out_key, uint32_t *out_idx)
{
	struct nvme_ofi_ctrlr *tctrlr = tqpair->tctrlr;
	const uint64_t access = FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
	bool prov_key = (tctrlr->info->domain_attr->mr_mode & FI_MR_PROV_KEY) != 0;
	struct nvme_ofi_mr_cache_entry *e;
	struct fid_mr *mr = NULL;
	uint64_t key, addr, req_key;
	uint32_t i, slot;
	int rc;

	/* 1. Lookup among live (registered) entries. */
	for (i = 0; i < tqpair->mr_cache_cap; i++) {
		e = &tqpair->mr_cache[i];
		if (e->mr != NULL && e->buf == buf && e->len >= len) {
			e->refcnt++;
			tqpair->mr_hit++;
			*out_addr = e->addr;
			*out_key = e->key;
			*out_idx = i;
			return 0;
		}
	}

	/* 2. Ensure a free slot: evict a cold entry, or grow the pool. */
	if (tqpair->mr_free_head == UINT32_MAX) {
		for (i = 0; i < tqpair->mr_cache_cap; i++) {
			e = &tqpair->mr_cache[i];
			if (e->mr != NULL && e->refcnt == 0) {
				break;
			}
		}
		if (i < tqpair->mr_cache_cap) {
			fi_close(&e->mr->fid);
			e->mr = NULL;
			e->next_free = tqpair->mr_free_head;
			tqpair->mr_free_head = i;
			tqpair->mr_evict++;
		} else {
			/* Every entry is in flight — grow the pool (rare; bounded by QD). */
			uint32_t oldcap = tqpair->mr_cache_cap, newcap = oldcap * 2, j;
			struct nvme_ofi_mr_cache_entry *grown;

			grown = realloc(tqpair->mr_cache, newcap * sizeof(*grown));
			if (grown == NULL) {
				SPDK_ERRLOG("ofi host: MR cache grow failed\n");
				return -FI_ENOMEM;
			}
			tqpair->mr_cache = grown;
			tqpair->mr_cache_cap = newcap;
			for (j = oldcap; j < newcap; j++) {
				tqpair->mr_cache[j].mr = NULL;
				tqpair->mr_cache[j].next_free = (j + 1 < newcap) ? (j + 1) : tqpair->mr_free_head;
			}
			tqpair->mr_free_head = oldcap;
			tqpair->mr_grow++;
		}
	}

	/* 3. Pop a free slot, register, fill. */
	slot = tqpair->mr_free_head;
	e = &tqpair->mr_cache[slot];
	tqpair->mr_free_head = e->next_free;

	req_key = prov_key ? 0 : __atomic_fetch_add(&tctrlr->mr_next_key, 1, __ATOMIC_RELAXED);
	rc = fi_mr_reg(tqpair->domain, buf, len, access, 0, req_key, 0, &mr, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("ofi host: fi_mr_reg (remote data): %s\n", fi_strerror(-rc));
		e->next_free = tqpair->mr_free_head;
		tqpair->mr_free_head = slot;
		return rc;
	}
	if (tctrlr->info->domain_attr->mr_mode & FI_MR_ENDPOINT) {
		rc = fi_mr_bind(mr, &tqpair->ep->fid, access);
		if (rc == 0) { rc = fi_mr_enable(mr); }
		if (rc != 0) {
			SPDK_ERRLOG("ofi host: fi_mr_bind/enable: %s\n", fi_strerror(-rc));
			fi_close(&mr->fid);
			e->next_free = tqpair->mr_free_head;
			tqpair->mr_free_head = slot;
			return rc;
		}
	}

	key = fi_mr_key(mr);
	addr = (tctrlr->info->domain_attr->mr_mode & FI_MR_VIRT_ADDR) ? (uint64_t)buf : 0;

	e->buf = buf;
	e->len = len;
	e->mr = mr;
	e->addr = addr;
	e->key = key;
	e->refcnt = 1;
	tqpair->mr_reg++;
	spdk_trace_record(TRACE_NVME_OFI_HOST_MR_REG, tqpair->qpair.id, 0, 0, (uint32_t)len);

	*out_addr = addr;
	*out_key = key;
	*out_idx = slot;
	return 0;
}

/* Undo per-CID state committed in the V2 submit block when the send fails — the core
 * retries the request (possibly under a different cid), so this cid's MR reference and
 * bounce must be released. Self-gating: a no-op for V1/CONNECT/no-data (clean slot). */
static void
nvme_ofi_submit_rollback(struct nvme_ofi_qpair *tqpair, uint16_t cid)
{
	struct nvme_ofi_outstanding *o;

	if (cid >= tqpair->req_table_sz) {
		return;
	}
	o = &tqpair->outstanding[cid];
	if (o->bounce != NULL) {
		nvme_ofi_bounce_put(tqpair, o->bounce);
		o->bounce = NULL;
	}
	nvme_ofi_mr_put(tqpair, o->mr_idx);
	o->mr_idx = UINT32_MAX;
	o->need_scatter = false;
	/* The cid was popped at submit but never committed (req_table[cid] stays NULL on
	 * a failed send — the core retries, possibly under a different cid). Return it. */
	nvme_ofi_cid_put(tqpair, cid);
}

static int
nvme_ofi_qpair_submit_request(struct spdk_nvme_qpair *qpair, struct nvme_request *req)
{
	struct nvme_ofi_qpair *tqpair = nvme_ofi_qpair(qpair);
	struct nvme_ofi_send_slot *slot = NULL;
	enum spdk_nvme_data_transfer xfer;
	uint16_t cid;
	uint64_t tag;
	uint32_t send_len;
	bool has_incap_data = false;	/* V1 H2C in-capsule payload appended after the SQE */
	struct iovec iov;
	struct fi_msg msg = {0};
	ssize_t rc;

	if (!tqpair->ep_enabled) {
		return -EAGAIN;
	}
	/* V1 (in-capsule) bounds a transfer to one message; V2 (RMA) does not. So
	 * only reject oversize IO when this controller is NOT using the RMA path. */
	if (!tqpair->use_rma && req->payload_size > NVME_OFI_IN_CAPSULE_DATA_SIZE) {
		SPDK_ERRLOG("ofi host: V1 rejects %u-byte IO (> %d in-capsule)\n",
			    req->payload_size, NVME_OFI_IN_CAPSULE_DATA_SIZE);
		return -EINVAL;
	}
	/* V2 RMA bounce buffer on the target bounds a single transfer to 128 KiB. */
	if (tqpair->use_rma && req->payload_size > NVME_OFI_RMA_DATA_SIZE) {
		SPDK_ERRLOG("ofi host: V2 rejects %u-byte IO (> %d RMA ceiling)\n",
			    req->payload_size, NVME_OFI_RMA_DATA_SIZE);
		return -EINVAL;
	}

	/* Allocate a unique command id. The core does NOT set cmd.cid for fabric
	 * transports (nvme_tcp assigns it from the tcp_req index, nvme_tcp.c:872);
	 * leaving it 0 makes every command collide on req_table[0], which silently
	 * loses one of any two concurrently-outstanding commands (e.g. an in-flight
	 * AER vs the next admin command during init). The cid stays reserved until the
	 * *response* arrives (req_table[cid] != NULL), so it is NOT tied to the send
	 * slot — a slot frees on its tx completion, which can land before the response.
	 * H2: O(1) pop from the free-cid stack (was an O(req_table_sz) scan). A send slot
	 * is acquired later, and only on the fi_sendmsg path (the inject path holds none). */
	if (tqpair->cid_free_n == 0) {
		return -EAGAIN;	/* no free cid; core will retry */
	}
	cid = tqpair->cid_free[--tqpair->cid_free_n];
	req->cmd.cid = cid;

	/* Direction: FABRIC commands (e.g. CONNECT) carry it in fctype, not opc. The
	 * Fabrics CONNECT data is ALWAYS in-capsule (the controller — and any MR it
	 * could RMA against — does not exist yet), so it never takes the V2 path. */
	bool is_connect = false;
	if (req->cmd.opc == SPDK_NVME_OPC_FABRIC) {
		struct spdk_nvmf_capsule_cmd *fcmd = (struct spdk_nvmf_capsule_cmd *)&req->cmd;
		xfer = spdk_nvme_opc_get_data_transfer(fcmd->fctype);
		is_connect = (fcmd->fctype == SPDK_NVMF_FABRIC_COMMAND_CONNECT);
	} else {
		xfer = spdk_nvme_opc_get_data_transfer(req->cmd.opc);
	}

	bool use_rma = tqpair->use_rma && !is_connect &&
		       xfer != SPDK_NVME_DATA_NONE && req->payload_size > 0;

	/* The core does NOT build the SGL for fabric transports (nvme_tcp_req_init
	 * does, nvme_tcp.c:872-916); a zero-length SGL makes the target downgrade the
	 * transfer to NONE and reject data commands with INVALID_FIELD. */
	req->cmd.psdt = SPDK_NVME_PSDT_SGL_MPTR_CONTIG;

	if (use_rma) {
		/* V2: advertise ONE keyed SGL so the target moves the data via RMA.
		 *   - contiguous payload: zero-copy — register the caller's buffer directly.
		 *   - multi-segment SGL: gather into a per-qpair bounce buffer (one CPU copy;
		 *     design §6.3.2 — portable across CXI rma_iov_limit=1 and verbs>1) and
		 *     register that. Either way a single keyed SGL is advertised. */
		void *rma_buf = req->payload.contig_or_cb_arg;
		struct nvme_ofi_bounce *bounce = NULL;
		uint64_t rma_addr, rma_key;
		uint32_t mr_idx;
		bool need_scatter = false;
		int mrc;

		if (req->payload.reset_sgl_fn != NULL) {
			/* multi-segment: gather SGL → bounce, then register the bounce. */
			bounce = nvme_ofi_bounce_get(tqpair);
			if (bounce == NULL) {
				nvme_ofi_cid_put(tqpair, cid);
				return -ENOMEM;
			}
			if (xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
				mrc = nvme_ofi_sgl_to_buf(&req->payload, req->payload_offset,
							  req->payload_size, bounce->buf);
				if (mrc != 0) {
					nvme_ofi_bounce_put(tqpair, bounce);
					nvme_ofi_cid_put(tqpair, cid);
					return mrc;
				}
			}
			rma_buf = bounce->buf;
			need_scatter = (xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST);
		}
		mrc = nvme_ofi_mr_get(tqpair, rma_buf, req->payload_size,
				      &rma_addr, &rma_key, &mr_idx);
		if (mrc != 0) {
			if (bounce != NULL) {
				nvme_ofi_bounce_put(tqpair, bounce);
			}
			nvme_ofi_cid_put(tqpair, cid);
			return mrc;
		}
		req->cmd.dptr.sgl1.keyed.type = SPDK_NVME_SGL_TYPE_KEYED_DATA_BLOCK;
		req->cmd.dptr.sgl1.keyed.subtype = SPDK_NVME_SGL_SUBTYPE_ADDRESS;
		req->cmd.dptr.sgl1.keyed.length = req->payload_size;
		req->cmd.dptr.sgl1.keyed.key = rma_key;
		req->cmd.dptr.sgl1.address = rma_addr;

		/* Commit per-CID state consumed on completion (#3 MR ref; Gap B bounce).
		 * Rolled back by nvme_ofi_submit_rollback if the send below fails — the core
		 * then retries the request, possibly under a different cid. */
		tqpair->outstanding[cid].mr_idx = mr_idx;
		tqpair->outstanding[cid].bounce = bounce;
		tqpair->outstanding[cid].need_scatter = need_scatter;

		/* V2 capsule is the bare 64B SQE — no in-capsule data (inject-direct below). */
		send_len = sizeof(req->cmd);
	} else {
		/* V1 in-capsule:
		 *   - HOST_TO_CONTROLLER: data block lives in *this* capsule at offset 0.
		 *   - CONTROLLER_TO_HOST: transport data block; data rides the response. */
		req->cmd.dptr.sgl1.unkeyed.length = req->payload_size;
		req->cmd.dptr.sgl1.address = 0;
		if (xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
			req->cmd.dptr.sgl1.unkeyed.type = SPDK_NVME_SGL_TYPE_DATA_BLOCK;
			req->cmd.dptr.sgl1.unkeyed.subtype = SPDK_NVME_SGL_SUBTYPE_OFFSET;
		} else {
			req->cmd.dptr.sgl1.unkeyed.type = SPDK_NVME_SGL_TYPE_TRANSPORT_DATA_BLOCK;
			req->cmd.dptr.sgl1.unkeyed.subtype = SPDK_NVME_SGL_SUBTYPE_TRANSPORT;
		}

		/* Capsule = 64B SQE [+ HOST_TO_CONTROLLER data]. The assembly into a send
		 * slot (data is not contiguous with req->cmd) happens on the slot path below;
		 * has_incap_data flags that this command cannot take the inject-direct path. */
		send_len = sizeof(req->cmd);
		if (xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER && req->payload_size > 0) {
			if (req->payload.reset_sgl_fn != NULL) {
				/* SGL not supported in V1 (single-segment). */
				nvme_ofi_cid_put(tqpair, cid);
				return -EINVAL;
			}
			has_incap_data = true;
			send_len += req->payload_size;
		}
	}

	tag = NVME_OFI_TAG(cid, NVME_OFI_MSG_SQE);

	/* Inject-direct: when the capsule is the bare SQE (no appended in-capsule data)
	 * AND fits inject_size, send it straight from &req->cmd with fi_injectdata — NO
	 * send slot (skips the H1 pop) and NO memcpy into a slot buffer. The SQE is copied
	 * inline by the provider and generates no TX completion. This is the V2 hot path
	 * and every no-data command.
	 *
	 * Why inject (vs sendmsg) for the bare SQE matters under load: the core's resubmit
	 * batch (nvme_qpair_resubmit_requests) submits many queued requests in a tight loop
	 * WITHOUT polling between them; if each held a send slot until its FI_SEND completion
	 * (not reaped mid-batch) the slot pool would exhaust, submit would -EAGAIN, and the
	 * core — which only resubmits as many as it completed (nvme_qpair.c:905) — would
	 * STRAND the rest once the transport went idle (the V2 large-IO hang, #20).
	 *
	 * tcp/sockets are lazy-connect: the first send returns -FI_EAGAIN while the
	 * connection establishes; the provider progresses when its CQ is read, so spin a
	 * bounded number draining our own CQ between attempts (p0a_findings). */
	if (!has_incap_data && send_len <= tqpair->tctrlr->info->tx_attr->inject_size) {
		int spins = 0;
		do {
			rc = fi_injectdata(tqpair->ep, &req->cmd, send_len, tag,
					   tqpair->peer_fi_addr);
			if (rc != -FI_EAGAIN) {
				break;
			}
			nvme_ofi_drain_cq(tqpair, tqpair->num_slots);
		} while (++spins < NVME_OFI_SEND_SPIN_MAX);
		if (rc == -FI_EAGAIN) {
			nvme_ofi_submit_rollback(tqpair, cid);
			return -EAGAIN;
		}
		if (rc != 0) {
			SPDK_ERRLOG("ofi host: fi_injectdata: %s\n", fi_strerror(-(int)rc));
			nvme_ofi_submit_rollback(tqpair, cid);
			return (int)rc;
		}
		/* inject completes inline: no slot held, no tx completion to recycle. The
		 * cid stays reserved in req_table until the response CQE arrives. */
		tqpair->req_table[cid] = req;
		spdk_trace_record(TRACE_NVME_OFI_HOST_SUBMIT, tqpair->qpair.id, 0, (uintptr_t)req,
				  (uintptr_t)req->cb_arg, (uint32_t)cid);
		return 0;
	}

	/* Slot path: V1 in-capsule data, or a capsule larger than inject_size (e.g. a
	 * provider with inject_size < 64 — then even the bare V2 SQE lands here, keeping
	 * the #20 protection via the slot's FI_SEND completion). Assemble in a send slot
	 * (H1: O(1) free-list pop) and fi_sendmsg. */
	slot = TAILQ_FIRST(&tqpair->send_free);
	if (slot == NULL) {
		nvme_ofi_submit_rollback(tqpair, cid);	/* frees mr/bounce/cid */
		return -EAGAIN;
	}
	TAILQ_REMOVE(&tqpair->send_free, slot, link);
	memcpy(slot->buf, &req->cmd, sizeof(req->cmd));
	if (has_incap_data) {
		memcpy((char *)slot->buf + sizeof(req->cmd), req->payload.contig_or_cb_arg,
		       req->payload_size);
	}

	iov.iov_base = slot->buf;
	iov.iov_len = send_len;
	msg.msg_iov = &iov;
	msg.desc = &slot->desc;
	msg.iov_count = 1;
	msg.addr = tqpair->peer_fi_addr;
	msg.context = slot;
	msg.data = tag;
	{
		int spins = 0;
		do {
			rc = fi_sendmsg(tqpair->ep, &msg, FI_REMOTE_CQ_DATA | FI_COMPLETION);
			if (rc != -FI_EAGAIN) {
				break;
			}
			nvme_ofi_drain_cq(tqpair, tqpair->num_slots);
		} while (++spins < NVME_OFI_SEND_SPIN_MAX);
	}
	if (rc != 0) {
		if (rc != -FI_EAGAIN) {
			SPDK_ERRLOG("ofi host: fi_sendmsg: %s\n", fi_strerror(-(int)rc));
		}
		TAILQ_INSERT_HEAD(&tqpair->send_free, slot, link);	/* return the slot */
		nvme_ofi_submit_rollback(tqpair, cid);
		return rc == -FI_EAGAIN ? -EAGAIN : (int)rc;
	}

	slot->cid = cid;
	tqpair->req_table[cid] = req;
	spdk_trace_record(TRACE_NVME_OFI_HOST_SUBMIT, tqpair->qpair.id, 0, (uintptr_t)req,
			  (uintptr_t)req->cb_arg, (uint32_t)cid);
	return 0;
}

static int32_t
nvme_ofi_qpair_process_completions(struct spdk_nvme_qpair *qpair, uint32_t max_completions)
{
	struct nvme_ofi_qpair *tqpair = nvme_ofi_qpair(qpair);

	/* While connecting, process_completions IS the connect driver: advance the
	 * sideband handshake + EP + Fabrics CONNECT one round per call. nvme_fabric
	 * _qpair_connect_poll re-enters process_completions; the in_connect_poll
	 * guard breaks that recursion (connect_poll drains the CQ itself). */
	if (nvme_qpair_get_state(qpair) == NVME_QPAIR_CONNECTING) {
		int rc;

		if (tqpair->in_connect_poll) {
			return 0;
		}
		tqpair->in_connect_poll = true;
		rc = nvme_ofi_connect_poll(tqpair);
		tqpair->in_connect_poll = false;
		if (rc < 0) {
			return rc;
		}
		return 0;
	}

	return nvme_ofi_drain_cq(tqpair, max_completions);
}

/* -------------------------------------------------------------------------- */
/* misc qpair ops (stubs where OFI needs nothing special)                     */
/* -------------------------------------------------------------------------- */

static void
nvme_ofi_qpair_abort_reqs(struct spdk_nvme_qpair *qpair, uint32_t dnr)
{
	struct nvme_ofi_qpair *tqpair = nvme_ofi_qpair(qpair);
	struct spdk_nvme_cpl cpl = {0};
	uint32_t i;

	cpl.status.sct = SPDK_NVME_SCT_GENERIC;
	cpl.status.sc = SPDK_NVME_SC_ABORTED_BY_REQUEST;
	cpl.status.dnr = dnr ? 1 : 0;

	for (i = 0; i < tqpair->req_table_sz; i++) {
		if (tqpair->req_table[i] != NULL) {
			nvme_ofi_complete_request(tqpair, (uint16_t)i, &cpl, NULL, 0);
		}
	}
}

static int
nvme_ofi_qpair_reset(struct spdk_nvme_qpair *qpair)
{
	/* No-op, matching nvme_tcp/nvme_rdma. The core calls this from
	 * NVME_CTRLR_STATE_RESET_ADMIN_QUEUE and then transitions straight to
	 * IDENTIFY *without* reconnecting — so the admin qpair (and its EP) must
	 * stay up. Disconnecting here tears down the EP and makes the very next
	 * IDENTIFY submit fail with -ENXIO (controller init -> ERROR). */
	return 0;
}

static int
nvme_ofi_qpair_iterate_requests(struct spdk_nvme_qpair *qpair,
				int (*iter_fn)(struct nvme_request *req, void *arg), void *arg)
{
	struct nvme_ofi_qpair *tqpair = nvme_ofi_qpair(qpair);
	uint32_t i;
	int rc;

	for (i = 0; i < tqpair->req_table_sz; i++) {
		if (tqpair->req_table[i] != NULL) {
			rc = iter_fn(tqpair->req_table[i], arg);
			if (rc != 0) {
				return rc;
			}
		}
	}
	return 0;
}

static void
nvme_ofi_admin_qpair_abort_aers(struct spdk_nvme_qpair *qpair)
{
	struct nvme_ofi_qpair *tqpair = nvme_ofi_qpair(qpair);
	struct spdk_nvme_cpl cpl = {0};
	uint32_t i;

	cpl.status.sct = SPDK_NVME_SCT_GENERIC;
	cpl.status.sc = SPDK_NVME_SC_ABORTED_SQ_DELETION;
	for (i = 0; i < tqpair->req_table_sz; i++) {
		struct nvme_request *req = tqpair->req_table[i];
		if (req != NULL && req->cmd.opc == SPDK_NVME_OPC_ASYNC_EVENT_REQUEST) {
			nvme_ofi_complete_request(tqpair, (uint16_t)i, &cpl, NULL, 0);
		}
	}
}

/* -------------------------------------------------------------------------- */
/* poll group (minimal: the core drives each qpair's CQ directly)             */
/* -------------------------------------------------------------------------- */

static struct spdk_nvme_transport_poll_group *
nvme_ofi_poll_group_create(void)
{
	struct spdk_nvme_transport_poll_group *group;

	group = calloc(1, sizeof(*group));
	if (group == NULL) {
		return NULL;
	}
	STAILQ_INIT(&group->connected_qpairs);
	STAILQ_INIT(&group->disconnected_qpairs);
	return group;
}

static int
nvme_ofi_poll_group_add(struct spdk_nvme_transport_poll_group *group,
			struct spdk_nvme_qpair *qpair)
{
	qpair->poll_group = group;
	return 0;
}

/* Connect/disconnect within a poll group. The real connect is initiated by
 * ctrlr_connect_qpair and driven by poll_group_process_completions (which calls
 * qpair_process_completions -> connect_poll while CONNECTING); each qpair owns
 * its own EP+CQ and sideband sock, so there is no shared sock-group membership
 * to maintain here. Both are no-ops (matching nvme_tcp_poll_group_connect_qpair).
 * NOTE: without poll_group_connect_qpair the core dereferences a NULL op pointer
 * when connecting an IO qpair (nvme_transport.c:852). */
static int
nvme_ofi_poll_group_connect_qpair(struct spdk_nvme_qpair *qpair)
{
	return 0;
}

static int
nvme_ofi_poll_group_disconnect_qpair(struct spdk_nvme_qpair *qpair)
{
	return 0;
}

static int
nvme_ofi_poll_group_remove(struct spdk_nvme_transport_poll_group *group,
			   struct spdk_nvme_qpair *qpair)
{
	qpair->poll_group = NULL;
	return 0;
}

static int64_t
nvme_ofi_poll_group_process_completions(struct spdk_nvme_transport_poll_group *group,
					uint32_t completions_per_qpair,
					spdk_nvme_disconnected_qpair_cb disconnected_qpair_cb)
{
	struct spdk_nvme_qpair *qpair, *tmp;
	int64_t total = 0, rc;

	/* Each qpair owns its CQ; drain every connected qpair. The core maintains
	 * the connected_qpairs membership. */
	STAILQ_FOREACH_SAFE(qpair, &group->connected_qpairs, poll_group_stailq, tmp) {
		rc = nvme_ofi_qpair_process_completions(qpair, completions_per_qpair);
		if (rc > 0) {
			total += rc;
		}
	}
	return total;
}

static int
nvme_ofi_poll_group_destroy(struct spdk_nvme_transport_poll_group *group)
{
	free(group);
	return 0;
}

/* -------------------------------------------------------------------------- */
/* Ops table + registration                                                   */
/* -------------------------------------------------------------------------- */

const struct spdk_nvme_transport_ops nvme_ofi_ops = {
	.name = "OFI",
	.type = SPDK_NVME_TRANSPORT_CUSTOM_FABRICS,

	.ctrlr_construct = nvme_ofi_ctrlr_construct,
	.ctrlr_scan = nvme_fabric_ctrlr_scan,
	.ctrlr_destruct = nvme_ofi_ctrlr_destruct,
	.ctrlr_enable = nvme_ofi_ctrlr_enable,

	.ctrlr_set_reg_4 = nvme_fabric_ctrlr_set_reg_4,
	.ctrlr_set_reg_8 = nvme_fabric_ctrlr_set_reg_8,
	.ctrlr_get_reg_4 = nvme_fabric_ctrlr_get_reg_4,
	.ctrlr_get_reg_8 = nvme_fabric_ctrlr_get_reg_8,
	.ctrlr_set_reg_4_async = nvme_fabric_ctrlr_set_reg_4_async,
	.ctrlr_set_reg_8_async = nvme_fabric_ctrlr_set_reg_8_async,
	.ctrlr_get_reg_4_async = nvme_fabric_ctrlr_get_reg_4_async,
	.ctrlr_get_reg_8_async = nvme_fabric_ctrlr_get_reg_8_async,

	.ctrlr_get_max_xfer_size = nvme_ofi_ctrlr_get_max_xfer_size,
	.ctrlr_get_max_sges = nvme_ofi_ctrlr_get_max_sges,
	.ctrlr_get_memory_domains = nvme_ofi_ctrlr_get_memory_domains,

	.ctrlr_create_io_qpair = nvme_ofi_ctrlr_create_io_qpair,
	.ctrlr_delete_io_qpair = nvme_ofi_ctrlr_delete_io_qpair,
	.ctrlr_connect_qpair = nvme_ofi_ctrlr_connect_qpair,
	.ctrlr_disconnect_qpair = nvme_ofi_ctrlr_disconnect_qpair,

	.qpair_abort_reqs = nvme_ofi_qpair_abort_reqs,
	.qpair_reset = nvme_ofi_qpair_reset,
	.qpair_submit_request = nvme_ofi_qpair_submit_request,
	.qpair_process_completions = nvme_ofi_qpair_process_completions,
	.qpair_iterate_requests = nvme_ofi_qpair_iterate_requests,
	.admin_qpair_abort_aers = nvme_ofi_admin_qpair_abort_aers,

	.poll_group_create = nvme_ofi_poll_group_create,
	.poll_group_connect_qpair = nvme_ofi_poll_group_connect_qpair,
	.poll_group_disconnect_qpair = nvme_ofi_poll_group_disconnect_qpair,
	.poll_group_add = nvme_ofi_poll_group_add,
	.poll_group_remove = nvme_ofi_poll_group_remove,
	.poll_group_process_completions = nvme_ofi_poll_group_process_completions,
	.poll_group_destroy = nvme_ofi_poll_group_destroy,
};

SPDK_NVME_TRANSPORT_REGISTER(ofi, &nvme_ofi_ops);
SPDK_LOG_REGISTER_COMPONENT(nvme_ofi)

/* Host (initiator) tracepoints — Phase 2 of P1g observability. Separate group
 * 0x13 / owner 0x32 / object 0x70 from the target (lib/nvmf, group 0x7): nvmf_tgt
 * links both lib/nvmf and lib/nvme, so the IDs must not collide. Mirrors nvme_tcp.c
 * (owner_type + object registered globally; per-event owner_id = qpair->id, no
 * per-qpair owner registration). spdk_trace_record early-outs when the group is
 * disabled, so these are near-free on the hot path by default. */
static void
nvme_ofi_host_trace(void)
{
	struct spdk_trace_tpoint_opts opts[] = {
		{
			"OFI_H_QP_CREATE", TRACE_NVME_OFI_HOST_QP_CREATE,
			OWNER_TYPE_NVME_OFI_HOST_QP, OBJECT_NONE, 0,
			{	{ "qsize", SPDK_TRACE_ARG_TYPE_INT, 4 }, }
		},
		{
			"OFI_H_QP_DESTROY", TRACE_NVME_OFI_HOST_QP_DESTROY,
			OWNER_TYPE_NVME_OFI_HOST_QP, OBJECT_NONE, 0,
			{	{ "qid", SPDK_TRACE_ARG_TYPE_INT, 4 }, }
		},
		{
			"OFI_H_SUBMIT", TRACE_NVME_OFI_HOST_SUBMIT,
			OWNER_TYPE_NVME_OFI_HOST_QP, OBJECT_NVME_OFI_HOST_REQ, 1,
			{	{ "ctx", SPDK_TRACE_ARG_TYPE_PTR, 8 },
				{ "cid", SPDK_TRACE_ARG_TYPE_INT, 4 }, }
		},
		{
			"OFI_H_COMPLETE", TRACE_NVME_OFI_HOST_COMPLETE,
			OWNER_TYPE_NVME_OFI_HOST_QP, OBJECT_NVME_OFI_HOST_REQ, 0,
			{	{ "ctx", SPDK_TRACE_ARG_TYPE_PTR, 8 },
				{ "cid", SPDK_TRACE_ARG_TYPE_INT, 4 },
				{ "sc", SPDK_TRACE_ARG_TYPE_INT, 4 }, }
		},
		{
			"OFI_H_CQ_ERROR", TRACE_NVME_OFI_HOST_CQ_ERROR,
			OWNER_TYPE_NVME_OFI_HOST_QP, OBJECT_NONE, 0,
			{	{ "err", SPDK_TRACE_ARG_TYPE_INT, 4 }, }
		},
		{
			"OFI_H_CONNECT", TRACE_NVME_OFI_HOST_CONNECT,
			OWNER_TYPE_NVME_OFI_HOST_QP, OBJECT_NONE, 0,
			{	{ "qid", SPDK_TRACE_ARG_TYPE_INT, 4 }, }
		},
		{
			"OFI_H_MR_REG", TRACE_NVME_OFI_HOST_MR_REG,
			OWNER_TYPE_NVME_OFI_HOST_QP, OBJECT_NONE, 0,
			{	{ "len", SPDK_TRACE_ARG_TYPE_INT, 4 }, }
		},
	};

	spdk_trace_register_object(OBJECT_NVME_OFI_HOST_REQ, 'R');
	spdk_trace_register_owner_type(OWNER_TYPE_NVME_OFI_HOST_QP, 'h');
	spdk_trace_register_description_ext(opts, SPDK_COUNTOF(opts));
}
SPDK_TRACE_REGISTER_FN(nvme_ofi_host_trace, "nvme_ofi_host", TRACE_GROUP_NVME_OFI_HOST)
