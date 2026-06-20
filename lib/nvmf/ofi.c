/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 Andong Hu. All rights reserved.
 *
 *   NVMe-oF OFI (libfabric) target transport — P1c-1 (EP bring-up + qpair).
 *
 *   P1a registers/creates/listens; P1b accepts a sideband TCP connection and
 *   runs the §5.3 handshake. P1c-1 brings up the real libfabric endpoint:
 *   on ADDR_EXCHANGE the target selects a poll group, hops to that pg's thread
 *   to create/bind/enable the EP (P0-1 order), fi_getname's the real local
 *   address and fi_av_insert's the peer, then sends that real address back and,
 *   on handshake completion, hands the qpair to nvmf via spdk_nvmf_tgt_new_qpair
 *   — steered onto the EP's pg thread by get_optimal_poll_group.
 *
 *   Threading (design §3.5/§8.1): one fid_domain + fid_av + dual fid_cq per
 *   poll group (== per SPDK thread, since there is one OFI poll group per thread
 *   per transport). The EP for each qpair is created on, and bound to the CQ of,
 *   that poll group — the CQ bind MUST precede fi_enable (P0-1), so the target
 *   pg is selected before the EP is created.
 *
 *   Out of scope (P1c-2): the V1 MSG NVMe-capsule data path (recv pre-post,
 *   poll_group_poll CQ drain + command decode, req_complete fi_send). The EP is
 *   up and addressable here; no NVMe IO flows yet.
 *
 *   Design: docs/design/ofi_transport_design.md (structs §3.2, callbacks §3.3,
 *   libfabric lifecycle §3.4, sideband §5.2/§5.3). The fi_getinfo hints are
 *   runtime-adaptive per provider (§3.4.1 / v1.3 fix) — NOT hardcoded to CXI.
 */

#include "spdk/stdinc.h"
#include "spdk/sock.h"
#include "spdk/thread.h"
#include "spdk/nvme.h"
#include "spdk/nvmf_transport.h"
#include "spdk/string.h"
#include "spdk/util.h"
#include "spdk/log.h"

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>		/* fi_getname */
#include <rdma/fi_rma.h>		/* fi_read / fi_write (V2 target-initiated RMA) */
#include <rdma/fi_errno.h>

#include "nvmf_internal.h"
#include "transport.h"
#include "ofi_internal.h"

/* -------------------------------------------------------------------------- */
/* Defaults                                                                   */
/* -------------------------------------------------------------------------- */

#define NVMF_OFI_DEFAULT_MAX_IO_QUEUE_DEPTH	128
#define NVMF_OFI_DEFAULT_MAX_ADMIN_QUEUE_DEPTH	128
#define NVMF_OFI_DEFAULT_MAX_QPAIRS_PER_CTRLR	129
#define NVMF_OFI_DEFAULT_IN_CAPSULE_DATA_SIZE	4096
#define NVMF_OFI_DEFAULT_MAX_IO_SIZE		131072
#define NVMF_OFI_DEFAULT_IO_UNIT_SIZE		131072
#define NVMF_OFI_DEFAULT_NUM_SHARED_BUFFERS	511
#define NVMF_OFI_DEFAULT_BUFFER_CACHE_SIZE	UINT32_MAX
#define NVMF_OFI_DEFAULT_ABORT_TIMEOUT_SEC	1

/* libfabric API version we target (installed libfabric is 1.22). */
#define NVMF_OFI_FI_VERSION		FI_VERSION(1, 22)

/* libfabric provider for the OFI data path. Dev-friendly default; overridable
 * via the OFI_PROVIDER env var ("tcp" / "sockets" / "verbs;ofi_rxm" / "cxi"). */
#define NVMF_OFI_DEFAULT_PROVIDER	"tcp"
#define NVMF_OFI_PROVIDER_ENV		"OFI_PROVIDER"

/* Accept poller rate (us) for the sideband listener sock group. */
#define NVMF_OFI_ACCEPT_POLL_RATE_US	SPDK_NVMF_DEFAULT_ACCEPT_POLL_RATE_US

/* Per-connection sideband recv/send scratch. The largest handshake frame is
 * hdr + ADDR_EXCHANGE payload; round up generously. */
#define NVMF_OFI_SB_BUF_SIZE		(sizeof(struct ofi_sb_hdr) + OFI_SB_MAX_ADDR_EXCHANGE_PAYLOAD)

/* Target-side sideband handshake state machine (design §5.3, passive role). */
enum spdk_nvmf_ofi_sb_state {
	OFI_SB_WAIT_HELLO = 0,	/* reading HELLO from host */
	OFI_SB_WAIT_ADDR,	/* HELLO_ACK sent; reading ADDR_EXCHANGE */
	OFI_SB_EP_SETUP,	/* ADDR_EXCHANGE parsed; EP being brought up on pg thread */
	OFI_SB_WAIT_ADDR_ACK,	/* our ADDR_EXCHANGE sent; reading ADDR_ACK */
	OFI_SB_DONE,		/* handshake complete; qpair handed to nvmf */
	OFI_SB_FAILED,		/* protocol/validation error or peer gone */
};

/* Upper bound on a libfabric endpoint address blob (fi_getname). SOCKADDR_IN is
 * 16 bytes, CXI is 8; 256 is generous and bounds the ADDR_EXCHANGE payload. */
#define NVMF_OFI_MAX_EP_ADDR_LEN	256

/* V1 data-path framing (design §6.1) — MUST match the host (lib/nvme/nvme_ofi.c).
 * The CID rides the CQ immediate-data field as a 64-bit tag (cid<<8 | type). */
enum spdk_nvmf_ofi_msg_type {
	SPDK_NVMF_OFI_MSG_SQE	= 1,	/* host->target: 64B SQE [+ WRITE data] */
	SPDK_NVMF_OFI_MSG_CQE	= 4,	/* target->host: 16B CQE [+ READ data]  */
};
#define SPDK_NVMF_OFI_BUILD_TAG(cid, type)	(((uint64_t)(cid) << 8) | (uint64_t)(type))
#define SPDK_NVMF_OFI_TAG_CID(tag)		((uint16_t)(((tag) >> 8) & 0xffff))

/* V1 in-capsule data ceiling (caps a single MSG's payload). */
#define NVMF_OFI_IN_CAPSULE_DATA_SIZE	4096
/* V2 RMA bounce-buffer ceiling: the per-req local buffer the target fi_read's host
 * WRITE data into / fi_write's host READ data from. Bounds a single IO's transfer
 * (design max 128 KiB). Host advertises a keyed SGL; target RMAs into this buffer. */
#define NVMF_OFI_RMA_DATA_SIZE		131072
/* Recv buffer: 64B SQE + in-capsule data. Send buffer: 16B CQE + in-capsule data. */
#define NVMF_OFI_RECV_BUF_SIZE	(sizeof(struct spdk_nvme_cmd) + NVMF_OFI_IN_CAPSULE_DATA_SIZE)
#define NVMF_OFI_SEND_BUF_SIZE	(sizeof(struct spdk_nvme_cpl) + NVMF_OFI_IN_CAPSULE_DATA_SIZE)

/* Forward declaration so create() can reference the ops table. */
const struct spdk_nvmf_transport_ops spdk_nvmf_transport_ofi;

/* -------------------------------------------------------------------------- */
/* Data structures (subset needed for P1a; base struct always first field)    */
/* -------------------------------------------------------------------------- */

struct spdk_nvmf_ofi_transport;

struct spdk_nvmf_ofi_listener {
	struct spdk_nvme_transport_id	trid;
	struct spdk_sock		*listen_sock;	/* TCP sideband listener */
	struct spdk_nvmf_ofi_transport	*transport;	/* back-pointer for accept cb */
	TAILQ_ENTRY(spdk_nvmf_ofi_listener)	link;
};

/*
 * A sideband connection accepted on a listener, BEFORE it becomes a qpair.
 * P1b runs the §5.3 handshake to completion here, then (for now) closes. P1c
 * will, on OFI_SB_DONE, bring up the libfabric EP and call
 * spdk_nvmf_tgt_new_qpair instead of closing.
 *
 * Framing is non-blocking + buffer-and-advance: each readable callback pulls
 * bytes into rx_buf; once a full frame (20-byte hdr, then payload_len bytes) is
 * present we validate + dispatch. This is the prototype's blocking
 * ofi_pp_handshake target branch re-expressed for the reactor.
 */
struct spdk_nvmf_ofi_sb_conn {
	struct spdk_sock		*sock;
	struct spdk_nvmf_ofi_transport	*transport;
	enum spdk_nvmf_ofi_sb_state	state;

	/* rx accumulation */
	uint8_t				rx_buf[NVMF_OFI_SB_BUF_SIZE];
	size_t				rx_off;		/* bytes accumulated */

	/* peer info learned from the handshake */
	char				peer_addr[SPDK_NVMF_TRADDR_MAX_LEN];
	uint16_t			peer_port;
	char				peer_provider[32];
	uint32_t			peer_ep_addr_len;
	char				local_ip[SPDK_NVMF_TRADDR_MAX_LEN];	/* listener IP — bind EP src to it */
	struct spdk_nvme_transport_id	listen_trid;		/* the listener this conn arrived on */
	uint8_t				peer_ep_addr[NVMF_OFI_MAX_EP_ADDR_LEN];

	/* P1c EP bring-up: the qpair (with its EP) is created on the pg thread; the
	 * acceptor thread resumes the handshake when the pg thread reports ready.
	 * local_ep_addr is filled by the pg thread (fi_getname) and read back by the
	 * acceptor thread to populate the ADDR_EXCHANGE reply. */
	struct spdk_nvmf_ofi_qpair	*oqpair;
	struct spdk_thread		*acceptor_thread;
	int				ep_setup_rc;
	uint8_t				local_ep_addr[NVMF_OFI_MAX_EP_ADDR_LEN];
	size_t				local_ep_addr_len;

	TAILQ_ENTRY(spdk_nvmf_ofi_sb_conn)	link;
};

/*
 * One OFI poll group per SPDK thread per transport. It owns the per-thread
 * libfabric domain (FI_THREAD_DOMAIN), the shared AV, and the dual CQ (tx/rx)
 * that every qpair's EP on this thread binds to (design §3.5). Created on the
 * pg thread in poll_group_create; all libfabric objects below are touched only
 * by that thread.
 */
struct spdk_nvmf_ofi_poll_group {
	struct spdk_nvmf_transport_poll_group	group;
	struct spdk_nvmf_ofi_transport		*transport;
	struct spdk_thread			*thread;

	struct fid_domain			*domain;
	struct fid_av				*av;
	struct fid_cq				*cq_tx;
	struct fid_cq				*cq_rx;

	TAILQ_HEAD(, spdk_nvmf_ofi_qpair)	qpairs;
	TAILQ_ENTRY(spdk_nvmf_ofi_poll_group)	link;
};

struct spdk_nvmf_ofi_transport {
	struct spdk_nvmf_transport		transport;	/* must be first */

	struct fid_fabric			*fabric;	/* per-transport libfabric fabric */
	struct fi_info				*info;		/* fi_getinfo result */

	char					provider[32];	/* libfabric provider name */

	/* TCP sideband listeners (one per add_listener). */
	TAILQ_HEAD(, spdk_nvmf_ofi_listener)	listeners;
	pthread_mutex_t				lock;

	/* Accept path: one sock group for all listen socks + the accept poller,
	 * plus the in-flight sideband connections being handshaken. */
	struct spdk_sock_group			*listen_sock_group;
	struct spdk_poller			*accept_poller;
	TAILQ_HEAD(, spdk_nvmf_ofi_sb_conn)	sb_conns;

	/* Poll groups (for get_optimal_poll_group round-robin, P1b+). */
	TAILQ_HEAD(, spdk_nvmf_ofi_poll_group)	poll_groups;
	struct spdk_nvmf_ofi_poll_group		*next_pg;
};

struct spdk_nvmf_ofi_qpair {
	struct spdk_nvmf_qpair			qpair;		/* must be first */
	struct spdk_nvmf_ofi_transport		*transport;
	struct spdk_nvmf_ofi_poll_group		*group;		/* pre-selected pg (steers get_optimal_poll_group) */

	/* libfabric endpoint — created/bound/enabled on group->thread (P0-1). */
	struct fid_ep				*ep;
	fi_addr_t				peer_fi_addr;	/* AV handle for the peer */
	bool					ep_enabled;
	bool					mr_local;

	/* V1 data-path pools (allocated in poll_group_add, on the pg thread). */
	struct spdk_nvmf_ofi_recv_slot		*recv_slots;
	struct spdk_nvmf_ofi_req		*reqs;
	TAILQ_HEAD(, spdk_nvmf_ofi_req)	free_reqs;
	/* Reqs whose target-initiated RMA / CQE send hit -FI_EAGAIN (TX queue full);
	 * retried in poll_group_poll after cq_tx is drained. Each uses the req's `link`
	 * (a req here is out of free_reqs, and is on at most one list at a time). */
	TAILQ_HEAD(, spdk_nvmf_ofi_req)	pending_rma;
	TAILQ_HEAD(, spdk_nvmf_ofi_req)	pending_send;
	uint32_t				num_slots;	/* == queue depth */
	bool					pools_ready;

	struct spdk_nvme_transport_id		peer_trid;
	struct spdk_nvme_transport_id		local_trid;
	struct spdk_nvme_transport_id		listen_trid;

	TAILQ_ENTRY(spdk_nvmf_ofi_qpair)	link;
};

/* A pre-posted recv buffer (one per outstanding command slot). op_context
 * passed to fi_recv points here, so a CQ entry maps back to its qpair. */
struct spdk_nvmf_ofi_recv_slot {
	struct spdk_nvmf_ofi_qpair	*oqpair;
	void				*buf;		/* NVMF_OFI_RECV_BUF_SIZE */
	void				*desc;		/* MR desc (FI_MR_LOCAL) or NULL */
	struct fid_mr			*mr;		/* MR handle when mr_local */
	bool				posted;
};

/*
 * A transport request: embeds the core's spdk_nvmf_request plus the storage for
 * its cmd/rsp and its response send buffer. One per outstanding command slot.
 * On recv, a free req is paired with the recv slot whose buffer holds the
 * command; the slot is held until the response is sent (zero-copy H2C data).
 */
struct spdk_nvmf_ofi_req {
	struct spdk_nvmf_request		req;		/* must be first */
	struct spdk_nvmf_ofi_qpair		*oqpair;
	union nvmf_h2c_msg			cmd_storage;
	union nvmf_c2h_msg			rsp_storage;
	struct spdk_nvmf_ofi_recv_slot		*recv_slot;	/* held during H2C processing */
	void					*send_buf;	/* CQE [+ data] */
	void					*send_desc;
	struct fid_mr				*send_mr;
	void					*data_buf;	/* C2H response buffer (core fills) / V2 RMA bounce */
	void					*data_desc;
	struct fid_mr				*data_mr;
	bool					send_in_flight;

	/* V2 RMA (set per-command from a keyed SGL). When use_rma, the data does NOT
	 * ride the capsule: the target fi_read's it from / fi_write's it to the host's
	 * advertised {rma_addr, rma_key} buffer, with data_buf as the local bounce. */
	bool					use_rma;
	bool					rma_is_read;	/* deferred-RMA direction (fi_read vs fi_write) */
	bool					rma_with_cqe;	/* #46: C2H write folds the CQE as CQ immediate data */
	uint64_t				rma_addr;	/* host buffer addr (vaddr or offset) */
	uint64_t				rma_key;	/* host MR key */
	uint32_t				cqe_len;	/* CQE capsule length for a deferred send */
	TAILQ_ENTRY(spdk_nvmf_ofi_req)		link;
};

/* -------------------------------------------------------------------------- */
/* Runtime-adaptive fi_getinfo (design §3.4.1 / v1.3)                         */
/* -------------------------------------------------------------------------- */

/*
 * addr_format + mr_mode are chosen per provider at runtime. Hardcoding CXI
 * values would filter sockets/tcp/verbs out at fi_getinfo, so the transport
 * could never come up on a dev box — violating the "one code, many providers"
 * promise (design §2.4). Authoritative values come from the returned info, but
 * the hints must be provider-appropriate so the right provider survives the
 * filter.
 */
static int
nvmf_ofi_getinfo(const char *prov, struct fi_info **out_info)
{
	struct fi_info *hints, *info, *i;
	int rc;

	hints = fi_allocinfo();
	if (hints == NULL) {
		SPDK_ERRLOG("fi_allocinfo failed\n");
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
		/* CXI reports CQ_DATA in its caps; request it explicitly there. */
		hints->caps = FI_MSG | FI_RMA | FI_REMOTE_CQ_DATA | FI_READ | FI_WRITE;
		hints->addr_format = FI_ADDR_CXI;
		hints->domain_attr->mr_mode = FI_MR_PROV_KEY | FI_MR_ALLOCATED | FI_MR_ENDPOINT;
	} else {
		/* sockets / tcp / verbs;ofi_rxm (prototype P0a/P0b-proven):
		 *  - FI_READ|FI_WRITE required so ofi_rxm isn't filtered out
		 *    (-FI_ENODATA); a no-op on tcp/sockets/cxi.
		 *  - FI_REMOTE_CQ_DATA is deliberately NOT in caps here: dev providers
		 *    reject it in the hints filter (-FI_ENODATA, P0a finding). CQ_DATA is
		 *    selected at send time via the op-flag and still delivered. */
		hints->caps = FI_MSG | FI_RMA | FI_READ | FI_WRITE;
		hints->addr_format = FI_SOCKADDR_IN;
		hints->domain_attr->mr_mode =
			FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY;
	}

	info = NULL;
	rc = fi_getinfo(NVMF_OFI_FI_VERSION, NULL, NULL, 0, hints, &info);
	fi_freeinfo(hints);
	if (rc != 0) {
		SPDK_ERRLOG("fi_getinfo failed for provider '%s': %s\n", prov, fi_strerror(-rc));
		return rc;
	}

	for (i = info; i != NULL; i = i->next) {
		if (i->fabric_attr->prov_name != NULL &&
		    strcmp(i->fabric_attr->prov_name, prov) == 0) {
			*out_info = fi_dupinfo(i);
			fi_freeinfo(info);
			if (*out_info == NULL) {
				return -ENOMEM;
			}
			return 0;
		}
	}

	fi_freeinfo(info);
	SPDK_ERRLOG("provider '%s' not offered by libfabric\n", prov);
	return -ENOENT;
}

/* -------------------------------------------------------------------------- */
/* opts_init / create / destroy                                               */
/* -------------------------------------------------------------------------- */

static int nvmf_ofi_accept(void *ctx);

static void
nvmf_ofi_opts_init(struct spdk_nvmf_transport_opts *opts)
{
	opts->max_queue_depth = NVMF_OFI_DEFAULT_MAX_IO_QUEUE_DEPTH;
	opts->max_qpairs_per_ctrlr = NVMF_OFI_DEFAULT_MAX_QPAIRS_PER_CTRLR;
	opts->in_capsule_data_size = NVMF_OFI_DEFAULT_IN_CAPSULE_DATA_SIZE;
	opts->max_io_size = NVMF_OFI_DEFAULT_MAX_IO_SIZE;
	opts->io_unit_size = NVMF_OFI_DEFAULT_IO_UNIT_SIZE;
	opts->max_aq_depth = NVMF_OFI_DEFAULT_MAX_ADMIN_QUEUE_DEPTH;
	opts->num_shared_buffers = NVMF_OFI_DEFAULT_NUM_SHARED_BUFFERS;
	opts->buf_cache_size = NVMF_OFI_DEFAULT_BUFFER_CACHE_SIZE;
	opts->dif_insert_or_strip = false;
	opts->abort_timeout_sec = NVMF_OFI_DEFAULT_ABORT_TIMEOUT_SEC;
	opts->transport_specific = NULL;
}

static struct spdk_nvmf_transport *
nvmf_ofi_create(struct spdk_nvmf_transport_opts *opts)
{
	struct spdk_nvmf_ofi_transport *otransport;
	const char *prov;
	int rc;

	otransport = calloc(1, sizeof(*otransport));
	if (otransport == NULL) {
		SPDK_ERRLOG("calloc failed\n");
		return NULL;
	}

	otransport->transport.ops = &spdk_nvmf_transport_ofi;
	TAILQ_INIT(&otransport->listeners);
	TAILQ_INIT(&otransport->sb_conns);
	TAILQ_INIT(&otransport->poll_groups);
	pthread_mutex_init(&otransport->lock, NULL);

	prov = getenv(NVMF_OFI_PROVIDER_ENV);
	if (prov == NULL || prov[0] == '\0') {
		prov = NVMF_OFI_DEFAULT_PROVIDER;
	}
	snprintf(otransport->provider, sizeof(otransport->provider), "%s", prov);

	/* Runtime-adaptive fi_getinfo + per-transport fabric. */
	rc = nvmf_ofi_getinfo(otransport->provider, &otransport->info);
	if (rc != 0) {
		SPDK_ERRLOG("OFI transport create: getinfo failed for provider '%s'\n", otransport->provider);
		goto err_info;
	}

	rc = fi_fabric(otransport->info->fabric_attr, &otransport->fabric, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("fi_fabric failed: %s\n", fi_strerror(-rc));
		goto err_fabric;
	}

	/* Sideband accept: one sock group for all listen socks, polled by the
	 * accept poller. New connections' sideband handshake is driven from the
	 * per-sock data callback registered in listen(). */
	otransport->listen_sock_group = spdk_sock_group_create(NULL);
	if (otransport->listen_sock_group == NULL) {
		SPDK_ERRLOG("spdk_sock_group_create failed\n");
		goto err_group;
	}
	otransport->accept_poller = SPDK_POLLER_REGISTER(nvmf_ofi_accept, otransport,
				    NVMF_OFI_ACCEPT_POLL_RATE_US);
	if (otransport->accept_poller == NULL) {
		SPDK_ERRLOG("accept poller register failed\n");
		goto err_poller;
	}

	SPDK_NOTICELOG("*** OFI Transport Init (provider=%s, addr_format=%s) ***\n",
		       otransport->provider,
		       otransport->info->addr_format == FI_ADDR_CXI ? "CXI" : "SOCKADDR");
	SPDK_INFOLOG(nvmf_ofi, "OFI transport: provider=%s caps=0x%lx mr_mode=0x%lx\n",
		     otransport->provider,
		     (unsigned long)otransport->info->caps,
		     (unsigned long)otransport->info->domain_attr->mr_mode);

	return &otransport->transport;

err_poller:
	spdk_sock_group_close(&otransport->listen_sock_group);
err_group:
	fi_close(&otransport->fabric->fid);
	otransport->fabric = NULL;
err_fabric:
	fi_freeinfo(otransport->info);
	otransport->info = NULL;
err_info:
	pthread_mutex_destroy(&otransport->lock);
	free(otransport);
	return NULL;
}

static void nvmf_ofi_sb_conn_close(struct spdk_nvmf_ofi_sb_conn *conn);

static void
nvmf_ofi_destroy(struct spdk_nvmf_transport *transport,
		 spdk_nvmf_transport_destroy_done_cb cb_fn, void *cb_arg)
{
	struct spdk_nvmf_ofi_transport *otransport =
		SPDK_CONTAINEROF(transport, struct spdk_nvmf_ofi_transport, transport);
	struct spdk_nvmf_ofi_listener *listener, *tmp;
	struct spdk_nvmf_ofi_sb_conn *conn, *ctmp;

	/* Stop accepting + drain in-flight sideband connections first. */
	spdk_poller_unregister(&otransport->accept_poller);
	TAILQ_FOREACH_SAFE(conn, &otransport->sb_conns, link, ctmp) {
		nvmf_ofi_sb_conn_close(conn);
	}

	/* Close any open sideband listeners. */
	pthread_mutex_lock(&otransport->lock);
	TAILQ_FOREACH_SAFE(listener, &otransport->listeners, link, tmp) {
		if (listener->listen_sock != NULL) {
			spdk_sock_group_remove_sock(otransport->listen_sock_group, listener->listen_sock);
			spdk_sock_close(&listener->listen_sock);
		}
		TAILQ_REMOVE(&otransport->listeners, listener, link);
		free(listener);
	}
	pthread_mutex_unlock(&otransport->lock);

	if (otransport->listen_sock_group != NULL) {
		spdk_sock_group_close(&otransport->listen_sock_group);
	}

	if (otransport->fabric != NULL) {
		fi_close(&otransport->fabric->fid);
		otransport->fabric = NULL;
	}
	if (otransport->info != NULL) {
		fi_freeinfo(otransport->info);
		otransport->info = NULL;
	}

	pthread_mutex_destroy(&otransport->lock);
	free(otransport);

	if (cb_fn != NULL) {
		cb_fn(cb_arg);
	}
}

/* -------------------------------------------------------------------------- */
/* listen / stop_listen (TCP sideband socket)                                 */
/* -------------------------------------------------------------------------- */

static void nvmf_ofi_accept_cb(void *ctx, struct spdk_sock_group *group,
			       struct spdk_sock *sock);

static struct spdk_nvmf_ofi_listener *
nvmf_ofi_find_listener(struct spdk_nvmf_ofi_transport *otransport,
		       const struct spdk_nvme_transport_id *trid)
{
	struct spdk_nvmf_ofi_listener *listener;

	TAILQ_FOREACH(listener, &otransport->listeners, link) {
		if (spdk_nvme_transport_id_compare(trid, &listener->trid) == 0) {
			return listener;
		}
	}
	return NULL;
}

static int
nvmf_ofi_listen(struct spdk_nvmf_transport *transport,
		const struct spdk_nvme_transport_id *trid,
		struct spdk_nvmf_listen_opts *opts)
{
	struct spdk_nvmf_ofi_transport *otransport =
		SPDK_CONTAINEROF(transport, struct spdk_nvmf_ofi_transport, transport);
	struct spdk_nvmf_ofi_listener *listener;
	struct spdk_sock_opts sock_opts;
	char *endptr;
	long port;
	int rc;

	port = strtol(trid->trsvcid, &endptr, 10);
	if (*endptr != '\0' || port <= 0 || port > 65535) {
		SPDK_ERRLOG("invalid trsvcid '%s'\n", trid->trsvcid);
		return -EINVAL;
	}

	pthread_mutex_lock(&otransport->lock);
	if (nvmf_ofi_find_listener(otransport, trid) != NULL) {
		pthread_mutex_unlock(&otransport->lock);
		SPDK_NOTICELOG("OFI listener already exists for %s:%s\n", trid->traddr, trid->trsvcid);
		return 0;
	}
	pthread_mutex_unlock(&otransport->lock);

	listener = calloc(1, sizeof(*listener));
	if (listener == NULL) {
		return -ENOMEM;
	}
	listener->trid = *trid;
	listener->transport = otransport;

	spdk_sock_get_default_opts(&sock_opts);
	listener->listen_sock = spdk_sock_listen_ext(trid->traddr, (int)port,
			      opts != NULL ? opts->sock_impl : NULL, &sock_opts);
	if (listener->listen_sock == NULL) {
		SPDK_ERRLOG("spdk_sock_listen_ext failed for %s:%ld: %s\n",
			    trid->traddr, port, spdk_strerror(errno));
		free(listener);
		return -errno;
	}

	/* Add the listen sock to the accept group; nvmf_ofi_accept_cb fires when a
	 * peer connects, accepts it, and starts the sideband handshake. */
	rc = spdk_sock_group_add_sock(otransport->listen_sock_group, listener->listen_sock,
				      nvmf_ofi_accept_cb, listener);
	if (rc != 0) {
		SPDK_ERRLOG("spdk_sock_group_add_sock failed for %s:%ld: %s\n",
			    trid->traddr, port, spdk_strerror(-rc));
		spdk_sock_close(&listener->listen_sock);
		free(listener);
		return rc;
	}

	pthread_mutex_lock(&otransport->lock);
	TAILQ_INSERT_TAIL(&otransport->listeners, listener, link);
	pthread_mutex_unlock(&otransport->lock);

	SPDK_NOTICELOG("OFI transport listening on sideband %s:%s (provider=%s)\n",
		       trid->traddr, trid->trsvcid, otransport->provider);
	return 0;
}

static void
nvmf_ofi_stop_listen(struct spdk_nvmf_transport *transport,
		     const struct spdk_nvme_transport_id *trid)
{
	struct spdk_nvmf_ofi_transport *otransport =
		SPDK_CONTAINEROF(transport, struct spdk_nvmf_ofi_transport, transport);
	struct spdk_nvmf_ofi_listener *listener;

	pthread_mutex_lock(&otransport->lock);
	listener = nvmf_ofi_find_listener(otransport, trid);
	if (listener != NULL) {
		TAILQ_REMOVE(&otransport->listeners, listener, link);
	}
	pthread_mutex_unlock(&otransport->lock);

	if (listener != NULL) {
		if (listener->listen_sock != NULL) {
			spdk_sock_group_remove_sock(otransport->listen_sock_group, listener->listen_sock);
			spdk_sock_close(&listener->listen_sock);
		}
		free(listener);
	}
}

/* -------------------------------------------------------------------------- */
/* Sideband accept + handshake state machine (design §5.3, passive role)      */
/* -------------------------------------------------------------------------- */

/* Close a sideband connection: remove from the accept group, close the sock,
 * unlink, free. Safe to call from the data callback (after which the caller
 * must not touch conn). */
static void
nvmf_ofi_sb_conn_close(struct spdk_nvmf_ofi_sb_conn *conn)
{
	struct spdk_nvmf_ofi_transport *otransport = conn->transport;

	if (conn->sock != NULL) {
		spdk_sock_group_remove_sock(otransport->listen_sock_group, conn->sock);
		spdk_sock_close(&conn->sock);
	}
	TAILQ_REMOVE(&otransport->sb_conns, conn, link);
	free(conn);
}

/* Send a single handshake frame (hdr + optional payload) on the sideband sock.
 * Handshake frames are tiny and bounded; one writev suffices on a fresh socket.
 * Returns 0 on success, negative errno otherwise. */
static int
nvmf_ofi_sb_send(struct spdk_nvmf_ofi_sb_conn *conn, const struct ofi_sb_hdr *hdr,
		 const void *payload, uint32_t payload_len)
{
	struct iovec iov[2];
	int iovcnt = 1;
	ssize_t want, n;

	iov[0].iov_base = (void *)hdr;
	iov[0].iov_len = sizeof(*hdr);
	want = sizeof(*hdr);
	if (payload_len > 0) {
		iov[1].iov_base = (void *)payload;
		iov[1].iov_len = payload_len;
		want += payload_len;
		iovcnt = 2;
	}

	n = spdk_sock_writev(conn->sock, iov, iovcnt);
	if (n != want) {
		SPDK_ERRLOG("sideband send short/failed: %zd of %zd (%s)\n",
			    n, want, n < 0 ? spdk_strerror(-n) : "partial");
		return n < 0 ? (int)n : -EIO;
	}
	return 0;
}

/* Reply with HELLO_ACK / ADDR_ACK / ERROR carrying only a status (no payload). */
static int
nvmf_ofi_sb_send_status(struct spdk_nvmf_ofi_sb_conn *conn, uint16_t msg_type,
			uint32_t status)
{
	struct ofi_sb_hdr hdr;

	ofi_sb_hdr_init(&hdr, msg_type, 0, status);
	return nvmf_ofi_sb_send(conn, &hdr, NULL, 0);
}

/* -------------------------------------------------------------------------- */
/* EP bring-up: cross-thread (acceptor thread <-> pg thread) — design §3.4/§3.5 */
/* -------------------------------------------------------------------------- */

/* Round-robin a target poll group for the next qpair. Caller holds no lock. The
 * selected pg owns the CQ the qpair's EP will bind to, so it must be chosen
 * before the EP is created (CQ bind precedes fi_enable, P0-1). */
static struct spdk_nvmf_ofi_poll_group *
nvmf_ofi_pick_pg(struct spdk_nvmf_ofi_transport *otransport)
{
	struct spdk_nvmf_ofi_poll_group *pg;

	pthread_mutex_lock(&otransport->lock);
	pg = otransport->next_pg;
	if (pg == NULL) {
		pg = TAILQ_FIRST(&otransport->poll_groups);
	}
	if (pg != NULL) {
		otransport->next_pg = TAILQ_NEXT(pg, link);
	}
	pthread_mutex_unlock(&otransport->lock);
	return pg;
}

/* Tear down a qpair's EP + AV entry. Runs on the pg thread (FI_THREAD_DOMAIN). */
static void
nvmf_ofi_ep_teardown(struct spdk_nvmf_ofi_qpair *oqpair)
{
	struct spdk_nvmf_ofi_poll_group *pg = oqpair->group;

	if (oqpair->peer_fi_addr != FI_ADDR_NOTAVAIL && pg != NULL && pg->av != NULL) {
		fi_av_remove(pg->av, &oqpair->peer_fi_addr, 1, 0);
		oqpair->peer_fi_addr = FI_ADDR_NOTAVAIL;
	}
	if (oqpair->ep != NULL) {
		fi_close(&oqpair->ep->fid);
		oqpair->ep = NULL;
	}
}

static void nvmf_ofi_ep_ready(void *ctx);

/* Runs on the pg thread: tear down the EP and free the qpair. Used by failure
 * paths that abandon a qpair whose EP lives on the pg thread, before it was ever
 * handed to nvmf (so qpair_fini will not run for it). */
static void
nvmf_ofi_qpair_ep_destroy_msg(void *ctx)
{
	struct spdk_nvmf_ofi_qpair *oqpair = ctx;

	nvmf_ofi_ep_teardown(oqpair);
	free(oqpair);
}

/*
 * Runs on the pg thread. Create the qpair's EP on the pg's domain, bind the
 * shared AV + the pg's dual CQ, enable, fi_getname the local address, and
 * fi_av_insert the peer. The strict order (bind CQ -> enable -> getname) is the
 * P0-1 / C6 sequence proven in the prototype (ofi_pp_create_ep). On any failure
 * conn->ep_setup_rc is set; either way control hops back to the acceptor thread.
 */
static void
nvmf_ofi_ep_setup_on_pg(void *ctx)
{
	struct spdk_nvmf_ofi_sb_conn *conn = ctx;
	struct spdk_nvmf_ofi_qpair *oqpair = conn->oqpair;
	struct spdk_nvmf_ofi_poll_group *pg = oqpair->group;
	struct spdk_nvmf_ofi_transport *otransport = conn->transport;
	fi_addr_t peer = FI_ADDR_NOTAVAIL;
	size_t addrlen;
	ssize_t ninsert;
	int rc;

	rc = fi_endpoint(pg->domain, otransport->info, &oqpair->ep, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("fi_endpoint failed: %s\n", fi_strerror(-rc));
		goto out;
	}
	/* Bind the EP's source address to the listener's NIC. fi_getinfo(node=NULL)
	 * lets the tcp/sockets provider pick an arbitrary interface (e.g.
	 * 192.168.200.1) the peer cannot reach; pin it to the listen IP
	 * (port 0 = ephemeral). tcp/sockets-only: verbs;ofi_rxm and cxi resolve the
	 * EP address from the device, and forcing a sockaddr source breaks ofi_rxm. */
	if (conn->local_ip[0] != '\0' &&
	    otransport->info->addr_format == FI_SOCKADDR_IN &&
	    (strncmp(otransport->provider, "tcp", 3) == 0 ||
	     strncmp(otransport->provider, "sockets", 7) == 0)) {
		struct sockaddr_in src = {0};
		src.sin_family = AF_INET;
		src.sin_port = 0;
		if (inet_pton(AF_INET, conn->local_ip, &src.sin_addr) == 1) {
			rc = fi_setname(&oqpair->ep->fid, &src, sizeof(src));
			if (rc != 0) {
				SPDK_WARNLOG("fi_setname(%s) failed: %s (continuing)\n",
					     conn->local_ip, fi_strerror(-rc));
			}
		}
	}
	rc = fi_ep_bind(oqpair->ep, &pg->av->fid, 0);
	if (rc != 0) {
		SPDK_ERRLOG("fi_ep_bind(av) failed: %s\n", fi_strerror(-rc));
		goto out;
	}
	rc = fi_ep_bind(oqpair->ep, &pg->cq_tx->fid, FI_TRANSMIT);
	if (rc != 0) {
		SPDK_ERRLOG("fi_ep_bind(cq_tx) failed: %s\n", fi_strerror(-rc));
		goto out;
	}
	rc = fi_ep_bind(oqpair->ep, &pg->cq_rx->fid, FI_RECV);
	if (rc != 0) {
		SPDK_ERRLOG("fi_ep_bind(cq_rx) failed: %s\n", fi_strerror(-rc));
		goto out;
	}
	/* CQ bound -> safe to enable (P0-1: CXI freezes the CQ pointers in enable). */
	rc = fi_enable(oqpair->ep);
	if (rc != 0) {
		SPDK_ERRLOG("fi_enable failed: %s\n", fi_strerror(-rc));
		goto out;
	}
	oqpair->ep_enabled = true;

	/* fi_getname only valid after enable (CXI allocates the PID in enable). */
	addrlen = sizeof(conn->local_ep_addr);
	rc = fi_getname(&oqpair->ep->fid, conn->local_ep_addr, &addrlen);
	if (rc != 0) {
		SPDK_ERRLOG("fi_getname failed: %s (addrlen=%zu)\n", fi_strerror(-rc), addrlen);
		goto out;
	}
	conn->local_ep_addr_len = addrlen;
	if (addrlen >= sizeof(struct sockaddr_in)) {
		struct sockaddr_in *sin = (struct sockaddr_in *)conn->local_ep_addr;
		char ip[INET_ADDRSTRLEN] = {0};
		inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
		SPDK_INFOLOG(nvmf_ofi, "ofi target: local EP sockaddr = %s:%u (fam=%u)\n",
			       ip, ntohs(sin->sin_port), sin->sin_family);
	}

	/* Insert the peer's address (parsed from its ADDR_EXCHANGE) into the AV. */
	ninsert = fi_av_insert(pg->av, conn->peer_ep_addr, 1, &peer, 0, NULL);
	if (ninsert != 1) {
		SPDK_ERRLOG("fi_av_insert failed: %zd\n", ninsert);
		rc = (ninsert < 0) ? (int)ninsert : -EINVAL;
		goto out;
	}
	oqpair->peer_fi_addr = peer;

	SPDK_INFOLOG(nvmf_ofi, "EP up on pg thread %s: local_addr_len=%zu peer_fi_addr=0x%lx\n",
		     spdk_thread_get_name(pg->thread), conn->local_ep_addr_len,
		     (unsigned long)peer);
	rc = 0;

out:
	conn->ep_setup_rc = rc;
	if (rc != 0) {
		nvmf_ofi_ep_teardown(oqpair);
	}
	spdk_thread_send_msg(conn->acceptor_thread, nvmf_ofi_ep_ready, conn);
}

/*
 * Runs on the acceptor thread once the pg thread has brought up the EP. On
 * success send our ADDR_EXCHANGE carrying the real fi_getname address and move
 * to WAIT_ADDR_ACK; on failure tear down and close the sideband.
 */
static void
nvmf_ofi_ep_ready(void *ctx)
{
	struct spdk_nvmf_ofi_sb_conn *conn = ctx;
	struct spdk_nvmf_ofi_transport *otransport = conn->transport;
	uint8_t buf[sizeof(struct ofi_sb_addr) + NVMF_OFI_MAX_EP_ADDR_LEN];
	struct ofi_sb_addr *a = (struct ofi_sb_addr *)buf;
	struct ofi_sb_hdr hdr;
	uint32_t plen;
	int rc;

	if (conn->ep_setup_rc != 0) {
		SPDK_ERRLOG("sideband: EP setup failed (%d), aborting handshake\n", conn->ep_setup_rc);
		nvmf_ofi_sb_send_status(conn, OFI_SB_ERROR, OFI_SB_STAT_ENOMEM);
		free(conn->oqpair);
		conn->oqpair = NULL;
		nvmf_ofi_sb_conn_close(conn);
		return;
	}

	/* ADDR_EXCHANGE: fixed ofi_sb_addr header + our real fi_getname blob. */
	memset(a, 0, sizeof(*a));
	snprintf(a->provider, sizeof(a->provider), "%s", otransport->provider);
	a->ep_addr_len_le = ofi_cpu_to_le32((uint32_t)conn->local_ep_addr_len);
	a->flags_le = ofi_cpu_to_le32(0);	/* V1: no RMA */
	memcpy(buf + sizeof(*a), conn->local_ep_addr, conn->local_ep_addr_len);
	plen = (uint32_t)(sizeof(*a) + conn->local_ep_addr_len);

	ofi_sb_hdr_init(&hdr, OFI_SB_ADDR_EXCHANGE, plen, OFI_SB_STAT_OK);
	rc = nvmf_ofi_sb_send(conn, &hdr, buf, plen);
	if (rc != 0) {
		SPDK_ERRLOG("sideband: failed to send ADDR_EXCHANGE (%d)\n", rc);
		/* qpair's EP must be torn down on the pg thread. */
		spdk_thread_send_msg(conn->oqpair->group->thread,
				     nvmf_ofi_qpair_ep_destroy_msg, conn->oqpair);
		conn->oqpair = NULL;
		nvmf_ofi_sb_conn_close(conn);
		return;
	}
	conn->state = OFI_SB_WAIT_ADDR_ACK;
}

/*
 * Handle one fully-received frame (hdr at rx_buf, payload following) according
 * to the target handshake choreography. Returns:
 *   0  -> frame consumed, stay open (state advanced, or handshake DONE)
 *  <0  -> close the connection (failure)
 */
static int
nvmf_ofi_sb_handle_frame(struct spdk_nvmf_ofi_sb_conn *conn,
			 uint16_t msg_type, uint32_t payload_len)
{
	struct spdk_nvmf_ofi_transport *otransport = conn->transport;
	const uint8_t *payload = conn->rx_buf + sizeof(struct ofi_sb_hdr);
	int rc;

	switch (conn->state) {
	case OFI_SB_WAIT_HELLO: {
		const struct ofi_sb_hello *hello = (const struct ofi_sb_hello *)payload;
		const char *err = NULL;

		if (msg_type != OFI_SB_HELLO || payload_len != sizeof(*hello)) {
			SPDK_WARNLOG("sideband: expected HELLO, got msg_type=%u len=%u\n",
				     msg_type, payload_len);
			nvmf_ofi_sb_send_status(conn, OFI_SB_ERROR, OFI_SB_STAT_EINVAL);
			return -EPROTO;
		}
		if (ofi_sb_hello_validate(hello, &err) != 0) {
			SPDK_WARNLOG("sideband: HELLO rejected (%s)\n", err ? err : "?");
			nvmf_ofi_sb_send_status(conn, OFI_SB_HELLO_ACK, OFI_SB_STAT_EINVAL);
			return -EINVAL;
		}
		SPDK_INFOLOG(nvmf_ofi, "sideband HELLO ok: host_provider='%s' qid=%u\n",
			     hello->host_provider, ofi_le16_to_cpu(hello->qid_le));
		rc = nvmf_ofi_sb_send_status(conn, OFI_SB_HELLO_ACK, OFI_SB_STAT_OK);
		if (rc != 0) {
			return rc;
		}
		conn->state = OFI_SB_WAIT_ADDR;
		return 0;
	}

	case OFI_SB_WAIT_ADDR: {
		const struct ofi_sb_addr *pa = (const struct ofi_sb_addr *)payload;
		struct spdk_nvmf_ofi_poll_group *pg;
		struct spdk_nvmf_ofi_qpair *oqpair;
		uint32_t flags;

		if (msg_type != OFI_SB_ADDR_EXCHANGE || payload_len < sizeof(*pa)) {
			SPDK_WARNLOG("sideband: expected ADDR_EXCHANGE, got msg_type=%u len=%u\n",
				     msg_type, payload_len);
			return -EPROTO;
		}
		/* Parse the peer's endpoint address; it is fi_av_insert'd on the pg thread. */
		snprintf(conn->peer_provider, sizeof(conn->peer_provider), "%.*s",
			 (int)sizeof(conn->peer_provider) - 1, pa->provider);
		conn->peer_ep_addr_len = ofi_le32_to_cpu(pa->ep_addr_len_le);
		flags = ofi_le32_to_cpu(pa->flags_le);
		SPDK_INFOLOG(nvmf_ofi,
			     "sideband ADDR_EXCHANGE: peer provider='%s' ep_addr_len=%u flags=0x%x\n",
			     conn->peer_provider, conn->peer_ep_addr_len, flags);

		if (conn->peer_ep_addr_len == 0 ||
		    conn->peer_ep_addr_len > sizeof(conn->peer_ep_addr) ||
		    payload_len < sizeof(*pa) + conn->peer_ep_addr_len) {
			SPDK_WARNLOG("sideband: bad peer ep_addr_len %u (payload %u)\n",
				     conn->peer_ep_addr_len, payload_len);
			nvmf_ofi_sb_send_status(conn, OFI_SB_ERROR, OFI_SB_STAT_EINVAL);
			return -EPROTO;
		}
		memcpy(conn->peer_ep_addr, payload + sizeof(*pa), conn->peer_ep_addr_len);

		/* Select the target poll group NOW (its CQ must be bound before the EP is
		 * enabled, P0-1), allocate the qpair, and bring up the EP on that pg's
		 * thread. The handshake resumes in nvmf_ofi_ep_ready once it is up. */
		pg = nvmf_ofi_pick_pg(otransport);
		if (pg == NULL) {
			SPDK_ERRLOG("sideband: no poll groups available for qpair\n");
			nvmf_ofi_sb_send_status(conn, OFI_SB_ERROR, OFI_SB_STAT_ETRANSIENT);
			return -EAGAIN;
		}

		oqpair = calloc(1, sizeof(*oqpair));
		if (oqpair == NULL) {
			nvmf_ofi_sb_send_status(conn, OFI_SB_ERROR, OFI_SB_STAT_ENOMEM);
			return -ENOMEM;
		}
		oqpair->transport = otransport;
		oqpair->group = pg;
		oqpair->peer_fi_addr = FI_ADDR_NOTAVAIL;
		oqpair->qpair.transport = &otransport->transport;

		conn->oqpair = oqpair;
		conn->acceptor_thread = spdk_get_thread();
		conn->state = OFI_SB_EP_SETUP;
		spdk_thread_send_msg(pg->thread, nvmf_ofi_ep_setup_on_pg, conn);
		return 0;
	}

	case OFI_SB_WAIT_ADDR_ACK: {
		struct spdk_nvmf_ofi_qpair *oqpair = conn->oqpair;

		if (msg_type != OFI_SB_ADDR_ACK) {
			SPDK_WARNLOG("sideband: expected ADDR_ACK, got msg_type=%u\n", msg_type);
			return -EPROTO;
		}
		/* Send our ADDR_ACK to close the dual-ACK (design §5.3). */
		rc = nvmf_ofi_sb_send_status(conn, OFI_SB_ADDR_ACK, OFI_SB_STAT_OK);
		if (rc != 0) {
			return rc;
		}
		conn->state = OFI_SB_DONE;
		SPDK_NOTICELOG("sideband handshake complete: peer %s:%u provider='%s' ep_addr_len=%u\n",
			       conn->peer_addr, conn->peer_port,
			       conn->peer_provider, conn->peer_ep_addr_len);

		/* Fill the qpair's trids, then hand it to nvmf. get_optimal_poll_group
		 * steers it onto oqpair->group (the EP's CQ thread). The sideband sock
		 * stays open for future keepalive/teardown (P2); it is no longer driven. */
		snprintf(oqpair->peer_trid.traddr, sizeof(oqpair->peer_trid.traddr), "%s", conn->peer_addr);
		snprintf(oqpair->peer_trid.trsvcid, sizeof(oqpair->peer_trid.trsvcid), "%u", conn->peer_port);
		oqpair->peer_trid.trtype = SPDK_NVME_TRANSPORT_CUSTOM_FABRICS;
		oqpair->peer_trid.adrfam = SPDK_NVMF_ADRFAM_IPV4;
		/* listen_trid MUST be the listener's trid (192.168.200.41:4421) so the
		 * core's listener-access check matches the subsystem's listener; the
		 * local EP/data path uses a different ephemeral port and is irrelevant
		 * to NVMe-oF addressing. */
		oqpair->listen_trid = conn->listen_trid;
		oqpair->local_trid = conn->listen_trid;

		conn->oqpair = NULL;	/* ownership passes to nvmf / the poll group */
		spdk_nvmf_tgt_new_qpair(otransport->transport.tgt, &oqpair->qpair);
		return 0;
	}

	default:
		SPDK_ERRLOG("sideband: frame in unexpected state %d\n", conn->state);
		return -EPROTO;
	}
}

/*
 * Sideband data callback: drain readable bytes into rx_buf, then process as
 * many complete frames as are buffered. Non-blocking; never loops on the
 * reactor. A frame is complete when we have the 20-byte header plus its
 * payload_len bytes.
 */
static void
nvmf_ofi_sb_data_cb(void *ctx, struct spdk_sock_group *group, struct spdk_sock *sock)
{
	struct spdk_nvmf_ofi_sb_conn *conn = ctx;
	ssize_t n;

	/* Pull whatever is available into the tail of rx_buf. */
	n = spdk_sock_recv(sock, conn->rx_buf + conn->rx_off,
			   sizeof(conn->rx_buf) - conn->rx_off);
	if (n == 0) {
		SPDK_INFOLOG(nvmf_ofi, "sideband: peer closed (state=%d)\n", conn->state);
		nvmf_ofi_sb_conn_close(conn);
		return;
	}
	if (n < 0) {
		if (n == -EAGAIN) {
			return;
		}
		SPDK_INFOLOG(nvmf_ofi, "sideband recv error %zd (%s)\n", n, spdk_strerror(-n));
		nvmf_ofi_sb_conn_close(conn);
		return;
	}
	conn->rx_off += n;

	/* Process every complete frame currently buffered. */
	for (;;) {
		struct ofi_sb_hdr *hdr;
		uint16_t msg_type;
		uint32_t payload_len, status;
		size_t frame_len;
		int rc;

		/* While the EP is being brought up on the pg thread, defer: the next
		 * sideband frame (ADDR_ACK) cannot legitimately arrive until we have
		 * sent our ADDR_EXCHANGE in nvmf_ofi_ep_ready. After DONE the sideband
		 * is idle (keepalive/teardown is P2), so stop processing too. */
		if (conn->state == OFI_SB_EP_SETUP || conn->state == OFI_SB_DONE) {
			break;
		}
		if (conn->rx_off < sizeof(struct ofi_sb_hdr)) {
			break;	/* header not yet complete */
		}
		hdr = (struct ofi_sb_hdr *)conn->rx_buf;
		if (ofi_sb_hdr_validate(hdr, &msg_type, &payload_len, &status) != 0) {
			/* Malformed: stream desynced, close (design §5.4 rows 6,7). */
			nvmf_ofi_sb_conn_close(conn);
			return;
		}
		frame_len = sizeof(struct ofi_sb_hdr) + payload_len;
		if (frame_len > sizeof(conn->rx_buf)) {
			SPDK_WARNLOG("sideband: frame %zu > buf %zu\n", frame_len, sizeof(conn->rx_buf));
			nvmf_ofi_sb_conn_close(conn);
			return;
		}
		if (conn->rx_off < frame_len) {
			break;	/* payload not yet fully arrived */
		}

		rc = nvmf_ofi_sb_handle_frame(conn, msg_type, payload_len);

		/* Consume the frame: shift any trailing bytes to the front. */
		memmove(conn->rx_buf, conn->rx_buf + frame_len, conn->rx_off - frame_len);
		conn->rx_off -= frame_len;

		if (rc < 0) {
			/* Protocol/validation/resource failure: close the sideband. A qpair
			 * mid-EP-setup is freed by its own pg-thread error path. */
			nvmf_ofi_sb_conn_close(conn);
			return;
		}
	}
}

/* A peer connected to a listener: accept it and start the sideband handshake. */
static void
nvmf_ofi_accept_cb(void *ctx, struct spdk_sock_group *group, struct spdk_sock *listen_sock)
{
	struct spdk_nvmf_ofi_listener *listener = ctx;
	struct spdk_nvmf_ofi_transport *otransport = listener->transport;
	struct spdk_sock *sock;
	struct spdk_nvmf_ofi_sb_conn *conn;
	char caddr[SPDK_NVMF_TRADDR_MAX_LEN], saddr[SPDK_NVMF_TRADDR_MAX_LEN];
	uint16_t cport, sport;
	int rc;

	while ((sock = spdk_sock_accept(listen_sock)) != NULL) {
		conn = calloc(1, sizeof(*conn));
		if (conn == NULL) {
			SPDK_ERRLOG("sideband conn alloc failed\n");
			spdk_sock_close(&sock);
			continue;
		}
		conn->sock = sock;
		conn->transport = otransport;
		conn->state = OFI_SB_WAIT_HELLO;
		conn->listen_trid = listener->trid;

		if (spdk_sock_getaddr(sock, saddr, sizeof(saddr), &sport,
				      caddr, sizeof(caddr), &cport) == 0) {
			snprintf(conn->peer_addr, sizeof(conn->peer_addr), "%s", caddr);
			conn->peer_port = cport;
			/* saddr is the listener's local IP — bind the EP's source to it so
			 * the tcp provider picks the right NIC (not an arbitrary interface). */
			snprintf(conn->local_ip, sizeof(conn->local_ip), "%s", saddr);
		}

		rc = spdk_sock_group_add_sock(otransport->listen_sock_group, sock,
					      nvmf_ofi_sb_data_cb, conn);
		if (rc != 0) {
			SPDK_ERRLOG("sideband add_sock failed: %s\n", spdk_strerror(-rc));
			spdk_sock_close(&sock);
			free(conn);
			continue;
		}
		TAILQ_INSERT_TAIL(&otransport->sb_conns, conn, link);
		SPDK_INFOLOG(nvmf_ofi, "sideband: accepted %s:%u\n", conn->peer_addr, conn->peer_port);
	}
}

/* Accept poller: drive the listener sock group. */
static int
nvmf_ofi_accept(void *ctx)
{
	struct spdk_nvmf_ofi_transport *otransport = ctx;
	int rc;

	rc = spdk_sock_group_poll(otransport->listen_sock_group);
	if (rc < 0) {
		SPDK_ERRLOG("sideband sock_group_poll failed: %s\n", spdk_strerror(-rc));
	}
	return rc > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

/* -------------------------------------------------------------------------- */
/* cdata_init / listener_discover                                             */
/* -------------------------------------------------------------------------- */

static void
nvmf_ofi_cdata_init(struct spdk_nvmf_transport *transport,
		    struct spdk_nvmf_subsystem *subsystem,
		    struct spdk_nvmf_ctrlr_data *cdata)
{
	/* P1a: rely on core defaults (keep sgls.supported). Nothing OFI-specific yet. */
}

static void
nvmf_ofi_listener_discover(struct spdk_nvmf_transport *transport,
			   struct spdk_nvme_transport_id *trid,
			   struct spdk_nvmf_discovery_log_page_entry *entry)
{
	/* TODO(P1b): a proper spec trtype for the custom OFI transport; the nvmf
	 * discovery trtype field is uint8_t and CUSTOM_FABRICS (4097) does not fit.
	 * For now copy address fields and leave trtype reserved. */
	entry->trtype = 0; /* reserved */
	entry->adrfam = trid->adrfam;
	spdk_strcpy_pad(entry->trsvcid, trid->trsvcid, sizeof(entry->trsvcid), ' ');
	spdk_strcpy_pad(entry->traddr, trid->traddr, sizeof(entry->traddr), ' ');
}

/* -------------------------------------------------------------------------- */
/* poll group (minimal: allocate + list; no domain/CQ until a qpair arrives)  */
/* -------------------------------------------------------------------------- */

/*
 * Runs on the pg's SPDK thread. Bring up the per-thread libfabric domain + the
 * shared AV + the dual CQ (tx/rx) that every qpair's EP on this thread binds to.
 * FI_AV_MAP / FI_CQ_FORMAT_DATA mirror the prototype (design §3.5.1/§3.5.2): the
 * CQ data field carries the 64-bit V1 tag.
 */
static struct spdk_nvmf_transport_poll_group *
nvmf_ofi_poll_group_create(struct spdk_nvmf_transport *transport,
			   struct spdk_nvmf_poll_group *group)
{
	struct spdk_nvmf_ofi_transport *otransport =
		SPDK_CONTAINEROF(transport, struct spdk_nvmf_ofi_transport, transport);
	struct spdk_nvmf_ofi_poll_group *opgroup;
	struct fi_av_attr av_attr = {0};
	struct fi_cq_attr cq_attr = {0};
	int rc;

	opgroup = calloc(1, sizeof(*opgroup));
	if (opgroup == NULL) {
		SPDK_ERRLOG("calloc failed\n");
		return NULL;
	}
	opgroup->transport = otransport;
	opgroup->thread = group->thread;
	TAILQ_INIT(&opgroup->qpairs);

	rc = fi_domain(otransport->fabric, otransport->info, &opgroup->domain, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("fi_domain failed: %s\n", fi_strerror(-rc));
		goto err;
	}

	av_attr.type = FI_AV_MAP;
	rc = fi_av_open(opgroup->domain, &av_attr, &opgroup->av, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("fi_av_open failed: %s\n", fi_strerror(-rc));
		goto err;
	}

	cq_attr.size = otransport->transport.opts.max_queue_depth * 2;
	cq_attr.format = FI_CQ_FORMAT_DATA;
	cq_attr.wait_obj = FI_WAIT_NONE;
	rc = fi_cq_open(opgroup->domain, &cq_attr, &opgroup->cq_tx, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("fi_cq_open(tx) failed: %s\n", fi_strerror(-rc));
		goto err;
	}
	rc = fi_cq_open(opgroup->domain, &cq_attr, &opgroup->cq_rx, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("fi_cq_open(rx) failed: %s\n", fi_strerror(-rc));
		goto err;
	}

	pthread_mutex_lock(&otransport->lock);
	TAILQ_INSERT_TAIL(&otransport->poll_groups, opgroup, link);
	pthread_mutex_unlock(&otransport->lock);

	SPDK_INFOLOG(nvmf_ofi, "poll group created on thread %s (domain+av+cq up)\n",
		     spdk_thread_get_name(opgroup->thread));
	return &opgroup->group;

err:
	if (opgroup->cq_rx) { fi_close(&opgroup->cq_rx->fid); }
	if (opgroup->cq_tx) { fi_close(&opgroup->cq_tx->fid); }
	if (opgroup->av)    { fi_close(&opgroup->av->fid); }
	if (opgroup->domain) { fi_close(&opgroup->domain->fid); }
	free(opgroup);
	return NULL;
}

static void
nvmf_ofi_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group)
{
	struct spdk_nvmf_ofi_poll_group *opgroup =
		SPDK_CONTAINEROF(group, struct spdk_nvmf_ofi_poll_group, group);
	struct spdk_nvmf_ofi_transport *otransport = opgroup->transport;

	pthread_mutex_lock(&otransport->lock);
	TAILQ_REMOVE(&otransport->poll_groups, opgroup, link);
	if (otransport->next_pg == opgroup) {
		otransport->next_pg = TAILQ_FIRST(&otransport->poll_groups);
	}
	pthread_mutex_unlock(&otransport->lock);

	/* Qpairs (and their EPs) are torn down via qpair_fini before this; close the
	 * shared libfabric objects last, in reverse creation order. */
	if (opgroup->cq_rx)  { fi_close(&opgroup->cq_rx->fid); }
	if (opgroup->cq_tx)  { fi_close(&opgroup->cq_tx->fid); }
	if (opgroup->av)     { fi_close(&opgroup->av->fid); }
	if (opgroup->domain) { fi_close(&opgroup->domain->fid); }

	free(opgroup);
}

/*
 * The qpair's EP was created on, and its CQ bound to, oqpair->group during the
 * sideband handshake (CQ bind precedes fi_enable, P0-1). Steer nvmf to that same
 * poll group so the qpair runs on the thread that owns its CQ.
 */
static struct spdk_nvmf_transport_poll_group *
nvmf_ofi_get_optimal_poll_group(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_ofi_qpair *oqpair =
		SPDK_CONTAINEROF(qpair, struct spdk_nvmf_ofi_qpair, qpair);

	if (oqpair->group == NULL) {
		return NULL;
	}
	return &oqpair->group->group;
}

/* -------------------------------------------------------------------------- */
/* V1 data-path helpers (run on the poll-group thread)                        */
/* -------------------------------------------------------------------------- */

static int
nvmf_ofi_post_recv(struct spdk_nvmf_ofi_qpair *oqpair, struct spdk_nvmf_ofi_recv_slot *slot)
{
	ssize_t rc;

	do {
		rc = fi_recv(oqpair->ep, slot->buf, NVMF_OFI_RECV_BUF_SIZE, slot->desc,
			     oqpair->peer_fi_addr, slot);
	} while (rc == -FI_EAGAIN);

	if (rc != 0) {
		SPDK_ERRLOG("ofi target: fi_recv: %s\n", fi_strerror(-(int)rc));
		return (int)rc;
	}
	slot->posted = true;
	return 0;
}

static void nvmf_ofi_send_cqe(struct spdk_nvmf_ofi_req *oreq, uint32_t send_len);
static void nvmf_ofi_req_release(struct spdk_nvmf_ofi_req *req);

/* Raw RMA issue: fi_read (NVMe WRITE: pull host data into data_buf) or fi_write
 * (NVMe READ: push data_buf to host). op_context is the req so the cq_tx
 * completion (FI_READ / FI_WRITE) maps back. Returns the provider rc verbatim. */
static ssize_t
nvmf_ofi_issue_rma(struct spdk_nvmf_ofi_qpair *oqpair, struct spdk_nvmf_ofi_req *oreq)
{
	size_t len = oreq->req.length;

	if (oreq->rma_is_read) {
		return fi_read(oqpair->ep, oreq->data_buf, len, oreq->data_desc,
			       oqpair->peer_fi_addr, oreq->rma_addr, oreq->rma_key, oreq);
	}
	if (oreq->rma_with_cqe) {
		/* #46: fold the response CQE into the write as CQ immediate data (the
		 * CID tag). The host completes on this single write completion — no
		 * separate CQE MSG (saving a message, a send slot, a completion, and a
		 * host recv slot on every READ). Success is implied; any error takes
		 * the separate-CQE path in req_complete. RC TRANSMIT_COMPLETE (the
		 * local completion below) ⇒ data delivered to host memory (p0b), and
		 * the remote CQ data lands with it. */
		struct spdk_nvme_cpl *rsp = &oreq->rsp_storage.nvme_cpl;
		struct fi_msg_rma msg = {0};
		struct iovec iov = { .iov_base = oreq->data_buf, .iov_len = len };
		struct fi_rma_iov rma = { .addr = oreq->rma_addr, .len = len, .key = oreq->rma_key };

		msg.msg_iov = &iov;
		msg.desc = &oreq->data_desc;
		msg.iov_count = 1;
		msg.addr = oqpair->peer_fi_addr;
		msg.rma_iov = &rma;
		msg.rma_iov_count = 1;
		msg.context = oreq;
		msg.data = SPDK_NVMF_OFI_BUILD_TAG(rsp->cid, SPDK_NVMF_OFI_MSG_CQE);
		return fi_writemsg(oqpair->ep, &msg, FI_REMOTE_CQ_DATA | FI_COMPLETION);
	}
	return fi_write(oqpair->ep, oreq->data_buf, len, oreq->data_desc,
			oqpair->peer_fi_addr, oreq->rma_addr, oreq->rma_key, oreq);
}

/*
 * Post a target-initiated RMA (V2). The op completes asynchronously on cq_tx,
 * where the poll loop resumes the command (exec after read, send CQE after
 * write). On -FI_EAGAIN the TX queue is full: with FI_PROGRESS_MANUAL we cannot
 * spin here (only draining the CQ frees space, and we ARE the poll loop) — so the
 * req is queued and retried in poll_group_poll after cq_tx is drained. Returns 0
 * if issued or deferred, negative on a hard error.
 */
static int
nvmf_ofi_post_rma(struct spdk_nvmf_ofi_qpair *oqpair, struct spdk_nvmf_ofi_req *oreq,
		  bool is_read)
{
	ssize_t rc;

	oreq->rma_is_read = is_read;
	oreq->rma_with_cqe = false;
	rc = nvmf_ofi_issue_rma(oqpair, oreq);
	if (rc == -FI_EAGAIN) {
		TAILQ_INSERT_TAIL(&oqpair->pending_rma, oreq, link);
		return 0;
	}
	if (rc != 0) {
		SPDK_ERRLOG("ofi target: fi_%s: %s\n", is_read ? "read" : "write",
			    fi_strerror(-(int)rc));
		return (int)rc;
	}
	return 0;
}

/* #46: post a C2H write that folds the CQE as CQ immediate data — one operation
 * delivers the read data AND the completion to the host, replacing the old
 * fi_write + fi_sendmsg(CQE) pair. Defers to pending_rma on -FI_EAGAIN like
 * post_rma; the deferred retry re-issues as a writemsg-with-CQE because
 * issue_rma checks rma_with_cqe. */
static int
nvmf_ofi_post_rma_cqe(struct spdk_nvmf_ofi_qpair *oqpair, struct spdk_nvmf_ofi_req *oreq)
{
	ssize_t rc;

	oreq->rma_is_read = false;
	oreq->rma_with_cqe = true;
	rc = nvmf_ofi_issue_rma(oqpair, oreq);
	if (rc == -FI_EAGAIN) {
		TAILQ_INSERT_TAIL(&oqpair->pending_rma, oreq, link);
		return 0;
	}
	if (rc != 0) {
		SPDK_ERRLOG("ofi target: fi_writemsg(CQE): %s\n", fi_strerror(-(int)rc));
		return (int)rc;
	}
	return 0;
}

/* Resume a deferred RMA after its completion: NVMe WRITE (fi_read done) execs the
 * command; NVMe READ (fi_write done) sends the CQE. */
static void
nvmf_ofi_rma_done(struct spdk_nvmf_ofi_req *oreq)
{
	if (oreq->rma_is_read) {
		spdk_nvmf_request_exec(&oreq->req);
	} else {
		/* C2H write done. #46: the CQE was folded into the write as CQ
		 * immediate data, so it is already delivered to the host — no separate
		 * CQE to send. (This is the only C2H-write path now; the separate-CQE
		 * fallback posts a fi_sendmsg, not an RMA write, and completes via the
		 * FI_SEND path.) Recycle the req. */
		nvmf_ofi_req_release(oreq);
	}
}

/* Retry RMAs / CQE sends deferred on a full TX queue. Stops at the first
 * still-EAGAIN op (queue still full) — order is preserved, and the next poll
 * (after more cq_tx drains) makes progress. Called from poll_group_poll between
 * the cq_tx and cq_rx drains. */
static void
nvmf_ofi_drain_pending_rma(struct spdk_nvmf_ofi_poll_group *opgroup)
{
	struct spdk_nvmf_ofi_qpair *oqpair;

	TAILQ_FOREACH(oqpair, &opgroup->qpairs, link) {
		struct spdk_nvmf_ofi_req *oreq;

		while ((oreq = TAILQ_FIRST(&oqpair->pending_rma)) != NULL) {
			ssize_t rc = nvmf_ofi_issue_rma(oqpair, oreq);
			if (rc == -FI_EAGAIN) {
				break;
			}
			TAILQ_REMOVE(&oqpair->pending_rma, oreq, link);
			if (rc != 0) {
				SPDK_ERRLOG("ofi target: deferred fi_%s: %s\n",
					    oreq->rma_is_read ? "read" : "write",
					    fi_strerror(-(int)rc));
				nvmf_ofi_req_release(oreq);
			}
			/* success: completes later via cq_tx (FI_READ/FI_WRITE). */
		}
	}
}

/* Raw CQE send: fi_sendmsg the response capsule (CQE [+ V1 data] already in
 * send_buf), CID in the immediate data. Returns the provider rc. */
static ssize_t
nvmf_ofi_issue_send(struct spdk_nvmf_ofi_req *oreq, uint32_t send_len)
{
	struct spdk_nvmf_ofi_qpair *oqpair = oreq->oqpair;
	struct spdk_nvme_cpl *rsp = &oreq->rsp_storage.nvme_cpl;
	uint64_t tag = SPDK_NVMF_OFI_BUILD_TAG(rsp->cid, SPDK_NVMF_OFI_MSG_CQE);
	struct iovec iov;
	struct fi_msg msg = {0};

	iov.iov_base = oreq->send_buf;
	iov.iov_len = send_len;
	msg.msg_iov = &iov;
	msg.desc = &oreq->send_desc;
	msg.iov_count = 1;
	msg.addr = oqpair->peer_fi_addr;
	msg.context = oreq;
	msg.data = tag;
	return fi_sendmsg(oqpair->ep, &msg, FI_REMOTE_CQ_DATA | FI_COMPLETION);
}

static void
nvmf_ofi_drain_pending_send(struct spdk_nvmf_ofi_poll_group *opgroup)
{
	struct spdk_nvmf_ofi_qpair *oqpair;

	TAILQ_FOREACH(oqpair, &opgroup->qpairs, link) {
		struct spdk_nvmf_ofi_req *oreq;

		while ((oreq = TAILQ_FIRST(&oqpair->pending_send)) != NULL) {
			ssize_t rc = nvmf_ofi_issue_send(oreq, oreq->cqe_len);
			if (rc == -FI_EAGAIN) {
				break;
			}
			TAILQ_REMOVE(&oqpair->pending_send, oreq, link);
			if (rc != 0) {
				SPDK_ERRLOG("ofi target: deferred response fi_sendmsg: %s\n",
					    fi_strerror(-(int)rc));
				nvmf_ofi_req_release(oreq);
			} else {
				oreq->send_in_flight = true;
			}
		}
	}
}

static struct spdk_nvmf_ofi_req *
nvmf_ofi_req_get(struct spdk_nvmf_ofi_qpair *oqpair)
{
	struct spdk_nvmf_ofi_req *req = TAILQ_FIRST(&oqpair->free_reqs);

	if (req == NULL) {
		return NULL;
	}
	TAILQ_REMOVE(&oqpair->free_reqs, req, link);
	memset(&req->cmd_storage, 0, sizeof(req->cmd_storage));
	memset(&req->rsp_storage, 0, sizeof(req->rsp_storage));
	req->req.raw = 0;
	req->recv_slot = NULL;
	req->send_in_flight = false;
	return req;
}

/* Release a request after its response has been sent: re-post the held recv
 * slot and return the req to the free pool. */
static void
nvmf_ofi_req_release(struct spdk_nvmf_ofi_req *req)
{
	struct spdk_nvmf_ofi_qpair *oqpair = req->oqpair;

	if (req->recv_slot != NULL) {
		req->recv_slot->posted = false;
		nvmf_ofi_post_recv(oqpair, req->recv_slot);
		req->recv_slot = NULL;
	}
	TAILQ_INSERT_TAIL(&oqpair->free_reqs, req, link);
}

static void
nvmf_ofi_qpair_free_pools(struct spdk_nvmf_ofi_qpair *oqpair)
{
	uint32_t i;

	for (i = 0; i < oqpair->num_slots && oqpair->recv_slots; i++) {
		if (oqpair->mr_local && oqpair->recv_slots[i].mr) {
			fi_close(&oqpair->recv_slots[i].mr->fid);
		}
		spdk_free(oqpair->recv_slots[i].buf);
	}
	for (i = 0; i < oqpair->num_slots && oqpair->reqs; i++) {
		if (oqpair->mr_local && oqpair->reqs[i].send_mr) {
			fi_close(&oqpair->reqs[i].send_mr->fid);
		}
		if (oqpair->mr_local && oqpair->reqs[i].data_mr) {
			fi_close(&oqpair->reqs[i].data_mr->fid);
		}
		spdk_free(oqpair->reqs[i].send_buf);
		spdk_free(oqpair->reqs[i].data_buf);
	}
	free(oqpair->recv_slots);
	free(oqpair->reqs);
	oqpair->recv_slots = NULL;
	oqpair->reqs = NULL;
	oqpair->pools_ready = false;
}

/* C2H data length from the command's SGL descriptor, clamped to the in-capsule
 * ceiling. The host populates sgl1.unkeyed.length with the transfer size for
 * every data command (matching nvme_tcp_req_init), so this is authoritative for
 * both admin (Identify/GetLog) and IO reads — no opcode special-casing needed. */
static uint32_t
nvmf_ofi_cmd_data_len(const union nvmf_h2c_msg *cmd)
{
	return spdk_min(cmd->nvme_cmd.dptr.sgl1.unkeyed.length, NVMF_OFI_IN_CAPSULE_DATA_SIZE);
}

static int
nvmf_ofi_poll_group_add(struct spdk_nvmf_transport_poll_group *group,
			struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_ofi_poll_group *opgroup =
		SPDK_CONTAINEROF(group, struct spdk_nvmf_ofi_poll_group, group);
	struct spdk_nvmf_ofi_qpair *oqpair =
		SPDK_CONTAINEROF(qpair, struct spdk_nvmf_ofi_qpair, qpair);
	struct spdk_nvmf_ofi_transport *otransport = oqpair->transport;
	uint32_t qd, i;
	int rc;

	/* Must be the pg we pre-selected: the EP's CQ is bound to it. */
	assert(oqpair->group == opgroup);
	qd = otransport->transport.opts.max_queue_depth;
	oqpair->num_slots = qd;
	oqpair->mr_local = (otransport->info->domain_attr->mr_mode & FI_MR_LOCAL) != 0;
	TAILQ_INIT(&oqpair->free_reqs);
	TAILQ_INIT(&oqpair->pending_rma);
	TAILQ_INIT(&oqpair->pending_send);

	oqpair->recv_slots = calloc(qd, sizeof(*oqpair->recv_slots));
	oqpair->reqs = calloc(qd, sizeof(*oqpair->reqs));
	if (oqpair->recv_slots == NULL || oqpair->reqs == NULL) {
		rc = -ENOMEM;
		goto err;
	}
	for (i = 0; i < qd; i++) {
		struct spdk_nvmf_ofi_recv_slot *rs = &oqpair->recv_slots[i];
		struct spdk_nvmf_ofi_req *rq = &oqpair->reqs[i];

		rs->oqpair = oqpair;
		rs->buf = spdk_zmalloc(NVMF_OFI_RECV_BUF_SIZE, 0, NULL,
				       SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
		rq->oqpair = oqpair;
		rq->send_buf = spdk_zmalloc(NVMF_OFI_SEND_BUF_SIZE, 0, NULL,
					    SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
		/* data_buf doubles as the V2 RMA bounce buffer (target is the RMA
		 * initiator), so it is sized to the RMA ceiling and registered FI_READ|
		 * FI_WRITE — FI_READ so fi_read can land into it, FI_WRITE so fi_write can
		 * source from it. */
		rq->data_buf = spdk_zmalloc(NVMF_OFI_RMA_DATA_SIZE, 0, NULL,
					    SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
		if (rs->buf == NULL || rq->send_buf == NULL || rq->data_buf == NULL) {
			rc = -ENOMEM;
			goto err;
		}
		if (oqpair->mr_local) {
			fi_mr_reg(opgroup->domain, rs->buf, NVMF_OFI_RECV_BUF_SIZE,
				  FI_RECV, 0, 0, 0, &rs->mr, NULL);
			fi_mr_reg(opgroup->domain, rq->send_buf, NVMF_OFI_SEND_BUF_SIZE,
				  FI_SEND, 0, 0, 0, &rq->send_mr, NULL);
			fi_mr_reg(opgroup->domain, rq->data_buf, NVMF_OFI_RMA_DATA_SIZE,
				  FI_READ | FI_WRITE, 0, 0, 0, &rq->data_mr, NULL);
			rs->desc = rs->mr ? fi_mr_desc(rs->mr) : NULL;
			rq->send_desc = rq->send_mr ? fi_mr_desc(rq->send_mr) : NULL;
			rq->data_desc = rq->data_mr ? fi_mr_desc(rq->data_mr) : NULL;
		}
		TAILQ_INSERT_TAIL(&oqpair->free_reqs, rq, link);
	}

	/* Pre-post a recv for every slot now that the EP is enabled. */
	for (i = 0; i < qd; i++) {
		rc = nvmf_ofi_post_recv(oqpair, &oqpair->recv_slots[i]);
		if (rc != 0) {
			goto err;
		}
	}
	oqpair->pools_ready = true;

	TAILQ_INSERT_TAIL(&opgroup->qpairs, oqpair, link);
	SPDK_INFOLOG(nvmf_ofi, "qpair added to pg thread %s (ep=%p peer_fi_addr=0x%lx qd=%u)\n",
		     spdk_thread_get_name(opgroup->thread), (void *)oqpair->ep,
		     (unsigned long)oqpair->peer_fi_addr, qd);
	return 0;

err:
	SPDK_ERRLOG("ofi target: poll_group_add pool alloc failed\n");
	nvmf_ofi_qpair_free_pools(oqpair);
	return rc;
}

static int
nvmf_ofi_poll_group_remove(struct spdk_nvmf_transport_poll_group *group,
			   struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_ofi_poll_group *opgroup =
		SPDK_CONTAINEROF(group, struct spdk_nvmf_ofi_poll_group, group);
	struct spdk_nvmf_ofi_qpair *oqpair =
		SPDK_CONTAINEROF(qpair, struct spdk_nvmf_ofi_qpair, qpair);

	TAILQ_REMOVE(&opgroup->qpairs, oqpair, link);
	nvmf_ofi_qpair_free_pools(oqpair);
	return 0;
}

/*
 * Drain the poll group's rx AND tx CQs and dispatch. Recv completions
 * (cq_rx) deliver a command capsule (SQE [+ in-capsule data]); tx completions
 * (cq_tx) mean a response was sent and its req can be recycled — which re-posts
 * the held recv slot. BOTH must be drained: if cq_tx is never read, reqs (and
 * their recv slots) are never recycled and the target starves after num_slots
 * commands. All on the pg thread (FI_THREAD_DOMAIN).
 */
static int
nvmf_ofi_poll_group_poll(struct spdk_nvmf_transport_poll_group *group)
{
	struct spdk_nvmf_ofi_poll_group *opgroup =
		SPDK_CONTAINEROF(group, struct spdk_nvmf_ofi_poll_group, group);
	struct fi_cq_data_entry entry;
	struct fi_cq_err_entry err;
	uint32_t reaped = 0;
	ssize_t rc;

	/* First drain tx completions: recycle reqs sent earlier this (or a prior)
	 * poll, freeing recv slots before we try to receive new commands. */
	while (reaped < 64) {
		rc = fi_cq_read(opgroup->cq_tx, &entry, 1);
		if (rc == -FI_EAGAIN) {
			break;
		}
		if (rc == -FI_EAVAIL) {
			struct spdk_nvmf_ofi_req *oreq;
			memset(&err, 0, sizeof(err));
			fi_cq_readerr(opgroup->cq_tx, &err, 0);
			SPDK_WARNLOG("ofi target: cq_tx error err=%d(%s) prov=%d flags=0x%lx\n",
				     err.err, fi_strerror(err.err), err.prov_errno,
				     (unsigned long)err.flags);
			/* A TX completion errored (a V2 fi_read/fi_write, or a response send).
			 * The fabric path for this qpair is now unreliable — and the owning
			 * req was leaked while the host hung on a CQE that will never arrive
			 * (the old code only logged + broke). Disconnect the qpair, matching
			 * tcp.c's response to a CQ error: the core aborts in-flight requests
			 * with transport errors so hosts complete instead of hanging.
			 * err.op_context is the failed op's context, which is always the
			 * owning req here (issue_rma / issue_send both pass oreq). */
			oreq = err.op_context;
			if (oreq != NULL) {
				spdk_nvmf_qpair_disconnect(&oreq->oqpair->qpair);
			}
			break;
		}
		if (rc < 0) {
			SPDK_ERRLOG("ofi target: cq_tx fi_cq_read: %zd\n", rc);
			break;
		}
		reaped++;
		{
			/* TX completion. Three kinds land on cq_tx, distinguished by the
			 * op flags (the op_context is always the req):
			 *  - FI_READ : a V2 fi_read finished — host WRITE data is now in
			 *    data_buf; exec the command (was deferred at recv time).
			 *  - FI_WRITE: a V2 fi_write finished — host READ data has landed in
			 *    host memory (RC TRANSMIT_COMPLETE ⇒ delivered, p0b_findings);
			 *    now send the CQE.
			 *  - else (FI_SEND): the response MSG was sent — recycle the req
			 *    (this also re-posts the recv slot it was holding). */
			struct spdk_nvmf_ofi_req *oreq = entry.op_context;

			if (entry.flags & (FI_READ | FI_WRITE)) {
				nvmf_ofi_rma_done(oreq);
			} else {
				oreq->send_in_flight = false;
				nvmf_ofi_req_release(oreq);
			}
		}
	}

	/* cq_tx drained ⇒ TX queue space freed; retry any RMA / CQE send deferred on
	 * -FI_EAGAIN before receiving new commands (which may defer more). */
	nvmf_ofi_drain_pending_rma(opgroup);
	nvmf_ofi_drain_pending_send(opgroup);

	/* Then drain rx completions: receive + execute new commands. */
	while (reaped < 64) {
		rc = fi_cq_read(opgroup->cq_rx, &entry, 1);
		if (rc == -FI_EAGAIN) {
			break;
		}
		if (rc == -FI_EAVAIL) {
			struct spdk_nvmf_ofi_recv_slot *slot;
			memset(&err, 0, sizeof(err));
			fi_cq_readerr(opgroup->cq_rx, &err, 0);
			SPDK_WARNLOG("ofi target: cq_rx error err=%d(%s) prov=%d flags=0x%lx len=%zu olen=%zu\n",
				     err.err, fi_strerror(err.err), err.prov_errno,
				     (unsigned long)err.flags, err.len, err.olen);
			/* A recv completion errored — the connection is broken. Disconnect the
			 * qpair so in-flight requests are aborted, not stranded. err.op_context
			 * is the recv buffer's slot (the success path also reads it as the
			 * slot at entry.op_context). */
			slot = err.op_context;
			if (slot != NULL) {
				spdk_nvmf_qpair_disconnect(&slot->oqpair->qpair);
			}
			break;
		}
		if (rc < 0) {
			SPDK_ERRLOG("ofi target: cq_rx fi_cq_read: %zd\n", rc);
			break;
		}
		reaped++;
		{
			struct spdk_nvmf_ofi_recv_slot *slot = entry.op_context;
			struct spdk_nvmf_ofi_qpair *oqpair = slot->oqpair;
			struct spdk_nvmf_ofi_req *req;
			struct spdk_nvme_cmd *sqe;
			uint32_t data_len;

			slot->posted = false;
			req = nvmf_ofi_req_get(oqpair);
			if (req == NULL) {
				SPDK_WARNLOG("ofi target: no free req, dropping cmd\n");
				nvmf_ofi_post_recv(oqpair, slot);
				continue;
			}
			/* Copy the SQE out of the recv buffer (data stays in place for H2C). */
			sqe = (struct spdk_nvme_cmd *)slot->buf;
			memcpy(&req->cmd_storage, sqe, sizeof(req->cmd_storage));
			req->req.cmd = &req->cmd_storage;
			req->req.rsp = &req->rsp_storage;
			req->req.qpair = &oqpair->qpair;
			req->req.xfer = spdk_nvmf_req_get_xfer(&req->req);
			req->recv_slot = slot;	/* hold the slot for zero-copy H2C data */
			req->use_rma = false;
			SPDK_DEBUGLOG(nvmf_ofi, "ofi target: recv cmd opc=0x%x cid=%u len=%zu xfer=%u\n",
				       sqe->opc, sqe->cid, entry.len, req->req.xfer);

			/* V2: a keyed SGL means the host advertised a remote buffer; the data
			 * moves over target-initiated RMA, not in-capsule. (V1's DATA_BLOCK /
			 * TRANSPORT_DATA_BLOCK SGLs keep the in-capsule path below.) The SGL
			 * type field overlays at the same bits across keyed/unkeyed/generic. */
			if (req->req.cmd->nvme_cmd.dptr.sgl1.generic.type ==
			    SPDK_NVME_SGL_TYPE_KEYED_DATA_BLOCK) {
				struct spdk_nvme_sgl_descriptor *sgl =
					&req->req.cmd->nvme_cmd.dptr.sgl1;
				uint32_t rlen = sgl->keyed.length;

				if (rlen > NVMF_OFI_RMA_DATA_SIZE) {
					SPDK_WARNLOG("ofi target: RMA len %u > %d ceiling, clamping\n",
						     rlen, NVMF_OFI_RMA_DATA_SIZE);
					rlen = NVMF_OFI_RMA_DATA_SIZE;
				}
				req->use_rma = true;
				req->rma_addr = sgl->address;
				req->rma_key = sgl->keyed.key;
				req->req.iov[0].iov_base = req->data_buf;
				req->req.iov[0].iov_len = rlen;
				req->req.length = rlen;
				req->req.iovcnt = 1;
				req->req.data_from_pool = false;

				if (req->req.xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
					/* WRITE: pull host data into data_buf, THEN exec (on the
					 * fi_read completion in the cq_tx drain). */
					if (nvmf_ofi_post_rma(oqpair, req, true) != 0) {
						nvmf_ofi_req_release(req);
					}
					continue;
				}
				/* READ (or no-data keyed): exec now; the fi_write to push the
				 * result to the host happens in req_complete. */
				spdk_nvmf_request_exec(&req->req);
				continue;
			}

			if (entry.len > sizeof(struct spdk_nvme_cmd)) {
				/* HOST_TO_CONTROLLER in-capsule data (e.g. CONNECT/WRITE). */
				data_len = entry.len - sizeof(struct spdk_nvme_cmd);
				if (sqe->opc == SPDK_NVME_OPC_FABRIC && data_len >= 1024) {
					const char *cd = (char *)slot->buf + sizeof(struct spdk_nvme_cmd);
					SPDK_DEBUGLOG(nvmf_ofi, "ofi target: connect data subnqn='%s' hostnqn='%s'\n",
						       cd + 256, cd + 512);
				}
				req->req.iov[0].iov_base = (char *)slot->buf + sizeof(struct spdk_nvme_cmd);
				req->req.iov[0].iov_len = data_len;
				req->req.length = data_len;
				req->req.iovcnt = 1;
				req->req.data_from_pool = false;
			} else if (req->req.xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST) {
				/* Response data: provide a buffer the core fills. */
				data_len = nvmf_ofi_cmd_data_len(req->req.cmd);
				req->req.iov[0].iov_base = req->data_buf;
				req->req.iov[0].iov_len = data_len;
				req->req.length = data_len;
				req->req.iovcnt = 1;
				req->req.data_from_pool = false;
			} else {
				req->req.length = 0;
				req->req.iovcnt = 0;
			}

			spdk_nvmf_request_exec(&req->req);
		}
	}

	return reaped;
}

/* -------------------------------------------------------------------------- */
/* qpair / request stubs (no qpair is created until the sideband accepts)     */
/* -------------------------------------------------------------------------- */

static void
nvmf_ofi_qpair_fini(struct spdk_nvmf_qpair *qpair,
		    spdk_nvmf_transport_qpair_fini_cb cb_fn, void *cb_arg)
{
	struct spdk_nvmf_ofi_qpair *oqpair =
		SPDK_CONTAINEROF(qpair, struct spdk_nvmf_ofi_qpair, qpair);

	/* Runs on the pg thread (poll_group_remove already unlinked it). Close the
	 * EP and drop the peer's AV entry. (P1c-2 adds capsule-buffer release.) */
	SPDK_INFOLOG(nvmf_ofi, "qpair_fini: tearing down EP %p on pg thread %s\n",
		     (void *)oqpair->ep, spdk_thread_get_name(spdk_get_thread()));
	nvmf_ofi_ep_teardown(oqpair);
	free(oqpair);

	if (cb_fn != NULL) {
		cb_fn(cb_arg);
	}
}

static int
nvmf_ofi_qpair_get_peer_trid(struct spdk_nvmf_qpair *qpair,
			     struct spdk_nvme_transport_id *trid)
{
	struct spdk_nvmf_ofi_qpair *oqpair =
		SPDK_CONTAINEROF(qpair, struct spdk_nvmf_ofi_qpair, qpair);

	*trid = oqpair->peer_trid;
	return 0;
}

static int
nvmf_ofi_qpair_get_local_trid(struct spdk_nvmf_qpair *qpair,
			      struct spdk_nvme_transport_id *trid)
{
	struct spdk_nvmf_ofi_qpair *oqpair =
		SPDK_CONTAINEROF(qpair, struct spdk_nvmf_ofi_qpair, qpair);

	*trid = oqpair->local_trid;
	return 0;
}

static int
nvmf_ofi_qpair_get_listen_trid(struct spdk_nvmf_qpair *qpair,
			       struct spdk_nvme_transport_id *trid)
{
	struct spdk_nvmf_ofi_qpair *oqpair =
		SPDK_CONTAINEROF(qpair, struct spdk_nvmf_ofi_qpair, qpair);

	*trid = oqpair->listen_trid;
	return 0;
}

/*
 * Send the response capsule (already built in oreq->send_buf: 16B CQE [+ V1 C2H
 * data]). send_len is the capsule length. The CID rides the CQ immediate data as
 * the tag. The req is recycled on the FI_SEND tx completion (poll_group_poll).
 */
static void
nvmf_ofi_send_cqe(struct spdk_nvmf_ofi_req *oreq, uint32_t send_len)
{
	ssize_t rc = nvmf_ofi_issue_send(oreq, send_len);

	if (rc == -FI_EAGAIN) {
		/* TX queue full — defer (see post_rma); retried in poll_group_poll.
		 * Dropping here would lose the CQE and hang the host on that command. */
		oreq->cqe_len = send_len;
		TAILQ_INSERT_TAIL(&oreq->oqpair->pending_send, oreq, link);
		return;
	}
	if (rc != 0) {
		SPDK_ERRLOG("ofi target: response fi_sendmsg: %s\n", fi_strerror(-(int)rc));
		/* Drop the request so the slot can be re-posted. */
		nvmf_ofi_req_release(oreq);
		return;
	}
	oreq->send_in_flight = true;
}

/*
 * The core finished a command. Build the CQE and deliver the response. V1: the
 * CQE [+ C2H data] is a single MSG. V2 (use_rma): a successful CONTROLLER_TO_HOST
 * read first pushes the data to the host over fi_write — and only sends the CQE
 * once that write completes (cq_tx FI_WRITE → nvmf_ofi_send_cqe), so the host
 * sees the CQE strictly after its buffer is filled. H2C / no-data just send the
 * CQE (the WRITE data was already fi_read before exec).
 */
static void
nvmf_ofi_req_complete(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_ofi_req *oreq = SPDK_CONTAINEROF(req, struct spdk_nvmf_ofi_req, req);
	struct spdk_nvme_cpl *rsp = &req->rsp->nvme_cpl;
	uint32_t send_len = sizeof(struct spdk_nvme_cpl);

	SPDK_DEBUGLOG(nvmf_ofi, "ofi target: req_complete cid=%u sct=%u sc=%u xfer=%u len=%u rma=%d\n",
		       rsp->cid, rsp->status.sct, rsp->status.sc, req->xfer, req->length,
		       oreq->use_rma);

	/* Build the CQE into the send buffer. */
	memcpy(oreq->send_buf, rsp, sizeof(*rsp));

	if (oreq->use_rma) {
		/* V2: data (if any) moves over RMA, never in-capsule. */
		if (spdk_nvme_cpl_is_success(rsp) &&
		    req->xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST && req->length > 0 &&
		    req->iovcnt > 0) {
			/* Push the read result AND deliver the CQE in one operation (#46): a
			 * fi_writemsg carrying the CID as CQ immediate data. The host
			 * completes on the write; no separate CQE MSG. On failure, fall
			 * through to the separate-CQE path below. */
			if (nvmf_ofi_post_rma_cqe(oreq->oqpair, oreq) == 0) {
				return;
			}
		}
		nvmf_ofi_send_cqe(oreq, send_len);
		return;
	}

	/* V1: append any C2H data in-capsule. */
	if (spdk_nvme_cpl_is_success(rsp) &&
	    req->xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST && req->length > 0 &&
	    req->iovcnt > 0) {
		uint32_t dlen = spdk_min(req->length, NVMF_OFI_IN_CAPSULE_DATA_SIZE);
		memcpy((char *)oreq->send_buf + sizeof(*rsp), req->iov[0].iov_base, dlen);
		send_len += dlen;
	}
	nvmf_ofi_send_cqe(oreq, send_len);
}

/* Core-initiated free (abort / qpair teardown path). Recycle the req. */
static void
nvmf_ofi_req_free(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_ofi_req *oreq = SPDK_CONTAINEROF(req, struct spdk_nvmf_ofi_req, req);

	if (oreq->send_in_flight) {
		return;	/* will be freed on tx completion */
	}
	nvmf_ofi_req_release(oreq);
}

/* V1 does not use the async iobuf pool (all data is in-capsule / pre-allocated),
 * so this is never driven in the current design — kept as a safe no-op. */
static void
nvmf_ofi_req_get_buffers_done(struct spdk_nvmf_request *req)
{
	SPDK_WARNLOG("ofi target: req_get_buffers_done unexpected (V1 uses in-capsule)\n");
}

static void
nvmf_ofi_qpair_abort_request(struct spdk_nvmf_qpair *qpair,
			     struct spdk_nvmf_request *req)
{
	/* P1c: complete the aborted request. */
	SPDK_DEBUGLOG(nvmf_ofi, "qpair_abort_request stub (P1c)\n");
}

static int
nvmf_ofi_subsystem_add_ns(struct spdk_nvmf_transport *transport,
			  const struct spdk_nvmf_subsystem *subsystem,
			  struct spdk_nvmf_ns *ns)
{
	return 0;
}

static int
nvmf_ofi_listen_associate(struct spdk_nvmf_transport *transport,
			  const struct spdk_nvmf_subsystem *subsystem,
			  const struct spdk_nvme_transport_id *trid)
{
	return 0;
}

/* -------------------------------------------------------------------------- */
/* Ops table + registration                                                   */
/* -------------------------------------------------------------------------- */

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_ofi = {
	.name = "OFI",
	.type = SPDK_NVME_TRANSPORT_CUSTOM_FABRICS,

	.opts_init = nvmf_ofi_opts_init,
	.create = nvmf_ofi_create,
	.destroy = nvmf_ofi_destroy,

	.listen = nvmf_ofi_listen,
	.stop_listen = nvmf_ofi_stop_listen,
	.listen_associate = nvmf_ofi_listen_associate,

	.cdata_init = nvmf_ofi_cdata_init,
	.listener_discover = nvmf_ofi_listener_discover,

	.subsystem_add_ns = nvmf_ofi_subsystem_add_ns,

	.get_optimal_poll_group = nvmf_ofi_get_optimal_poll_group,
	.poll_group_create = nvmf_ofi_poll_group_create,
	.poll_group_destroy = nvmf_ofi_poll_group_destroy,
	.poll_group_add = nvmf_ofi_poll_group_add,
	.poll_group_remove = nvmf_ofi_poll_group_remove,
	.poll_group_poll = nvmf_ofi_poll_group_poll,

	.req_free = nvmf_ofi_req_free,
	.req_complete = nvmf_ofi_req_complete,
	.req_get_buffers_done = nvmf_ofi_req_get_buffers_done,

	.qpair_fini = nvmf_ofi_qpair_fini,
	.qpair_get_local_trid = nvmf_ofi_qpair_get_local_trid,
	.qpair_get_peer_trid = nvmf_ofi_qpair_get_peer_trid,
	.qpair_get_listen_trid = nvmf_ofi_qpair_get_listen_trid,
	.qpair_abort_request = nvmf_ofi_qpair_abort_request,
};

SPDK_NVMF_TRANSPORT_REGISTER(ofi, &spdk_nvmf_transport_ofi);
SPDK_LOG_REGISTER_COMPONENT(nvmf_ofi)
