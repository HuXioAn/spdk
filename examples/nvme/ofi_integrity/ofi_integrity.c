/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2026.  OFI transport data-integrity initiator.
 *
 * Why this exists: spdk_nvme_perf proves the OFI transport runs at line rate
 * with zero errors, but it never *verifies payload contents*. The P1h host-side
 * work (lib/nvme/nvme_ofi.c) added a multi-segment gather/scatter bounce path
 * (SGL payload -> one contiguous bounce -> one keyed SGL -> target RMA; scatter
 * back on read) plus a refcounted MR cache. Those were validated for throughput
 * and error-freedom only. This program closes that gap: it writes a
 * position-dependent pattern through a *multi-segment* writev, reads it back
 * into a *separate* set of buffers via readv, and compares byte-for-byte. Any
 * mis-gather, segment reordering, wrong-offset scatter, or stale-MR corruption
 * shows up as a mismatch with the exact failing offset.
 *
 * Requires a backing store that actually retains data: run against a malloc bdev
 * (NOT null bdev, which discards writes and returns zeros).
 */

#include "spdk/stdinc.h"
#include "spdk/nvme.h"
#include "spdk/env.h"
#include "spdk/string.h"
#include "spdk/log.h"

#define MAX_SEGS	64

static struct spdk_nvme_transport_id g_trid = {};
static struct spdk_nvme_ctrlr	*g_ctrlr;
static struct spdk_nvme_ns	*g_ns;
static struct spdk_nvme_qpair	*g_qpair;
static uint32_t			 g_sector;
static int			 g_fail;	/* total mismatched cases */

/* Position-dependent byte pattern: a function of the byte's GLOBAL logical
 * offset within the IO payload, so a swapped segment or a shifted scatter
 * produces different bytes than expected. Seed varies per case so a stale
 * buffer can never false-pass. */
static inline uint8_t
pat(uint64_t global_off, uint32_t seed)
{
	uint64_t x = global_off * 1103515245ULL + 12345ULL + seed;
	return (uint8_t)(x >> 16);
}

/*
 * Single cb_arg context. CRITICAL: SPDK passes ONE cb_arg
 * (req->payload.contig_or_cb_arg == NVME_PAYLOAD_SGL's 3rd arg) to BOTH the SGL
 * iterator callbacks (reset_sgl_fn/next_sge_fn) AND the completion callback. So
 * the iterator state and the completion state must live in the same struct.
 * Mirrors the contiguous-segment model the transport expects: reset to a byte
 * offset, then walk segments.
 */
struct io_ctx {
	struct iovec	*iovs;
	int		 niov;
	int		 idx;
	uint32_t	 partial;	/* intra-segment offset after a reset */
	int		 done;
	int		 error;
};

static void
reset_sgl(void *cb_arg, uint32_t offset)
{
	struct io_ctx *it = cb_arg;

	it->idx = 0;
	while (it->idx < it->niov && offset >= it->iovs[it->idx].iov_len) {
		offset -= it->iovs[it->idx].iov_len;
		it->idx++;
	}
	it->partial = offset;
}

static int
next_sge(void *cb_arg, void **address, uint32_t *length)
{
	struct io_ctx *it = cb_arg;
	struct iovec *v;

	if (it->idx >= it->niov) {
		return -1;
	}
	v = &it->iovs[it->idx];
	*address = (uint8_t *)v->iov_base + it->partial;
	*length = v->iov_len - it->partial;
	it->partial = 0;
	it->idx++;
	return 0;
}

static void
io_complete(void *arg, const struct spdk_nvme_cpl *cpl)
{
	struct io_ctx *s = arg;

	s->done = 1;
	if (spdk_nvme_cpl_is_error(cpl)) {
		s->error = 1;
		fprintf(stderr, "  IO error status: %s\n",
			spdk_nvme_cpl_get_status_string(&cpl->status));
	}
}

/* Poll the qpair until the IO completes or we time out. */
static int
wait_io(struct io_ctx *s, const char *what)
{
	uint64_t spins = 0;

	while (!s->done) {
		spdk_nvme_qpair_process_completions(g_qpair, 0);
		if (++spins > 2000000000ULL) {
			fprintf(stderr, "  TIMEOUT waiting for %s\n", what);
			return -1;
		}
	}
	return s->error ? -1 : 0;
}

/*
 * One round-trip integrity case: nseg segments of seg_size bytes each, at
 * lba_base. Returns 0 on byte-exact match, 1 on any failure.
 */
static int
run_case(const char *label, int nseg, uint32_t seg_size, uint64_t lba_base, uint32_t seed)
{
	struct iovec wiov[MAX_SEGS], riov[MAX_SEGS];
	struct io_ctx wctx, rctx;
	uint64_t total = (uint64_t)nseg * seg_size;
	uint32_t lba_count = (uint32_t)(total / g_sector);
	int i, rc = 0;
	uint64_t goff;

	printf("[case %-14s] nseg=%-2d seg=%-6u total=%-7lu lba=%lu+%u seed=0x%x ... ",
	       label, nseg, seg_size, (unsigned long)total, (unsigned long)lba_base,
	       lba_count, seed);
	fflush(stdout);

	/* Separate write and read buffers, each segment a distinct DMA allocation
	 * so the scatter path genuinely deals with non-contiguous addresses. */
	for (i = 0; i < nseg; i++) {
		wiov[i].iov_base = spdk_zmalloc(seg_size, 0x1000, NULL,
						SPDK_ENV_NUMA_ID_ANY, SPDK_MALLOC_DMA);
		riov[i].iov_base = spdk_zmalloc(seg_size, 0x1000, NULL,
						SPDK_ENV_NUMA_ID_ANY, SPDK_MALLOC_DMA);
		if (!wiov[i].iov_base || !riov[i].iov_base) {
			printf("FAIL (alloc)\n");
			rc = 1;
			goto out;
		}
		wiov[i].iov_len = riov[i].iov_len = seg_size;
	}

	/* Fill write buffers with the global-offset pattern. */
	goff = 0;
	for (i = 0; i < nseg; i++) {
		uint8_t *b = wiov[i].iov_base;
		uint32_t j;
		for (j = 0; j < seg_size; j++) {
			b[j] = pat(goff + j, seed);
		}
		goff += seg_size;
	}

	/* WRITE (gather path on the host). The single cb_arg (&wctx) is what SPDK
	 * hands to reset_sgl/next_sge AND to io_complete. */
	wctx.iovs = wiov; wctx.niov = nseg; wctx.idx = 0; wctx.partial = 0;
	wctx.done = wctx.error = 0;
	rc = spdk_nvme_ns_cmd_writev(g_ns, g_qpair, lba_base, lba_count,
				     io_complete, &wctx, 0, reset_sgl, next_sge);
	if (rc != 0) {
		printf("FAIL (writev submit rc=%d)\n", rc);
		rc = 1;
		goto out;
	}
	if (wait_io(&wctx, "writev")) {
		printf("FAIL (writev io)\n");
		rc = 1;
		goto out;
	}

	/* READ back into the zeroed read buffers (scatter path on the host). */
	rctx.iovs = riov; rctx.niov = nseg; rctx.idx = 0; rctx.partial = 0;
	rctx.done = rctx.error = 0;
	rc = spdk_nvme_ns_cmd_readv(g_ns, g_qpair, lba_base, lba_count,
				    io_complete, &rctx, 0, reset_sgl, next_sge);
	if (rc != 0) {
		printf("FAIL (readv submit rc=%d)\n", rc);
		rc = 1;
		goto out;
	}
	if (wait_io(&rctx, "readv")) {
		printf("FAIL (readv io)\n");
		rc = 1;
		goto out;
	}

	/* COMPARE byte-for-byte against the expected global-offset pattern. */
	goff = 0;
	for (i = 0; i < nseg; i++) {
		uint8_t *b = riov[i].iov_base;
		uint32_t j;
		for (j = 0; j < seg_size; j++) {
			uint8_t want = pat(goff + j, seed);
			if (b[j] != want) {
				printf("FAIL: mismatch seg=%d off=%u (global=%lu) got=0x%02x want=0x%02x\n",
				       i, j, (unsigned long)(goff + j), b[j], want);
				rc = 1;
				goto out;
			}
		}
		goff += seg_size;
	}

	printf("OK\n");
	rc = 0;
out:
	for (i = 0; i < nseg; i++) {
		if (wiov[i].iov_base) {
			spdk_free(wiov[i].iov_base);
		}
		if (riov[i].iov_base) {
			spdk_free(riov[i].iov_base);
		}
	}
	if (rc) {
		g_fail++;
	}
	return rc;
}

static bool
probe_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
	 struct spdk_nvme_ctrlr_opts *opts)
{
	printf("Attaching to %s\n", trid->traddr);
	return true;
}

static void
attach_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
	  struct spdk_nvme_ctrlr *ctrlr, const struct spdk_nvme_ctrlr_opts *opts)
{
	int nsid;

	g_ctrlr = ctrlr;
	for (nsid = spdk_nvme_ctrlr_get_first_active_ns(ctrlr); nsid != 0;
	     nsid = spdk_nvme_ctrlr_get_next_active_ns(ctrlr, nsid)) {
		struct spdk_nvme_ns *ns = spdk_nvme_ctrlr_get_ns(ctrlr, nsid);
		if (ns && spdk_nvme_ns_is_active(ns)) {
			g_ns = ns;
			break;
		}
	}
	printf("Attached to %s\n", trid->traddr);
}

static int
parse_args(int argc, char **argv, struct spdk_env_opts *env_opts)
{
	int op;

	spdk_nvme_trid_populate_transport(&g_trid, SPDK_NVME_TRANSPORT_PCIE);
	snprintf(g_trid.subnqn, sizeof(g_trid.subnqn), "%s", SPDK_NVMF_DISCOVERY_NQN);

	while ((op = getopt(argc, argv, "i:r:L:")) != -1) {
		switch (op) {
		case 'i':
			env_opts->shm_id = spdk_strtol(optarg, 10);
			break;
		case 'r':
			if (spdk_nvme_transport_id_parse(&g_trid, optarg) != 0) {
				fprintf(stderr, "Error parsing transport address\n");
				return 1;
			}
			break;
		case 'L':
			spdk_log_set_flag(optarg);
			break;
		default:
			fprintf(stderr, "usage: %s -r <trid> [-i shmid] [-L flag]\n", argv[0]);
			return 1;
		}
	}
	return 0;
}

int
main(int argc, char **argv)
{
	struct spdk_env_opts opts;
	uint64_t lba = 0;
	int rc;

	opts.opts_size = sizeof(opts);
	spdk_env_opts_init(&opts);
	rc = parse_args(argc, argv, &opts);
	if (rc != 0) {
		return rc;
	}
	opts.name = "ofi_integrity";
	if (spdk_env_init(&opts) < 0) {
		fprintf(stderr, "Unable to initialize SPDK env\n");
		return 1;
	}

	printf("Probing %s ...\n", g_trid.traddr);
	rc = spdk_nvme_probe(&g_trid, NULL, probe_cb, attach_cb, NULL);
	if (rc != 0 || g_ctrlr == NULL) {
		fprintf(stderr, "probe/attach failed\n");
		rc = 1;
		goto exit;
	}
	if (g_ns == NULL) {
		fprintf(stderr, "no active namespace found\n");
		rc = 1;
		goto exit;
	}

	g_sector = spdk_nvme_ns_get_sector_size(g_ns);
	g_qpair = spdk_nvme_ctrlr_alloc_io_qpair(g_ctrlr, NULL, 0);
	if (g_qpair == NULL) {
		fprintf(stderr, "alloc_io_qpair failed\n");
		rc = 1;
		goto exit;
	}
	printf("Namespace sector=%u bytes, max_xfer=%u\n", g_sector,
	       spdk_nvme_ns_get_max_io_xfer_size(g_ns));
	printf("--- OFI multi-segment data-integrity sweep ---\n");

	/* 1-seg SGL: exercises the bounce path at its minimum (still reset_sgl_fn
	 * != NULL, so it's the SGL branch, not the zero-copy contig branch). */
	run_case("sgl-1seg",   1,  4096, lba, 0x11);  lba += 8;
	run_case("sgl-2seg",   2,  4096, lba, 0x22);  lba += 16;
	run_case("sgl-2x512",  2,   512, lba, 0x23);  lba += 8;
	run_case("sgl-8seg",   8,  4096, lba, 0x33);  lba += 64;
	run_case("sgl-16seg", 16,  4096, lba, 0x44);  lba += 128;
	/* 32 x 4K = 131072 = max_io_size boundary (32 = NVME_OFI_MAX_SGES). */
	run_case("sgl-32seg", 32,  4096, lba, 0x55);  lba += 256;
	/* Uneven segment count / odd size to stress the iterator math. */
	run_case("sgl-3x8k",   3,  8192, lba, 0x66);  lba += 48;

	printf("--- result: %s (%d failing case%s) ---\n",
	       g_fail == 0 ? "ALL PASS" : "FAILURES", g_fail, g_fail == 1 ? "" : "s");
	rc = g_fail ? 1 : 0;

	spdk_nvme_ctrlr_free_io_qpair(g_qpair);
exit:
	if (g_ctrlr) {
		struct spdk_nvme_detach_ctx *dctx = NULL;
		spdk_nvme_detach_async(g_ctrlr, &dctx);
		if (dctx) {
			spdk_nvme_detach_poll(dctx);
		}
	}
	fflush(stdout);
	spdk_env_fini();
	return rc;
}
