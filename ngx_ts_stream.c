
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_stream.h"


#define NGX_TS_PACKET_SIZE  188


typedef struct {
    ngx_chain_t   *cl;
    u_char        *p;
} ngx_ts_byte_read_t;


typedef struct {
    unsigned       pusi:1;
    unsigned       cont:4;
    unsigned       rand:1;
    unsigned       pcrf:1;
    uint16_t       pid;
    uint64_t       pcr;
} ngx_ts_header_t;


static void ngx_ts_byte_read_init(ngx_ts_byte_read_t *br, ngx_chain_t *cl);
static ngx_int_t ngx_ts_byte_read(ngx_ts_byte_read_t *br, u_char *dst,
    size_t len);
static ngx_int_t ngx_ts_byte_read_skip(ngx_ts_byte_read_t *br, size_t len);
static ngx_int_t ngx_ts_byte_read8(ngx_ts_byte_read_t *br, u_char *v);
static ngx_int_t ngx_ts_byte_read16(ngx_ts_byte_read_t *br, uint16_t *v);

static ssize_t ngx_ts_read_header(ngx_ts_stream_t *ts, u_char *p,
    ngx_ts_header_t *h);
static ngx_int_t ngx_ts_read_packet(ngx_ts_stream_t *ts, ngx_buf_t *b);
static ngx_int_t ngx_ts_read_pat(ngx_ts_stream_t *ts, ngx_ts_header_t *h,
    ngx_buf_t *b);
static ngx_int_t ngx_ts_read_pmt(ngx_ts_stream_t *ts, ngx_ts_program_t *prog,
    ngx_ts_header_t *h, ngx_buf_t *b);
static ngx_int_t ngx_ts_read_pes(ngx_ts_stream_t *ts, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_ts_header_t *h, ngx_buf_t *b);
static ngx_chain_t *ngx_ts_packetize(ngx_ts_stream_t *ts, ngx_ts_header_t *h,
    ngx_chain_t *in);

static ngx_int_t ngx_ts_free_buf(ngx_ts_stream_t *ts, ngx_buf_t *b);
static ngx_int_t ngx_ts_append_buf(ngx_ts_stream_t *ts, ngx_ts_header_t *h,
    ngx_chain_t **ll, ngx_buf_t *b);


static void
ngx_ts_byte_read_init(ngx_ts_byte_read_t *br, ngx_chain_t *cl)
{
    br->cl = cl;
    br->p = cl ? cl->buf->pos : NULL;
}


static ngx_int_t
ngx_ts_byte_read(ngx_ts_byte_read_t *br, u_char *dst, size_t len)
{
    size_t  n;

    while (br->cl && len) {
        n = ngx_min((size_t) (br->cl->buf->last - br->p), len);

        if (dst) {
            dst = ngx_cpymem(dst, br->p, n);
        }

        br->p += n;
        len -= n;

        if (br->p == br->cl->buf->last) {
            br->cl = br->cl->next;
            br->p = br->cl ? br->cl->buf->pos : NULL;
        }
    }

    return len ? NGX_AGAIN : NGX_OK;
}


static ngx_int_t
ngx_ts_byte_read_skip(ngx_ts_byte_read_t *br, size_t len)
{
    return ngx_ts_byte_read(br, NULL, len);
}


static ngx_int_t
ngx_ts_byte_read8(ngx_ts_byte_read_t *br, u_char *v)
{
    return ngx_ts_byte_read(br, v, 1);
}


static ngx_int_t
ngx_ts_byte_read16(ngx_ts_byte_read_t *br, uint16_t *v)
{
    if (ngx_ts_byte_read(br, (u_char *) v, 2) == NGX_AGAIN) {
        return NGX_AGAIN;
    }

#if (NGX_HAVE_LITTLE_ENDIAN)
    *v = htons(*v);
#endif

    return NGX_OK;
}


ngx_int_t
ngx_ts_read(ngx_ts_stream_t *ts, ngx_chain_t *in)
{
    size_t        n, size;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts read");

    for (/* void */; in; in = in->next) {

        while (in->buf->pos != in->buf->last) {
            b = ts->buf;

            if (b == NULL) {
                if (ts->free) {
                    cl = ts->free;
                    ts->free = cl->next;

                    b = cl->buf;
                    ngx_free_chain(ts->pool, cl);

                    b->pos = b->start;
                    b->last = b->start;

                } else {
                    b = ngx_create_temp_buf(ts->pool, NGX_TS_PACKET_SIZE);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }
                }

                ts->buf = b;
            }

            n = b->end - b->last;
            size = in->buf->last - in->buf->pos;

            if (n > size) {
                n = size;
            }

            b->last = ngx_cpymem(b->last, in->buf->pos, n);
            in->buf->pos += n;

            if (b->last == b->end) {
                if (ngx_ts_read_packet(ts, b) != NGX_OK) {
                    return NGX_ERROR;
                }

                ts->buf = NULL;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_read_packet(ngx_ts_stream_t *ts, ngx_buf_t *b)
{
    ssize_t            n;
    ngx_uint_t         i, j;
    ngx_chain_t       *cl;
    ngx_ts_es_t       *es;
    ngx_ts_header_t    h;
    ngx_ts_program_t  *prog;

    n = ngx_ts_read_header(ts, b->pos, &h);

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (n == NGX_DONE) {
        b->pos = b->last;

    } else {
        b->pos += n;
    }

    if (h.pid == 0) {
        return ngx_ts_read_pat(ts, &h, b);
    }

    for (i = 0; i < ts->nprogs; i++) {
        prog = &ts->progs[i];

        if (h.pid == prog->pid) {
            return ngx_ts_read_pmt(ts, prog, &h, b);
        }

        for (j = 0; j < prog->nes; j++) {
            es = &prog->es[j];

            if (h.pid == es->pid) {
                return ngx_ts_read_pes(ts, prog, es, &h, b);
            }
        }
    }

    ngx_log_error(NGX_LOG_INFO, ts->log, 0,
                  "dropping unexpected TS packet pid:0x%04uxd",
                  (unsigned) h.pid);

    cl = ngx_alloc_chain_link(ts->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = ts->free;
    ts->free = cl;

    return NGX_OK;
}


static ssize_t
ngx_ts_read_header(ngx_ts_stream_t *ts, u_char *p, ngx_ts_header_t *h)
{
    /*
     * TS Packet Header
     * ISO/IEC 13818-1 : 2000 (E)
     * 2.4.3.2 Transport Stream packet layer, p. 18
     */

    u_char    alen, afic;
    ssize_t   n;
    uint64_t  pcrb, pcre;

    /* sync_byte */
    if (*p++ != 0x47) {
        ngx_log_error(NGX_LOG_ERR, ts->log, 0, "invalid TS sync byte");
        return NGX_ERROR;
    }

    ngx_memzero(h, sizeof(ngx_ts_header_t));

    /* payload_unit_start_indicator */
    h->pusi = (*p & 0x40) ? 1 : 0;

    /* PID */
    h->pid = *p++ & 0x1f;
    h->pid = (h->pid << 8) + *p++;

    /* adaptation_field_control */
    afic = (*p & 0x30) >> 4;

    /* continuity_counter */
    h->cont = *p++ & 0x0f;

    if (afic == 0) {
        ngx_log_error(NGX_LOG_ERR, ts->log, 0, "invalid TS packet");
        return NGX_ERROR;
    }

    n = 4;

    if (afic & 0x02) {
        /* adaptation_field_length */
        alen = *p++;

        if (alen > 183) {
            ngx_log_error(NGX_LOG_ERR, ts->log, 0,
                          "too long TS adaptation field");
            return NGX_ERROR;
        }

        if (afic & 0x01) {
            n += alen + 1;

        } else {
            n = NGX_DONE;
        }

        if (alen) {
            /* random_access_indicator */
            h->rand = (*p & 0x40) ? 1 : 0;

            /* PCR_flag */
            h->pcrf = (*p & 0x10) ? 1 : 0;

            p++;

            if (h->pcrf) {
                /* program_clock_reference_base */
                pcrb = *p++;
                pcrb = (pcrb << 8) + *p++;
                pcrb = (pcrb << 8) + *p++;
                pcrb = (pcrb << 8) + *p++;
                pcrb = (pcrb << 1) + (*p >> 7);

                /* program_clock_reference_extension */
                pcre = *p++ & 0x01;
                pcre = (pcre << 8) + *p++;

                h->pcr = pcrb * 300 + pcre;
            }
        }
    }

    ngx_log_debug6(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts packet "
                   "pid:0x%04uxd, pusi:%d, c:%02d, r:%d, pcr:%uL, n:%uz",
                   (unsigned) h->pid, h->pusi, h->cont, h->rand, h->pcr,
                   n == NGX_DONE ? 0 : NGX_TS_PACKET_SIZE - n);

    return n;
}


static ngx_int_t
ngx_ts_read_pat(ngx_ts_stream_t *ts, ngx_ts_header_t *h, ngx_buf_t *b)
{
    /*
     * PAT
     * ISO/IEC 13818-1 : 2000 (E)
     * 2.4.4.3 Program association Table, p. 43
     */

    u_char               ptr;
    uint16_t             len, number, pid;
    ngx_uint_t           nprogs, n;
    ngx_ts_program_t    *prog;
    ngx_ts_byte_read_t   br, pr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts pat");

    if (ts->nprogs) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0,
                       "ts dropping successive pat");
        return ngx_ts_free_buf(ts, b);
    }

    if (ngx_ts_append_buf(ts, h, &ts->bufs, b) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_ts_byte_read_init(&br, ts->bufs);

    /* pointer_field */
    if (ngx_ts_byte_read8(&br, &ptr) == NGX_AGAIN) {
        return NGX_OK;
    }

    /* skipped bytes + table_id */
    if (ngx_ts_byte_read_skip(&br, ptr + 1) == NGX_AGAIN) {
        return NGX_OK;
    }

    /* section_length */
    if (ngx_ts_byte_read16(&br, &len) == NGX_AGAIN) {
        return NGX_OK;
    }

    len &= 0x0fff;

    if (len < 9) {
        ngx_log_error(NGX_LOG_ERR, ts->log, 0, "malformed PAT");
        return NGX_ERROR;
    }

    if (len > 0x03fd) {
        ngx_log_error(NGX_LOG_ERR, ts->log, 0, "too big PAT: %ud",
                      (unsigned) len);
        return NGX_ERROR;
    }

    pr = br;

    if (ngx_ts_byte_read_skip(&pr, len) == NGX_AGAIN) {
        return NGX_OK;
    }

    /* PAT is fully available */

    /* transport_stream_id .. last_section_number */
    ngx_ts_byte_read_skip(&br, 5);

    nprogs = (len - 9) / 4;

    ts->progs = ngx_pcalloc(ts->pool,
                            nprogs * sizeof(ngx_ts_program_t));
    if (ts->progs == NULL) {
        return NGX_ERROR;
    }

    prog = ts->progs;

    for (n = 0; n < nprogs; n++) {
        /* program_number */
        (void) ngx_ts_byte_read16(&br, &number);

        /* network_PID / program_map_PID */
        (void) ngx_ts_byte_read16(&br, &pid);

        if (number) {
            pid = pid & 0x1fff;

            prog->number = number;
            prog->pid = pid;
            prog++;

            ngx_log_debug2(NGX_LOG_DEBUG_CORE, ts->log, 0,
                           "ts program %ud, pid:0x%04uxd",
                           (unsigned) number, (unsigned) pid);
        }
    }

    ts->nprogs = prog - ts->progs;

    if (ts->pat_handler) {
        if (ts->pat_handler(ts) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_ts_free_chain(ts, &ts->bufs);

    return NGX_OK;
}


static ngx_int_t
ngx_ts_read_pmt(ngx_ts_stream_t *ts, ngx_ts_program_t *prog, ngx_ts_header_t *h,
    ngx_buf_t *b)
{
    /*
     * PMT
     * ISO/IEC 13818-1 : 2000 (E)
     * 2.4.4.8 Program Map Table, p. 46
     */

    u_char               ptr, type;
    uint16_t             len, pilen, elen, pid;
    ngx_uint_t           nes, n;
    ngx_ts_es_t         *es;
    ngx_ts_byte_read_t   br, pr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts pmt");

    if (prog->nes) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0,
                       "ts dropping successive pmt");
        return ngx_ts_free_buf(ts, b);
    }

    if (ngx_ts_append_buf(ts, h, &prog->bufs, b) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_ts_byte_read_init(&br, prog->bufs);

    /* pointer_field */
    if (ngx_ts_byte_read8(&br, &ptr) == NGX_AGAIN) {
        return NGX_OK;
    }

    /* skipped bytes + table_id */
    if (ngx_ts_byte_read_skip(&br, ptr + 1) == NGX_AGAIN) {
        return NGX_OK;
    }

    /* section_length */
    if (ngx_ts_byte_read16(&br, &len) == NGX_AGAIN) {
        return NGX_OK;
    }

    len &= 0x0fff;

    if (len < 13) {
        ngx_log_error(NGX_LOG_ERR, ts->log, 0, "malformed PMT");
        return NGX_ERROR;
    }

    if (len > 0x03fd) {
        ngx_log_error(NGX_LOG_ERR, ts->log, 0, "too big PMT: %ud",
                      (unsigned) len);
        return NGX_ERROR;
    }

    pr = br;

    if (ngx_ts_byte_read_skip(&pr, len) == NGX_AGAIN) {
        return NGX_OK;
    }

    /* PMT is fully available */

    /* program_number .. last_sesion_number */
    (void) ngx_ts_byte_read_skip(&br, 5);

    /* PCR_PID */
    (void) ngx_ts_byte_read16(&br, &pid);

    prog->pcr_pid = pid & 0x1fff;

    /* program_info_length */
    (void) ngx_ts_byte_read16(&br, &pilen);

    pilen &= 0x0fff;

    if (ngx_ts_byte_read_skip(&br, pilen) == NGX_AGAIN
        || len < 13 + pilen)
    {
        ngx_log_error(NGX_LOG_ERR, ts->log, 0, "malformed PMT");
        return NGX_ERROR;
    }

    len -= 13 + pilen;

    pr = br;

    for (nes = 0; len > 0; nes++) {
        if (ngx_ts_byte_read(&pr, NULL, 3) == NGX_AGAIN
            || ngx_ts_byte_read16(&pr, &elen) == NGX_AGAIN
            || ngx_ts_byte_read(&pr, NULL, elen & 0x0fff) == NGX_AGAIN
            || len < 5 + (elen & 0x0fff))
        {
            ngx_log_error(NGX_LOG_ERR, ts->log, 0, "malformed PMT");
            return NGX_ERROR;
        }

        len -= 5 + (elen & 0x0fff);
    }

    es = ngx_pcalloc(ts->pool, nes * sizeof(ngx_ts_es_t));
    if (es == NULL) {
        return NGX_ERROR;
    }

    prog->es = es;
    prog->nes = nes;

    for (n = 0; n < nes; n++, es++) {
        /* stream_type */
        (void) ngx_ts_byte_read8(&br, &type);

        /* elementary_PID */
        (void) ngx_ts_byte_read16(&br, &pid);

        /* ES_info_length */
        (void) ngx_ts_byte_read16(&br, &elen);

        /* ES_info */
        (void) ngx_ts_byte_read_skip(&br, elen & 0x0fff);

        pid = pid & 0x1fff;

        es->type = type;
        es->pid = pid;

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, ts->log, 0,
                       "ts es type:%ui, pid:0x%04uxd",
                       (ngx_uint_t) type, (unsigned) pid);
    }

    if (ts->pmt_handler) {
        if (ts->pmt_handler(ts, prog) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_ts_free_chain(ts, &prog->bufs);

    return NGX_OK;
}


static ngx_int_t
ngx_ts_read_pes(ngx_ts_stream_t *ts, ngx_ts_program_t *prog, ngx_ts_es_t *es,
    ngx_ts_header_t *h, ngx_buf_t *b)
{
    /*
     * PES Packet
     * ISO/IEC 13818-1 : 2000 (E)
     * 2.4.3.6 PES packet, p. 31
     */

    u_char              sid, pfx[3], v8, hlen;
    uint16_t            len, flags, v16;
    uint64_t            pts, dts;
    ngx_uint_t          ptsf;
    ngx_ts_byte_read_t  br, pr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts pes");

    if (es->bufs && h->pusi && b) {
        if (ngx_ts_read_pes(ts, prog, es, h, NULL) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (es->bufs == NULL) {
        es->rand = h->rand;
    }

    if (ngx_ts_append_buf(ts, h, &es->bufs, b) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_ts_byte_read_init(&br, es->bufs);

    /* packet_start_code_prefix */
    if (ngx_ts_byte_read(&br, pfx, 3) == NGX_AGAIN) {
        return NGX_OK;
    }

    if (pfx[0] != 0 || pfx[1] != 0 || pfx[2] != 1) {
        ngx_log_error(NGX_LOG_INFO, ts->log, 0, "missing PES start prefix");
        return NGX_ERROR;
    }

    /* stream_id */
    if (ngx_ts_byte_read8(&br, &sid) == NGX_AGAIN) {
        return NGX_OK;
    }

    es->sid = sid;

    /* PES_packet_length */
    if (ngx_ts_byte_read16(&br, &len) == NGX_AGAIN) {
        return NGX_OK;
    }

    if (len) {
        pr = br;

        if (ngx_ts_byte_read_skip(&pr, len) == NGX_AGAIN) {
            return NGX_OK;
        }

    } else if (b) {
        /* wait for PUSI */
        return NGX_OK;
    }

    /* PES is fully available */

    if (sid == 0xbe) {  /* padding_stream */
        ngx_ts_free_chain(ts, &es->bufs);
        return NGX_OK;
    }

    ptsf = 0;

    if (sid != 0xbc     /* program_stream_map */
        && sid != 0xbf  /* private_stream_2 */
        && sid != 0xf0  /* ECM_stream */
        && sid != 0xf1  /* EMM_stream */
        && sid != 0xff  /* program_stream_directory */
        && sid != 0xf2  /* DSMCC_stream */
        && sid != 0xf8) /* ITU-T Rec. H.222.1 type E stream */
    {
        /* PES_scrambling_control .. PES_extension_flag */
        if (ngx_ts_byte_read16(&br, &flags) == NGX_AGAIN) {
            return NGX_OK;
        }

        /* PES_header_data_length */
        if (ngx_ts_byte_read8(&br, &hlen) == NGX_AGAIN) {
            return NGX_OK;
        }

        if (len) {
            if (len < 3 + hlen) {
                ngx_log_error(NGX_LOG_INFO, ts->log, 0, "malformed PES");
                return NGX_ERROR;
            }

            len -= 3 + hlen;
        }

        pr = br;

        if (ngx_ts_byte_read_skip(&br, hlen) == NGX_AGAIN) {
            return NGX_OK;
        }

        if ((flags & 0x00c0) == 0x0080) { /* PTS_DTS_flags == '10' */
            ptsf = 1;

            /* PTS[32..30] */
            if (ngx_ts_byte_read8(&pr, &v8) == NGX_AGAIN) {
                return NGX_OK;
            }

            pts = (uint64_t) (v8 & 0x0e) << 29;

            /* PTS[29..15] */
            if (ngx_ts_byte_read16(&pr, &v16) == NGX_AGAIN) {
                return NGX_OK;
            }

            pts |= (uint64_t) (v16 & 0xfffe) << 14;

            /* PTS[14..0] */
            if (ngx_ts_byte_read16(&pr, &v16) == NGX_AGAIN) {
                return NGX_OK;
            }

            pts |= v16 >> 1;

            es->pts = pts;
            es->dts = pts;

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                           "ts pes pts:%uL", pts);
        }

        if ((flags & 0x00c0) == 0x00c0) { /* PTS_DTS_flags == '11' */
            ptsf = 1;

            /* PTS[32..30] */
            if (ngx_ts_byte_read8(&pr, &v8) == NGX_AGAIN) {
                return NGX_OK;
            }

            pts = (uint64_t) (v8 & 0x0e) << 29;

            /* PTS[29..15] */
            if (ngx_ts_byte_read16(&pr, &v16) == NGX_AGAIN) {
                return NGX_OK;
            }

            pts |= (uint64_t) (v16 & 0xfffe) << 14;

            /* PTS[14..0] */
            if (ngx_ts_byte_read16(&pr, &v16) == NGX_AGAIN) {
                return NGX_OK;
            }

            pts |= v16 >> 1;

            /* DTS[32..30] */
            if (ngx_ts_byte_read8(&pr, &v8) == NGX_AGAIN) {
                return NGX_OK;
            }

            dts = (uint64_t) (v8 & 0x0e) << 29;

            /* DTS[29..15] */
            if (ngx_ts_byte_read16(&pr, &v16) == NGX_AGAIN) {
                return NGX_OK;
            }

            dts |= (uint64_t) (v16 & 0xfffe) << 14;

            /* DTS[14..0] */
            if (ngx_ts_byte_read16(&pr, &v16) == NGX_AGAIN) {
                return NGX_OK;
            }

            dts |= v16 >> 1;

            es->pts = pts;
            es->dts = dts;

            ngx_log_debug2(NGX_LOG_DEBUG_CORE, ts->log, 0,
                           "ts pes pts:%uL, dts:%uL", pts, dts);
        }
    }

    if (br.cl) {
        br.cl->buf->pos = br.p;
    }

    if (len) {
        pr = br;

        if (ngx_ts_byte_read_skip(&pr, len) == NGX_AGAIN) {
            return NGX_OK;
        }

        if (pr.cl) {
            pr.cl->buf->last = pr.p;
        }
    }

    es->ptsf = ptsf;

    if (ts->pes_handler) {
        if (ts->pes_handler(ts, prog, es, br.cl) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_ts_free_chain(ts, &es->bufs);

    return NGX_OK;
}


ngx_chain_t *
ngx_ts_write_pat(ngx_ts_stream_t *ts)
{
    size_t             len;
    u_char            *p, *data;
    uint32_t           crc;
    ngx_buf_t          b;
    ngx_uint_t         n;
    ngx_chain_t        in;
    ngx_ts_header_t    h;
    ngx_ts_program_t  *prog;

    len = 9 + ts->nprogs * 4;

    data = ngx_pnalloc(ts->pool, 4 + len);
    if (data == NULL) {
        return NULL;
    }

    p = data;

    /* pointer_field */
    *p++ = 0;

    /* table_id */
    *p++ = 0;

    /* section_syntax_indicator, section_length */
    *p++ = 0x80 | (u_char) (len >> 8);
    *p++ = (u_char) len;

    /* transport_stream_id */
    *p++ = 0;

    /* version_number, current_next_indicator */
    *p++ = 0x01;

    /* section_number */
    *p++ = 0;

    /* last_section_number */
    *p++ = 0;

    for (n = 0; n < ts->nprogs; n++) {
        prog = &ts->progs[n];

        /* program_number */
        *p++ = (u_char) (prog->number >> 8);
        *p++ = (u_char) prog->number;

        /* program_map_PID */
        *p++ = (u_char) (prog->pid >> 8);
        *p++ = (u_char) prog->pid;
    }

    /* TODO is this the right crc? */
    crc = ngx_crc32_long(p + 1, p + 1 - data);

    *p++ = (crc >> 24);
    *p++ = (crc >> 16);
    *p++ = (crc >> 8);
    *p++ = crc;

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.start = data;
    b.pos = data;
    b.last = p;
    b.end = p;

    in.buf = &b;
    in.next = NULL;

    ngx_memzero(&h, sizeof(ngx_ts_header_t));

    return ngx_ts_packetize(ts, &h, &in);
}


ngx_chain_t *
ngx_ts_write_pmt(ngx_ts_stream_t *ts, ngx_ts_program_t *prog)
{
    size_t            len;
    u_char           *p, *data;
    uint32_t          crc;
    ngx_buf_t         b;
    ngx_uint_t        n;
    ngx_chain_t       in;
    ngx_ts_es_t      *es;
    ngx_ts_header_t   h;

    len = 13 + 5 * prog->nes;

    data = ngx_pnalloc(ts->pool, 4 + len);
    if (data == NULL) {
        return NULL;
    }

    p = data;

    /* pointer_field */
    *p++ = 0;

    /* table_id */
    *p++ = 0x02;

    /* section_syntax_indicator */
    *p++ = 0x80 | (u_char) (len >> 8);
    *p++ = (u_char) len;
    
    /* program_number */
    *p++ = (u_char) (prog->number >> 8);
    *p++ = (u_char) prog->number;

    /* version_number, current_next_indicator */
    *p++ = 0x01;

    /* section_number */
    *p++ = 0;

    /* last_section_number */
    *p++ = 0;

    /* PCR_PID */
    *p++ = (u_char) (prog->pcr_pid >> 8);
    *p++ = (u_char) prog->pcr_pid;

    /* program_info_length */
    *p++ = 0;
    *p++ = 0;

    for (n = 0; n < prog->nes; n++) {
        es = &prog->es[n];

        /* stream_type */
        *p++ = es->type;

        /* elementary_PID */
        *p++ = (u_char) (es->pid >> 8);
        *p++ = (u_char) es->pid;

        /* ES_info_length */
        *p++ = 0;
        *p++ = 0;
    }

    crc = ngx_crc32_long(p + 1, p + 1 - data);

    *p++ = (crc >> 24);
    *p++ = (crc >> 16);
    *p++ = (crc >> 8);
    *p++ = crc;

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.start = data;
    b.pos = data;
    b.last = p;
    b.end = p;

    in.buf = &b;
    in.next = NULL;

    ngx_memzero(&h, sizeof(ngx_ts_header_t));

    h.pid = prog->pid;

    return ngx_ts_packetize(ts, &h, &in);
}


ngx_chain_t *
ngx_ts_write_pes(ngx_ts_stream_t *ts, ngx_ts_program_t *prog, ngx_ts_es_t *es,
    ngx_chain_t *bufs)
{
    u_char           *p, *data;
    ngx_buf_t         b;
    ngx_chain_t       in;
    ngx_ts_header_t   h;

    /*XXX*/
    data = (u_char *) "foo";
    p = data + 3;

    /* XXX check pts == dts */

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.start = data;
    b.pos = data;
    b.last = p;
    b.end = p;

    in.buf = &b;
    in.next = NULL;

    ngx_memzero(&h, sizeof(ngx_ts_header_t));

    h.pid = es->pid;
    h.rand = 1;

    return ngx_ts_packetize(ts, &h, &in);
}


static ngx_chain_t *
ngx_ts_packetize(ngx_ts_stream_t *ts, ngx_ts_header_t *h, ngx_chain_t *in)
{
    u_char       *p, *ip, *af, *aflen;
    size_t        n, left;
    uint64_t      pcrb, pcre;
    ngx_buf_t    *b;
    ngx_chain_t  *out, *cl, **ll;

    left = 0;

    for (cl = in; cl; cl = cl->next) {
        left += cl->buf->last - cl->buf->pos;
    }

    ip = in->buf->pos;

    ll = &out;

    do {
        if (ts->free) {
            cl = ts->free;
            ts->free = cl->next;
            b = cl->buf;

        } else {
            b = ngx_create_temp_buf(ts->pool, NGX_TS_PACKET_SIZE);
            if (b == NULL) {
                return NULL;
            }

            cl = ngx_alloc_chain_link(ts->pool);
            if (cl == NULL) {
                return NULL;
            }

            cl->buf = b;
        }

        b->pos = b->start;
        b->last = b->end;

        p = b->pos;

        /* sync_byte */
        *p++ = 0x47;

        /* payload_unit_start_indicator, PID */
        *p++ = (ll == &out ? 0x40 : 0x00) | (u_char) (h->pid >> 8);
        *p++ = (u_char) h->pid;

        /* payload_present, continuity_counter */
        af = p;
        *p++ = 0x10 | h->cont;
        h->cont = (h->cont + 1) & 0x0f;

        if (h->rand || h->pcrf || left < 184) {
            /* adaptation_field_control */
            *af |= 0x20;

            /* adaptation_field_length */
            aflen = p;
            *p++ = 1;

            /* random_access_indicator, PCR_flag */
            *p++ = (h->rand ? 0x40 : 0x00) | (h->pcrf ? 0x10 : 0x00);

            if (h->pcrf) {
                pcrb = h->pcr / 300;
                pcre = h->pcr % 300;

                /*
                 * program_clock_reference_base,
                 * program_clock_reference_extension
                 */
                *p++ = (u_char) (pcrb >> 25);
                *p++ = (u_char) (pcrb >> 17);
                *p++ = (u_char) (pcrb >> 9);
                *p++ = (u_char) (pcrb >> 1);
                *p++ = (u_char) (pcrb << 7) | (u_char) ((pcre >> 8) & 0x01);
                *p++ = (u_char) pcre;

                *aflen += 6;
            }

            if (left < (size_t) (b->end - p)) {
                n = b->end - p - left;

                /* stuffing_byte */
                ngx_memset(p, '\xff', n);
                p += n;
                *aflen += n;
            }
        }

        /* data_byte */

        while (p != b->end) {
            n = ngx_min(in->buf->last - ip, b->end - p);

            p = ngx_cpymem(p, ip, n);

            left -= n;
            ip += n;

            if (ip == in->buf->last) {
                in = in->next;
                if (in == NULL) {
                    break;
                }

                ip = in->buf->pos;
            }
        }

        *ll = cl;
        ll = &cl->next;

    } while (in);

    *ll = NULL;

    return out;
}


static ngx_int_t
ngx_ts_free_buf(ngx_ts_stream_t *ts, ngx_buf_t *b)
{
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(ts->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = ts->free;
    ts->free = cl;

    return NGX_OK;
}


void
ngx_ts_free_chain(ngx_ts_stream_t *ts, ngx_chain_t **ll)
{
    ngx_chain_t  **fl;

    if (*ll == NULL) {
        return;
    }

    fl = ll;

    while (*ll) {
        ll = &(*ll)->next;
    }

    *ll = ts->free;
    ts->free = *fl;

    *fl = NULL;
}


static ngx_int_t
ngx_ts_append_buf(ngx_ts_stream_t *ts, ngx_ts_header_t *h, ngx_chain_t **ll,
    ngx_buf_t *b)
{
    ngx_chain_t  *cl;

    if (b == NULL) {
        return NGX_OK;
    }

    if (!h->pusi && *ll == NULL) {
        ngx_log_error(NGX_LOG_INFO, ts->log, 0, "dropping orhaned TS packet");
        return ngx_ts_free_buf(ts, b);
    }

    if (h->pusi && *ll) {
        ngx_log_error(NGX_LOG_INFO, ts->log, 0,
                      "dropping unfinished TS packets");
        ngx_ts_free_chain(ts, ll);
    }

    while (*ll) {
        ll = &(*ll)->next;
    }

    cl = ngx_alloc_chain_link(ts->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    *ll = cl;

    return NGX_OK;
}
