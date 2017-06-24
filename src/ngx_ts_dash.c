
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_dash.h"


#define NGX_TS_DASH_BUFFER_SIZE   1024

#define NGX_TS_DASH_DATETIME_LEN  sizeof("2000-12-31T23:59:59Z")
#define NGX_TS_DASH_CODEC_LEN     sizeof("avc1.PPPCCCLLL")


static void ngx_ts_dash_cleanup(void *data);
static ngx_int_t ngx_ts_dash_handler(ngx_ts_handler_data_t *hd);
static ngx_int_t ngx_ts_dash_pmt_handler(ngx_ts_dash_t *dash);
static ngx_int_t ngx_ts_dash_pes_handler(ngx_ts_dash_t *dash,
    ngx_ts_program_t *prog, ngx_ts_es_t *es, ngx_chain_t *in);
static ngx_int_t ngx_ts_dash_append_meta(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep, size_t size, uint64_t dts);
static void ngx_ts_dash_update_bandwidth(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep, ngx_chain_t *in, uint64_t dts);
static ngx_int_t ngx_ts_dash_copy_avc(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep, ngx_chain_t *in);
static ngx_int_t ngx_ts_dash_copy_aac(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep, ngx_chain_t *in);
static ssize_t ngx_ts_dash_copy_default(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep, ngx_chain_t *in);
static ngx_chain_t* ngx_ts_dash_get_buffer(ngx_ts_dash_t *dash);
static ngx_int_t ngx_ts_dash_close_segment(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep);
static void ngx_ts_dash_fill_subs(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep);
static ngx_int_t ngx_ts_dash_update_playlist(ngx_ts_dash_t *dash);
static ngx_int_t ngx_ts_dash_write_file(u_char *path1, u_char *path2,
    u_char *data, size_t len, ngx_log_t *log);
static void ngx_ts_dash_format_datetime(u_char *p, time_t t);
static void ngx_ts_dash_format_codec(u_char *p, ngx_ts_dash_rep_t *rep);
static ngx_int_t ngx_ts_dash_update_init_segments(ngx_ts_dash_t *dash);
static ngx_int_t ngx_ts_dash_open_segment(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep);

static ngx_msec_t ngx_ts_dash_file_manager(void *data);
static ngx_int_t ngx_ts_dash_manage_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_ts_dash_manage_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_ts_dash_delete_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_ts_dash_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);


ngx_ts_dash_t *
ngx_ts_dash_create(ngx_ts_dash_conf_t *conf, ngx_ts_stream_t *ts,
    ngx_str_t *name)
{
    size_t               len;
    ngx_ts_dash_t       *dash;
    ngx_pool_cleanup_t  *cln;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts dash create");

    dash = ngx_pcalloc(ts->pool, sizeof(ngx_ts_dash_t));
    if (dash == NULL) {
        return NULL;
    }

    dash->conf = conf;
    dash->ts = ts;
    dash->playlist_len = 128;

    dash->path.len = conf->path->name.len + 1 + name->len;
    dash->path.data = ngx_pnalloc(ts->pool, dash->path.len + 1);
    if (dash->path.data == NULL) {
        return NULL;
    }

    ngx_sprintf(dash->path.data, "%V/%V%Z", &conf->path->name, name);

    /* index.mpd */

    len = dash->path.len + sizeof("/index.mpd");

    dash->mpd_path = ngx_pnalloc(ts->pool, len);
    if (dash->mpd_path == NULL) {
        return NULL;
    }

    ngx_sprintf(dash->mpd_path, "%V/index.mpd%Z", &dash->path);

    /* index.mpd.tmp */

    len += sizeof(".tmp") - 1;

    dash->mpd_tmp_path = ngx_pnalloc(ts->pool, len);
    if (dash->mpd_tmp_path == NULL) {
        return NULL;
    }

    ngx_sprintf(dash->mpd_tmp_path, "%s.tmp%Z", dash->mpd_path);

    cln = ngx_pool_cleanup_add(ts->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_ts_dash_cleanup;
    cln->data = dash;

    if (ngx_ts_add_handler(ts, ngx_ts_dash_handler, dash) != NGX_OK) {
        return NULL;
    }

    return dash;
}


static void
ngx_ts_dash_cleanup(void *data)
{
    ngx_ts_dash_t *dash = data;

    ngx_ts_stream_t  *ts;

    ts = dash->ts;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts dash cleanup");

    /*XXX*/

    (void) dash;
    (void) ts;
}


static ngx_int_t
ngx_ts_dash_handler(ngx_ts_handler_data_t *hd)
{
    ngx_ts_dash_t *dash = hd->data;

    switch (hd->event) {

    case NGX_TS_PMT:
        return ngx_ts_dash_pmt_handler(dash);

    case NGX_TS_PES:
        return ngx_ts_dash_pes_handler(dash, hd->prog, hd->es, hd->bufs);

    default:
        return NGX_OK;
    }
}


static ngx_int_t
ngx_ts_dash_pmt_handler(ngx_ts_dash_t *dash)
{
    size_t              len;
    ngx_uint_t          i, j, n;
    ngx_ts_es_t        *es;
    ngx_ts_stream_t    *ts;
    ngx_ts_program_t   *prog;
    ngx_ts_dash_rep_t  *rep;
    ngx_ts_dash_set_t  *set, *aset, *vset;

    if (dash->sets) {
        return NGX_OK;
    }

    ts = dash->ts;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts dash pmt");

    n = 0;

    for (i = 0; i < ts->nprogs; i++) {
        prog = &ts->progs[i];

        if (prog->es == NULL) {
            return NGX_OK;
        }

        n += prog->nes;
    }

    dash->nsets = 0;
    dash->sets = ngx_pcalloc(ts->pool, 2 * sizeof(ngx_ts_dash_set_t));
    if (dash->sets == NULL) {
        return NGX_ERROR;
    }

    aset = NULL;
    vset = NULL;

    for (i = 0; i < ts->nprogs; i++) {
        prog = &ts->progs[i];

        for (j = 0; j < prog->nes; j++) {
            es = &prog->es[j];

            switch (es->type) {
            case NGX_TS_VIDEO_MPEG1:
            case NGX_TS_VIDEO_MPEG2:
            case NGX_TS_VIDEO_MPEG4:
            case NGX_TS_VIDEO_AVC:
                if (vset == NULL) {
                    vset = &dash->sets[dash->nsets++];
                    vset->video = 1;
                }

                set = vset;
                break;

            case NGX_TS_AUDIO_MPEG1:
            case NGX_TS_AUDIO_MPEG2:
            case NGX_TS_AUDIO_AAC:
                if (aset == NULL) {
                    aset = &dash->sets[dash->nsets++];
                }

                set = aset;
                break;

            default:
                continue;
            }

            if (set->reps == NULL) {
                set->nreps = 0;
                set->reps = ngx_pcalloc(ts->pool,
                                        n * sizeof(ngx_ts_dash_rep_t));
                if (set->reps == NULL) {
                    return NGX_ERROR;
                }
            }

            rep = &set->reps[set->nreps++];

            rep->es = es;

            rep->nsegs = dash->conf->nsegs;
            rep->segs = ngx_pcalloc(ts->pool,
                                    rep->nsegs * sizeof(ngx_ts_dash_segment_t));
            if (rep->segs == NULL) {
                return NGX_ERROR;
            }

            len = dash->path.len + 1 + NGX_INT_T_LEN + 1 + NGX_INT64_LEN
                  + sizeof(".mp4");

            rep->path.data = ngx_pnalloc(ts->pool, len);
            if (rep->path.data == NULL) {
                return NGX_ERROR;
            }

            rep->path.len = ngx_sprintf(rep->path.data, "%V/%ui.",
                                        &dash->path, (ngx_uint_t) es->pid)
                            - rep->path.data;

            /* init.mp4 */

            len = dash->path.len + 1 + NGX_INT_T_LEN + sizeof(".init.mp4");

            rep->init_path = ngx_pnalloc(ts->pool, len);
            if (rep->init_path == NULL) {
                return NGX_ERROR;
            }

            ngx_sprintf(rep->init_path, "%V/%ui.init.mp4%Z",
                        &dash->path, (ngx_uint_t) es->pid);

            /* init.mp4.tmp */

            len += sizeof(".tmp") - 1;

            rep->init_tmp_path = ngx_pnalloc(ts->pool, len);
            if (rep->init_tmp_path == NULL) {
                return NGX_ERROR;
            }

            ngx_sprintf(rep->init_tmp_path, "%s.tmp%Z", rep->init_path);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_dash_pes_handler(ngx_ts_dash_t *dash, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *in)
{
    ssize_t             rc;
    ngx_uint_t          i, j;
    ngx_ts_stream_t    *ts;
    ngx_ts_dash_set_t  *set;
    ngx_ts_dash_rep_t  *rep;

    if (!es->ptsf) {
        return NGX_OK;
    }

    ts = dash->ts;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts dash pes pid:%ud",
                   (unsigned) es->pid);

    for (i = 0; i < dash->nsets; i++) {
        set = &dash->sets[i];

        for (j = 0; j < set->nreps; j++) {
            rep =  &set->reps[j];

            if (rep->es == es) {
                goto found;
            }
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts dash skip es pid:%ud",
                   (unsigned) es->pid);

    return NGX_OK;

found:

    ngx_ts_dash_update_bandwidth(dash, rep, in, es->dts);

    if (ngx_ts_dash_close_segment(dash, rep) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_ts_dash_open_segment(dash, rep) != NGX_OK) {
        return NGX_ERROR;
    }

    switch (es->type) {
    case NGX_TS_VIDEO_AVC:
        return ngx_ts_dash_copy_avc(dash, rep, in);

    case NGX_TS_AUDIO_AAC:
        return ngx_ts_dash_copy_aac(dash, rep, in);

    case NGX_TS_AUDIO_MPEG1:
    case NGX_TS_AUDIO_MPEG2:
        /* return ngx_ts_dash_copy_mp3(dash, rep, in); */
        return NGX_OK;

    default:
        rc = ngx_ts_dash_copy_default(dash, rep, in);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        return ngx_ts_dash_append_meta(dash, rep, rc, es->dts);
    }
}


static ngx_int_t
ngx_ts_dash_append_meta(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    size_t size, uint64_t dts)
{
    size_t        n;
    u_char       *p;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;
    ngx_ts_es_t  *es;

    es = rep->es;

    rep->ndata += size;
    rep->nsamples++;

    n = es->video ? 16 : 8;

    cl = rep->last_meta;
    b = cl->buf;

    if ((size_t) (b->end - b->last) < n) {
        cl->next = ngx_ts_dash_get_buffer(dash);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        rep->last_meta = cl;
        b = cl->buf;
    }

    p = b->last;
    b->last += n;
    rep->nmeta += n;

    /* sample_duration */
    if (rep->subs.sample_duration) {
        ngx_ts_dash_write32(rep->subs.sample_duration, dts - rep->dts);
    }

    rep->subs.sample_duration = p;
    p = ngx_ts_dash_write32(p, 0);

    /* sample_size */
    p = ngx_ts_dash_write32(p, size);

    if (es->video) {
        /*
         * ISO/IEC 14496-12:2008(E)
         * 8.8.3 Track Extends Box, Sample flags, p. 44
         * sample_is_difference_sample for non-key sample
         */
        p = ngx_ts_dash_write32(p, es->rand ? 0x00000000 : 0x00010000);

        /* sample_composition_time_offset */
        ngx_ts_dash_write32(p, es->pts - es->dts);
    }

    rep->dts = dts;

    return NGX_OK;
}


static ngx_int_t
ngx_ts_dash_append_data(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    u_char *data, size_t len)
{
    size_t        n;
    ngx_chain_t  *cl;

    cl = rep->last_data;

    while (len) {
        if (cl->buf->last == cl->buf->end) {
            cl->next = ngx_ts_dash_get_buffer(dash);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
            rep->last_data = cl;
        }

        n = ngx_min((size_t) (cl->buf->end - cl->buf->last), len);

        cl->buf->last = ngx_cpymem(cl->buf->last, data, n);

        data += n;
        len -= n;
    }

    return NGX_OK;
}


static void
ngx_ts_dash_update_bandwidth(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    ngx_chain_t *in, uint64_t dts)
{
    int64_t  d, analyze;

    if (rep->bandwidth) {
        return;
    }

    if (rep->bandwidth_bytes == 0) {
        rep->bandwidth_dts = dts;
    }

    while (in) {
        rep->bandwidth_bytes += in->buf->last - in->buf->pos;
        in = in->next;
    }

    d = dts - rep->bandwidth_dts;
    analyze = (int64_t) dash->conf->analyze * 90;

    if (d >= analyze) {
        rep->bandwidth = rep->bandwidth_bytes * 8 * 90000 / d;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, dash->ts->log, 0,
                   "ts dash bandwidth:%ui, pid:%ud",
                   rep->bandwidth, (unsigned) rep->es->pid);
}


static ngx_int_t
ngx_ts_dash_copy_avc(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    ngx_chain_t *in)
{
    /*
     * Source format:
     * ISO/IEC 14496-10:2004(E)
     * Annex B. Byte Stream Format, p. 216
     *
     * Destination format:
     * ISO/IEC 14496-15:2004(E)
     * 5.3.4.2 Sample format, p. 15
     */

    size_t            size, nsize, n;
    u_char            ch, *p, *psize;
    ngx_uint_t        start, zeroes;
    ngx_chain_t      *out, *sps, *pps, **ll;
    ngx_ts_stream_t  *ts;

    ts = dash->ts;

    start = 0;
    size = 0;
    nsize = 0;
    zeroes = 0;
    psize = NULL;
    out = NULL;
    sps = NULL;
    pps = NULL;

    for (/* void */; in; in = in->next) {

        for (p = in->buf->pos; p != in->buf->last; p++) {
            ch = *p;

            if (ch == 0) {
                zeroes++;
                continue;
            }

            if (zeroes >= 2 && ch == 1) {
                start = 1;
                zeroes = 0;
                continue;
            }

            if (zeroes >= 3) {
                return NGX_ERROR;
            }

            if (start) {
                if (zeroes) {
                    return NGX_ERROR;
                }

                if (psize) {
                    ngx_ts_dash_write32(psize, nsize);
                }

                start = 0;
                nsize = 0;
                out = NULL;
                psize = NULL;

                switch (ch & 0x1f) {

                case 7: /* SPS */
                    if (rep->sps == NULL && sps == NULL) {
                        sps = ngx_ts_dash_get_buffer(dash);
                        if (sps == NULL) {
                            return NGX_ERROR;
                        }

                        out = sps;
                    }

                    break;

                case 8: /* PPS */
                    if (rep->pps == NULL && pps == NULL) {
                        pps = ngx_ts_dash_get_buffer(dash);
                        if (pps == NULL) {
                            return NGX_ERROR;
                        }

                        out = pps;
                    }

                    break;

                default:
                    out = rep->last_data;

                    if (out->buf->end - out->buf->last < 4) {
                        out->next = ngx_ts_dash_get_buffer(dash);
                        if (out->next == NULL) {
                            return NGX_ERROR;
                        }

                        rep->last_data = out->next;
                        out = out->next;
                    }

                    size += 4;
                }

                if (out) {
                    psize = out->buf->last;
                    out->buf->last += 4;
                }
            }

            if (out) {
                n = zeroes + 1;

                if ((size_t) (out->buf->end - out->buf->last) < n) {
                    out->next = ngx_ts_dash_get_buffer(dash);
                    if (out->next == NULL) {
                        return NGX_ERROR;
                    }

                    if (rep->last_data == out) {
                        rep->last_data = out->next;
                    }

                    out = out->next;
                }

                if (psize) {
                    nsize += n;
                }

                if (rep->last_data == out) {
                    size += n;
                }

                for (/* void */; zeroes; zeroes--) {
                    *out->buf->last++ = 0;
                }

                *out->buf->last++ = ch;
            }

            zeroes = 0;
        }
    }

    if (psize) {
        ngx_ts_dash_write32(psize, nsize);
    }

    if (sps) {
        n = ngx_ts_dash_read32(sps->buf->pos);

        if (n > 0xffff) {
            ngx_log_error(NGX_LOG_ERR, ts->log, 0,
                          "too big AVC SPS:%uz", n);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts AVC SPS:%uz", n);

        rep->sps_len = n;
        rep->sps = ngx_pnalloc(ts->pool, n);
        if (rep->sps == NULL) {
            return NGX_ERROR;
        }

        p = rep->sps;
        sps->buf->pos += 4;

        for (ll = &sps; *ll; ll = &(*ll)->next) {
            p = ngx_cpymem(p, (*ll)->buf->pos,
                           (*ll)->buf->last - (*ll)->buf->pos);
        }

        *ll = dash->free;
        dash->free = sps;
    }

    if (pps) {
        n = ngx_ts_dash_read32(pps->buf->pos);

        if (n > 0xffff) {
            ngx_log_error(NGX_LOG_ERR, ts->log, 0,
                          "too big AVC PPS:%uz", n);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts AVC PPS:%uz", n);

        rep->pps_len = n;
        rep->pps = ngx_pnalloc(ts->pool, n);
        if (rep->pps == NULL) {
            return NGX_ERROR;
        }

        p = rep->pps;
        pps->buf->pos += 4;

        for (ll = &pps; *ll; ll = &(*ll)->next) {
            p = ngx_cpymem(p, (*ll)->buf->pos,
                           (*ll)->buf->last - (*ll)->buf->pos);
        }

        *ll = dash->free;
        dash->free = pps;
    }

    return ngx_ts_dash_append_meta(dash, rep, size, rep->es->dts);
}


static ngx_int_t
ngx_ts_dash_copy_aac(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    ngx_chain_t *in)
{
    /*
     * XXX
     * ISO/IEC CD 14496-3 Subpart 4: 1998
     * 1.1.2 Audio_Data_Transport_Stream frame, ADTS, p. 10
     */

    size_t       len, n;
    u_char      *p, adts[9];
    uint64_t     dts;
    ngx_uint_t   f, i;

    static ngx_uint_t  freq[] = {
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
        16000, 12000, 11025,  8000,  7350,     0,     0,     0
    };

    if (in == NULL) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, dash->ts->log, 0, "ts dash AAC ts:%uL",
                   rep->es->dts);

    i = 0;

    p = in->buf->pos;

    for ( ;; ) {
        n = 0;

        /* protection_absent */
        adts[1] = 0;

        while (n < ((adts[1] & 0x01) ? 7 : 9 )) {
            if (p == in->buf->last) {
                in = in->next;

                if (in == NULL) {
                    if (n == 0) {
                        return NGX_OK;
                    }

                    goto failed;
                }

                p = in->buf->pos;
                continue;
            }

            adts[n++] = *p++;
        }

        if (rep->adts == NULL) {
            rep->adts = ngx_pnalloc(dash->ts->pool, 7);
            if (rep->adts == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(rep->adts, adts, 7);
        }

        len = adts[3] & 0x02;
        len = (len << 8) + adts[4];
        len = (len << 3) + (adts[5] >> 5);

        if (len < n) {
            goto failed;
        }

        len -= n;

        f = freq[(adts[2] >> 2) & 0x0f];
        if (f == 0) {
            goto failed;
        }

        dts = rep->es->dts + (uint64_t) 90000 * 1024 * i++ / f;

        ngx_log_debug4(NGX_LOG_DEBUG_CORE, dash->ts->log, 0,
                       "ts dash AAC hd:%uz, fr:%uz, f:%ui, ts:%uL",
                       n, len, f, dts);

        if (ngx_ts_dash_append_meta(dash, rep, len, dts) != NGX_OK) {
            return NGX_ERROR;
        }

        while (len) {
            if (p == in->buf->last) {
                in = in->next;
                if (in == NULL) {
                    goto failed;
                }

                p = in->buf->pos;
            }

            n = ngx_min((size_t) (in->buf->last - p), len);

            if (ngx_ts_dash_append_data(dash, rep, p, n) != NGX_OK) {
                return  NGX_ERROR;
            }

            p += n;
            len -= n;
        }
    }

failed:

    ngx_log_error(NGX_LOG_ERR, dash->ts->log, 0, "invalid AAC ADTS frame");

    return NGX_ERROR;
}


static ssize_t
ngx_ts_dash_copy_default(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    ngx_chain_t *in)
{
    size_t  n, size;

    for (size = 0; in; in = in->next) {
        n = in->buf->last - in->buf->pos;

        if (ngx_ts_dash_append_data(dash, rep, in->buf->pos, n) != NGX_OK) {
            return  NGX_ERROR;
        }

        size += n;
    }

    return size;
}


static ngx_chain_t *
ngx_ts_dash_get_buffer(ngx_ts_dash_t *dash)
{
    ngx_buf_t    *b;
    ngx_chain_t  *out;

    if (dash->free) {
        out = dash->free;
        dash->free = out->next;
        out->next = NULL;
        b = out->buf;

    } else {
        out = ngx_alloc_chain_link(dash->ts->pool);
        if (out == NULL) {
            return NULL;
        }

        b = ngx_create_temp_buf(dash->ts->pool, NGX_TS_DASH_BUFFER_SIZE);
        if (b == NULL) {
            return NULL;
        }

        out->buf = b;
        out->next = NULL;
    }

    b->pos = b->start;
    b->last = b->start;

    return out;
}


static ngx_int_t
ngx_ts_dash_close_segment(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep)
{
    size_t                  max_size;
    ssize_t                 n;
    int64_t                 d, min_seg, max_seg;
    ngx_err_t               err;
    ngx_str_t              *path;
    ngx_file_t              file;
    ngx_uint_t              try;
    ngx_chain_t            *out, **ll;
    ngx_ts_es_t            *es;
    ngx_ts_stream_t        *ts;
    ngx_ts_dash_segment_t  *seg;

    if (rep->meta == NULL) {
        return NGX_OK;
    }

    ts = dash->ts;

    es = rep->es;

    d = es->dts - rep->seg_dts;

    min_seg = (int64_t) dash->conf->min_seg * 90;
    max_seg = (int64_t) dash->conf->max_seg * 90;
    max_size = dash->conf->max_size;

    if (d < min_seg
        || (d < max_seg && es->video && !es->rand))
    {
        if (max_size == 0 || rep->nmeta + rep->ndata < max_size) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_WARN, ts->log, 0,
                      "closing DASH segment \"%V%uL.mp4\" on size limit",
                      &rep->path, rep->seg_dts);
    }

    path = &rep->path;

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.name.data = path->data;
    file.name.len = ngx_sprintf(path->data + path->len, "%uL.mp4%Z",
                                rep->seg_dts)
                    - path->data - 1;

    file.log = ts->log;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts dash close segment \"%s\"", file.name.data);

    for (try = 0; /* void */; try++) {
        file.fd = ngx_open_file(path->data,
                                NGX_FILE_WRONLY,
                                NGX_FILE_TRUNCATE,
                                NGX_FILE_DEFAULT_ACCESS);

        if (file.fd != NGX_INVALID_FILE) {
            break;
        }

        err = ngx_errno;

        if (try || (err != NGX_ENOENT && err != NGX_ENOTDIR)) {
            ngx_log_error(NGX_LOG_EMERG, ts->log, err,
                          ngx_open_file_n " \"%s\" failed", path->data);
            return NGX_ERROR;
        }

        /* XXX dir access mode */
        if (ngx_create_dir(dash->path.data, 0700) == NGX_FILE_ERROR) {
            err = ngx_errno;

            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_CRIT, ts->log, err,
                              ngx_create_dir_n " \"%s\" failed",
                              dash->path.data);
                return NGX_ERROR;
            }
        }
    }

    ngx_ts_dash_fill_subs(dash, rep);

    out = rep->meta;

    for (ll = &out; *ll; ll = &(*ll)->next);

    *ll = rep->data;

    rep->meta = NULL;
    rep->data = NULL;

    n = ngx_write_chain_to_file(&file, out, 0, ts->pool);

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ts->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", path->data);
    }

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    for (/* void */; *ll; ll = &(*ll)->next);

    *ll = dash->free;
    dash->free = out;

    seg = &rep->segs[rep->seg++ % rep->nsegs];
    seg->start = rep->seg_dts;
    seg->duration = d;

    if (ngx_ts_dash_update_playlist(dash) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_ts_dash_fill_subs(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep)
{
    uint32_t             traf, trun, moof, mdat;
    ngx_ts_dash_subs_t  *subs;

    subs = &rep->subs;

    ngx_ts_dash_write64(subs->pts, rep->seg_pts);
    ngx_ts_dash_write64(subs->dts, rep->seg_dts);

    ngx_ts_dash_write32(subs->seq, rep->seg);
    ngx_ts_dash_write32(subs->nsamples, rep->nsamples);
    ngx_ts_dash_write32(subs->duration, rep->es->dts - rep->seg_dts);

    if (subs->sample_duration) {
        ngx_ts_dash_write32(subs->sample_duration, rep->es->dts - rep->dts);
    }

    traf = ngx_ts_dash_read32(subs->traf) + rep->nmeta;
    ngx_ts_dash_write32(subs->traf, traf);

    trun = ngx_ts_dash_read32(subs->trun) + rep->nmeta;
    ngx_ts_dash_write32(subs->trun, trun);

    moof = ngx_ts_dash_read32(subs->moof) + rep->nmeta;
    ngx_ts_dash_write32(subs->moof, moof);

    mdat = ngx_ts_dash_read32(subs->mdat) + rep->ndata;
    ngx_ts_dash_write32(subs->mdat, mdat);

    ngx_ts_dash_write32(subs->moof_mdat, moof + mdat);
    ngx_ts_dash_write32(subs->moof_data, moof + 8);
}


static ngx_int_t
ngx_ts_dash_update_playlist(ngx_ts_dash_t *dash)
{
    u_char                 *p, *last, *data;
    time_t                  now;
    size_t                  len;
    ngx_uint_t              i, j, k, pid, bandwidth, min_update, min_buftime,
                            buf_depth;
    ngx_ts_stream_t        *ts;
    ngx_ts_dash_set_t      *set;
    ngx_ts_dash_rep_t      *rep;
    ngx_ts_dash_segment_t  *seg;
    u_char                  codec[NGX_TS_DASH_CODEC_LEN];
    u_char                  avail_start_time[NGX_TS_DASH_DATETIME_LEN];
    u_char                  pub_time[NGX_TS_DASH_DATETIME_LEN];

    if (ngx_ts_dash_update_init_segments(dash) != NGX_OK) {
        return NGX_ERROR;
    }

    ts = dash->ts;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts dash update playlist \"%s\"", dash->mpd_path);

    now = ngx_time();

    if (dash->availability_start == 0) {
        dash->availability_start = now;
    }

    ngx_ts_dash_format_datetime(avail_start_time, dash->availability_start);
    ngx_ts_dash_format_datetime(pub_time, now);

    /*
     *                 timeShiftBufferDepth
     *       ----------------------------------------
     *      |                                        |
     * -----///////----------------*-----------------> now
     *            |                |                 |
     *             ---------------- -----------------
     *                 liveDelay     lastSegDuration
     *           = 2 * minBufferTime
     *
     */

    min_update = dash->conf->min_seg / 1000;
    min_buftime = dash->conf->min_seg / 1000;
    buf_depth = 2 * min_buftime + dash->conf->max_seg / 1000 + 1;

    for ( ;; ) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                       "ts dash playlist len:%uz", dash->playlist_len);

        data = ngx_alloc(dash->playlist_len, ts->log);
        if (data == NULL) {
            return NGX_ERROR;
        }

        p = data;
        last = data + dash->playlist_len;

        p = ngx_slprintf(p, last,
                "<?xml version=\"1.0\"?>\n"
                "<MPD\n"
                "    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
                "    xmlns=\"urn:mpeg:DASH:schema:MPD:2011\"\n"
                "    xsi:schemaLocation=\"urn:mpeg:DASH:schema:MPD:2011 "
                                                             "DASH-MPD.xsd\"\n"
                "    type=\"dynamic\"\n"
                "    availabilityStartTime=\"%s\"\n"
                "    publishTime=\"%s\"\n"
                "    minimumUpdatePeriod=\"PT%uiS\"\n"
                "    minBufferTime=\"PT%uiS\"\n"
                "    timeShiftBufferDepth=\"PT%uiS\"\n"
                "    profiles=\"urn:hbbtv:dash:profile:isoff-live:2012,"
                               "urn:mpeg:dash:profile:isoff-live:2011\">\n"
                "  <Period\n"
                "      id=\"0\"\n"
                "      start=\"PT0S\">\n",
                avail_start_time, pub_time, min_update, min_buftime, buf_depth);

        for (i = 0; i < dash->nsets; i++) {
            set = &dash->sets[i];

            p = ngx_slprintf(p, last,
                    "    <AdaptationSet\n"
                    "        segmentAlignment=\"true\"\n"
                    "        mimeType=\"%s/mp4\">\n",
                    set->video ? "video" : "audio");
/*
            p = ngx_slprintf(p, last,
                    "      <AudioChannelConfiguration\n"
                    "          schemeIdUri=\"urn:mpeg:dash:"
                    "23003:3:audio_channel_configuration:2011\"\n"
                    "          value=\"6\"/>\n");
*/
            for (j = 0; j < set->nreps; j++) {
                rep = &set->reps[j];

                if (rep->bandwidth == 0) {
                    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0,
                                   "ts dash bandwidth not available");
                    ngx_free(data);
                    return NGX_OK;
                }

                pid = rep->es->pid;
                bandwidth = rep->bandwidth;

                ngx_ts_dash_format_codec(codec, rep);

                p = ngx_slprintf(p, last,
                        "      <Representation\n"
                        "          id=\"%ui\"\n"
                        "          codecs=\"%s\"\n"
                        "          bandwidth=\"%ui\">\n"
                        "        <SegmentTemplate\n"
                        "            timescale=\"90000\"\n"
                        "            media=\"$RepresentationID$.$Time$.mp4\"\n"
                        "            initialization="
                                           "\"$RepresentationID$.init.mp4\">\n"
                        "          <SegmentTimeline>\n",
                        pid, codec, bandwidth);

                for (k = 0; k < rep->nsegs; k++) {
                    seg = &rep->segs[(rep->seg + k) % rep->nsegs];

                    if (seg->duration) {
                        p = ngx_slprintf(p, last,
                                "            <S t=\"%uL\" d=\"%uL\"/>\n",
                                seg->start, seg->duration);
                    }
                }

                p = ngx_slprintf(p, last,
                        "          </SegmentTimeline>\n"
                        "        </SegmentTemplate>\n"
                        "      </Representation>\n");
            }

            p = ngx_slprintf(p, last,
                    "    </AdaptationSet>\n");
        }

        p = ngx_slprintf(p, last,
                "  </Period>\n"
                "</MPD>\n");

        if (p != last) {
            break;
        }

        ngx_free(data);

        dash->playlist_len *= 2;
    }

    len = p - data;

    if (ngx_ts_dash_write_file(dash->mpd_tmp_path, dash->mpd_path, data, len,
                               ts->log)
        != NGX_OK)
    {
        ngx_free(data);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_dash_write_file(u_char *path1, u_char *path2, u_char *data, size_t len,
    ngx_log_t *log)
{
    ssize_t    n;
    ngx_fd_t   fd;
    ngx_err_t  err;

    fd = ngx_open_file(path1,
                       NGX_FILE_WRONLY,
                       NGX_FILE_TRUNCATE,
                       NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", path1);
        return NGX_ERROR;
    }

    n = ngx_write_fd(fd, data, len);

    err = errno;

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", path1);
        return NGX_ERROR;
    }

    if (n < 0) {
        ngx_log_error(NGX_LOG_ALERT, log, err,
                      ngx_write_fd_n " to \"%s\" failed", path1);
        return NGX_ERROR;
    }

    if ((size_t) n != len) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "incomplete write to \"%s\"", path1);
        return NGX_ERROR;
    }

    if (path2) {
        if (ngx_rename_file(path1, path2) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_rename_file_n " \"%s\" to \"%s\" failed",
                          path1, path2);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_ts_dash_format_datetime(u_char *p, time_t t)
{
    struct tm  tm;

    ngx_libc_gmtime(t, &tm);

    if (strftime((char *) p, NGX_TS_DASH_DATETIME_LEN, "%Y-%m-%dT%H:%M:%SZ",
                 &tm)
        == 0)
    {
        *p = 0;
    }
}


static void
ngx_ts_dash_format_codec(u_char *p, ngx_ts_dash_rep_t *rep)
{
    u_char       type;
    ngx_uint_t   profile, compat, level, oti;

    type = rep->es->type;

    if (type == NGX_TS_VIDEO_AVC && rep->sps_len >= 4) {
        profile = rep->sps[1];
        compat = rep->sps[2];
        level = rep->sps[3];

        ngx_sprintf(p, "avc1.%02uXi%02uXi%02uXi%Z", profile, compat, level);
        return;
    }

    if (type == NGX_TS_AUDIO_AAC && rep->adts) {
        profile = (rep->adts[2] >> 6) + 1;
        ngx_sprintf(p, "mp4a.40.%ui%Z", profile);
        return;
    }

    oti = ngx_ts_dash_get_oti(type);

    ngx_sprintf(p, "mp4%c.%02uXi%Z", rep->es->video ? 'v' : 'a', oti);
}


static ngx_int_t
ngx_ts_dash_update_init_segments(ngx_ts_dash_t *dash)
{
    size_t              len;
    u_char             *data;
    ngx_uint_t          i, j;
    ngx_ts_stream_t    *ts;
    ngx_ts_dash_set_t  *set;
    ngx_ts_dash_rep_t  *rep;

    ts = dash->ts;

    for (i = 0; i < dash->nsets; i++) {
        set = &dash->sets[i];

        for (j = 0; j < set->nreps; j++) {
            rep = &set->reps[j];

            if (rep->bandwidth == 0) {
                continue;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                           "ts dash write init segment \"%s\"", rep->init_path);

            /* XXX ensure buf size */
            data = ngx_alloc(1024 + rep->sps_len + rep->pps_len, ts->log);
            if (data == NULL) {
                return NGX_ERROR;
            }

            len = ngx_ts_dash_write_init_segment(data, rep) - data;

            if (ngx_ts_dash_write_file(rep->init_tmp_path, rep->init_path,
                                       data, len, ts->log)
                != NGX_OK)
            {
                ngx_free(data);
                return NGX_ERROR;
            }

            ngx_free(data);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_dash_open_segment(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep)
{
    ngx_buf_t    *b;
    ngx_ts_es_t  *es;

    if (rep->meta) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, dash->ts->log, 0,
                   "ts dash open segment \"%V%uL.mp4\"",
                   &rep->path, rep->seg_dts);

    es = rep->es;

    ngx_memzero(&rep->subs, sizeof(ngx_ts_dash_subs_t));

    rep->seg_pts = es->pts;
    rep->seg_dts = es->dts;

    rep->nsamples = 0;
    rep->nmeta = 0;
    rep->ndata = 0;

    /* buffer is big enough to fit initial metadata */

    rep->meta = ngx_ts_dash_get_buffer(dash);
    if (rep->meta == NULL) {
        return NGX_ERROR;
    }

    rep->last_meta = rep->meta;

    b = rep->meta->buf;

    b->last = ngx_ts_dash_write_segment_meta(b->last, rep);

    rep->data = ngx_ts_dash_get_buffer(dash);
    if (rep->data == NULL) {
        return NGX_ERROR;
    }

    rep->last_data = rep->data;

    b = rep->data->buf;

    b->last = ngx_ts_dash_write_segment_data(b->last, rep);

    return NGX_OK;
}


static ngx_msec_t
ngx_ts_dash_file_manager(void *data)
{
    ngx_ts_dash_conf_t *dash = data;

    ngx_tree_ctx_t  tree;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                  "ts dash file manager");

    tree.init_handler = NULL;
    tree.file_handler = ngx_ts_dash_manage_file;
    tree.pre_tree_handler = ngx_ts_dash_manage_directory;
    tree.post_tree_handler = ngx_ts_dash_delete_directory;
    tree.spec_handler = ngx_ts_dash_delete_file;
    tree.data = dash;
    tree.alloc = 0;
    tree.log = ngx_cycle->log;

    (void) ngx_walk_tree(&tree, &dash->path->name);

    return dash->max_seg * dash->nsegs;
}


static ngx_int_t
ngx_ts_dash_manage_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_ts_dash_conf_t *dash = ctx->data;

    time_t  age, max_age;

    age = ngx_time() - ctx->mtime;

    max_age = 0;

    if (path->len >= 4
        && ngx_memcmp(path->data + path->len - 4, ".mpd", 4) == 0)
    {
        max_age = dash->max_seg * dash->nsegs / 1000;
    }

    if (path->len >= 4
        && ngx_memcmp(path->data + path->len - 4, ".mp4", 4) == 0)
    {
        max_age = dash->max_seg * dash->nsegs / 500;
    }

    if (path->len >= 4
        && ngx_memcmp(path->data + path->len - 4, ".tmp", 4) == 0)
    {
        max_age = 10;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "ts dash file \"%s\", age:%T, max_age:%T",
                   path->data, age, max_age);

    if (age < max_age) {
        return NGX_OK;
    }

    return ngx_ts_dash_delete_file(ctx, path);
}


static ngx_int_t
ngx_ts_dash_manage_directory(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    return NGX_OK;
}


static ngx_int_t
ngx_ts_dash_delete_directory(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "ts dash delete dir: \"%s\"", path->data);

    /* non-empty directory will not be removed anyway */

    /* TODO count files instead */

    (void) ngx_delete_dir(path->data);

    return NGX_OK;
}


static ngx_int_t
ngx_ts_dash_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "ts dash file delete: \"%s\"", path->data);

    if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", path->data);
    }

    return NGX_OK;
}


char *
ngx_ts_dash_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ssize_t              max_size;
    ngx_str_t           *value, s;
    ngx_int_t            v;
    ngx_uint_t           i, nsegs, clean;
    ngx_msec_t           min_seg, max_seg, analyze;
    ngx_ts_dash_conf_t  *dash, **field;

    field = (ngx_ts_dash_conf_t **) (p + cmd->offset);

    if (*field != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    dash = ngx_pcalloc(cf->pool, sizeof(ngx_ts_dash_conf_t));
    if (dash == NULL) {
        return NGX_CONF_ERROR;
    }

    dash->path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (dash->path == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    dash->path->name = value[1];

    if (dash->path->name.data[dash->path->name.len - 1] == '/') {
        dash->path->name.len--;
    }

    if (ngx_conf_full_name(cf->cycle, &dash->path->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    min_seg = 5000;
    max_seg = 0;
    analyze = 0;
    max_size = 16 * 1024 * 1024;
    nsegs = 6;
    clean = 1;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "segment=", 8) == 0) {

            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            min_seg = ngx_parse_time(&s, 0);
            if (min_seg == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid segment duration value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_segment=", 12) == 0) {

            s.len = value[i].len - 12;
            s.data = value[i].data + 12;

            max_seg = ngx_parse_time(&s, 0);
            if (max_seg == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max segment duration value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "analyze=", 8) == 0) {

            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            analyze = ngx_parse_time(&s, 0);
            if (analyze == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid analyze duration value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_size=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            max_size = ngx_parse_size(&s);
            if (max_size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max segment size value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "segments=", 7) == 0) {

            v = ngx_atoi(value[i].data + 9, value[i].len - 9);
            if (v == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid segments number value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            nsegs = v;

            continue;
        }

        if (ngx_strcmp(value[i].data, "noclean") == 0) {
            clean = 0;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    dash->min_seg = min_seg;

    /*
     * dash.js requires that segments do not
     * differ in duration by a factor more than 2
     */

    dash->max_seg = max_seg ? max_seg : min_seg * 2;
    dash->analyze = analyze ? analyze : min_seg * 2;
    dash->max_size = max_size;
    dash->nsegs = nsegs;

    if (clean) {
        dash->path->manager = ngx_ts_dash_file_manager;
    }

    dash->path->data = dash;
    dash->path->conf_file = cf->conf_file->file.name.data;
    dash->path->line = cf->conf_file->line;

    if (ngx_add_path(cf, &dash->path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *field = dash;

    return NGX_CONF_OK;
}
