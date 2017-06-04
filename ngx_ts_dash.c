
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_dash.h"


#define NGX_TS_DASH_BUFFER_SIZE   1024

#define NGX_TS_DASH_DATETIME_LEN  sizeof("2000-12-31T23:59:59")
#define NGX_TS_DASH_CODEC_LEN     sizeof("avc1.PPPCCCLLL")


static void ngx_ts_dash_cleanup(void *data);
static ngx_int_t ngx_ts_dash_handler(ngx_ts_handler_data_t *hd);
static ngx_int_t ngx_ts_dash_pmt_handler(ngx_ts_dash_t *dash);
static ngx_int_t ngx_ts_dash_pes_handler(ngx_ts_dash_t *dash,
    ngx_ts_program_t *prog, ngx_ts_es_t *es, ngx_chain_t *bufs);
static ssize_t ngx_ts_dash_copy_avc(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    ngx_chain_t *bufs);
static ssize_t ngx_ts_dash_copy_aac(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    ngx_chain_t *bufs);
static ssize_t ngx_ts_dash_copy_default(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep, ngx_chain_t *bufs, u_char *p);
static ngx_chain_t* ngx_ts_dash_get_buffer(ngx_ts_dash_t *dash);
static ngx_int_t ngx_ts_dash_close_segment(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep);
static void ngx_ts_dash_fill_subs(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep);
static ngx_int_t ngx_ts_dash_update_playlist(ngx_ts_dash_t *dash);
static ngx_int_t ngx_ts_dash_write_file(u_char *path1, u_char *path2,
    u_char *data, size_t len, ngx_log_t *log);
static void ngx_ts_dash_format_datetime(u_char *p, time_t t);
static void ngx_ts_dash_format_codec(u_char *p, ngx_ts_dash_rep_t *rep);
static ngx_int_t ngx_ts_dash_write_init_segments(ngx_ts_dash_t *dash);
static ngx_int_t ngx_ts_dash_open_segment(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep);
static ngx_msec_t ngx_ts_dash_file_manager(void *data);


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

            len = dash->path.len + 1 + NGX_INT_T_LEN + sizeof(".init.mp4");

            rep->init_path = ngx_pnalloc(ts->pool, len);
            if (rep->init_path == NULL) {
                return NGX_ERROR;
            }

            ngx_sprintf(rep->init_path, "%V/%ui.init.mp4%Z",
                        &dash->path, (ngx_uint_t) es->pid);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_dash_pes_handler(ngx_ts_dash_t *dash, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs)
{
    u_char             *p;
    size_t              size, n;
    ssize_t             rc;
    int64_t             d, analyze;
    ngx_buf_t          *b;
    ngx_uint_t          i, j;
    ngx_chain_t        *cl;
    ngx_ts_stream_t    *ts;
    ngx_ts_dash_set_t  *set;
    ngx_ts_dash_rep_t  *rep;

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

    if (ngx_ts_dash_close_segment(dash, rep) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_ts_dash_open_segment(dash, rep) != NGX_OK) {
        return NGX_ERROR;
    }

    switch (es->type) {
    case NGX_TS_VIDEO_AVC:
        rc = ngx_ts_dash_copy_avc(dash, rep, bufs);
        break;

    case NGX_TS_AUDIO_AAC:
        rc = ngx_ts_dash_copy_aac(dash, rep, bufs);
        break;

    default:
        rc = ngx_ts_dash_copy_default(dash, rep, bufs, NULL);
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    size = rc;

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
        ngx_ts_dash_write32(rep->subs.sample_duration, es->dts - rep->dts);
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

    rep->dts = es->dts;

    if (rep->bandwidth == 0) {
        if (rep->bandwidth_bytes == 0) {
            rep->bandwidth_pts = es->pts;
        }

        rep->bandwidth_bytes += size;

        d = es->pts - rep->bandwidth_pts;
        analyze = (int64_t) dash->conf->analyze * 90;

        if (d >= analyze) {
            rep->bandwidth = rep->bandwidth_bytes * 8 * 90000 / d;
        }
    }

    return NGX_OK;
}


static ssize_t
ngx_ts_dash_copy_avc(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    ngx_chain_t *bufs)
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

    for (/* void */; bufs; bufs = bufs->next) {

        for (p = bufs->buf->pos; p != bufs->buf->last; p++) {
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

    return size;
}


static ssize_t
ngx_ts_dash_copy_aac(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    ngx_chain_t *bufs)
{
    /*
     * XXX
     * ISO/IEC CD 14496-3 Subpart 4: 1998
     * 1.1.2 Audio_Data_Transport_Stream frame, ADTS, p. 10
     */

    u_char      *p, adts[9];
    ngx_uint_t   n;

    n = 0;

    for (/* void */; bufs; bufs = bufs->next) {

        for (p = bufs->buf->pos; p != bufs->buf->last; p++) {
            if (n == 9) {
                /* protection_absent == 0 */
                goto frame;
            }

            if (n == 7 && (adts[1] & 0x01)) {
                /* protection_absent == 1 */
                goto frame;
            }

            adts[n++] = *p;
        }
    }

    return NGX_ERROR;

frame:

    if (rep->adts == NULL) {
        rep->adts = ngx_pnalloc(dash->ts->pool, 7);
        if (rep->adts == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(rep->adts, adts, 7);
    }

    return ngx_ts_dash_copy_default(dash, rep, bufs, p);
}


static ssize_t
ngx_ts_dash_copy_default(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep,
    ngx_chain_t *bufs, u_char *p)
{
    size_t        n, size;
    ngx_chain_t  *cl;

    cl = rep->last_data;

    size = 0;

    while (bufs) {
        if (p == NULL) {
            p = bufs->buf->pos;
        }

        n = ngx_min(bufs->buf->last - p, cl->buf->end - cl->buf->last);

        ngx_memcpy(cl->buf->last, p, n);

        cl->buf->last += n;
        p += n;
        size += n;

        if (p == bufs->buf->last) {
            bufs = bufs->next;
            p = NULL;
        }

        if (cl->buf->last == cl->buf->end) {
            cl->next = ngx_ts_dash_get_buffer(dash);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
            rep->last_data = cl;
        }
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

    min_seg = (int64_t) dash->conf->min_seg * 90;
    max_seg = (int64_t) dash->conf->max_seg * 90;

    d = es->pts - rep->seg_pts;
    if (d < min_seg || (d < max_seg && es->video && !es->rand)) {
        return NGX_OK;
    }

    path = &rep->path;

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.name.data = path->data;
    file.name.len = ngx_sprintf(path->data + path->len, "%uL.mp4%Z",
                                rep->seg_pts)
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
    seg->start = rep->seg_pts;
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
    ngx_ts_dash_write32(subs->duration, rep->es->pts - rep->seg_pts);

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

    ts = dash->ts;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts dash update playlist \"%s\"", dash->mpd_path);

    now = ngx_time();

    if (dash->availability_start == 0) {
        dash->availability_start = now;
    }

    ngx_ts_dash_format_datetime(avail_start_time, dash->availability_start);
    ngx_ts_dash_format_datetime(pub_time, now);

    /* TODO fractions */
    min_update = dash->conf->max_seg / 1000; /* TODO */
    min_buftime = dash->conf->min_seg / 1000; /* TODO */
    buf_depth = dash->conf->max_seg * dash->conf->nsegs / 1000;

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
                "    profiles=\"urn:mpeg:dash:profile:isoff-live:2011\">\n"
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

    if (ngx_ts_dash_write_init_segments(dash) != NGX_OK) {
        ngx_free(data);
        return NGX_ERROR;
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

    if (strftime((char *) p, NGX_TS_DASH_DATETIME_LEN, "%Y-%m-%dT%H:%M:%S", &tm)
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
ngx_ts_dash_write_init_segments(ngx_ts_dash_t *dash)
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

            if (rep->init == 0) {
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                               "ts dash write init segment \"%s\"",
                               rep->init_path);

                /* XXX ensure buf size */
                data = ngx_alloc(1024 + rep->sps_len + rep->pps_len, ts->log);
                if (data == NULL) {
                    return NGX_ERROR;
                }

                len = ngx_ts_dash_write_init_segment(data, rep) - data;

                if (ngx_ts_dash_write_file(rep->init_path, NULL, data, len,
                                           ts->log)
                    != NGX_OK)
                {
                    ngx_free(data);
                    return NGX_ERROR;
                }

                ngx_free(data);

                rep->init = 1;
            }
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
                   "ts dash open segment \"%V%ui.mp4\"", &rep->path, rep->seg);

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
    /* XXX */
    return 10000;
}


char *
ngx_ts_dash_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t           *value, s;
    ngx_int_t            v;
    ngx_uint_t           i, nsegs;
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
    nsegs = 6;

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

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    dash->min_seg = min_seg;
    dash->max_seg = max_seg ? max_seg : min_seg * 3;
    dash->analyze = analyze ? analyze : min_seg * 3;
    dash->nsegs = nsegs;

    dash->path->manager = ngx_ts_dash_file_manager;
    dash->path->data = dash;
    dash->path->conf_file = cf->conf_file->file.name.data;
    dash->path->line = cf->conf_file->line;

    if (ngx_add_path(cf, &dash->path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *field = dash;

    return NGX_CONF_OK;
}
