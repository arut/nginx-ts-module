
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_dash.h"


#define NGX_TS_DASH_BUFFER_SIZE  1024


static ngx_chain_t* ngx_ts_dash_get_buffer(ngx_ts_dash_t *dash);
static ngx_int_t ngx_ts_dash_close_segment(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep);
static void ngx_ts_dash_fill_subs(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep);
static ngx_int_t ngx_ts_dash_open_segment(ngx_ts_dash_t *dash,
    ngx_ts_dash_rep_t *rep);

static u_char *ngx_ts_dash_box(u_char *p, const char type[4]);
static u_char *ngx_ts_dash_full_box(u_char *p, const char type[4],
    u_char version, uint32_t flags);
static u_char *ngx_ts_dash_write64(u_char *p, uint64_t v);
static u_char *ngx_ts_dash_write32(u_char *p, uint32_t v);
static uint32_t ngx_ts_dash_read32(u_char *p);

static u_char *ngx_ts_dash_write_styp(u_char *p);
static u_char *ngx_ts_dash_write_sidx(u_char *p, ngx_ts_dash_subs_t *subs);
static u_char *ngx_ts_dash_write_moof(u_char *p, ngx_ts_dash_subs_t *subs,
    ngx_uint_t video);
static u_char *ngx_ts_dash_write_mfhd(u_char *p, ngx_ts_dash_subs_t *subs);
static u_char *ngx_ts_dash_write_traf(u_char *p, ngx_ts_dash_subs_t *subs,
    ngx_uint_t video);
static u_char *ngx_ts_dash_write_tfhd(u_char *p);
static u_char *ngx_ts_dash_write_tfdt(u_char *p, ngx_ts_dash_subs_t *subs);
static u_char *ngx_ts_dash_write_trun(u_char *p, ngx_ts_dash_subs_t *subs,
    ngx_uint_t video);
static u_char *ngx_ts_dash_write_mdat(u_char *p, ngx_ts_dash_subs_t *subs);


ngx_ts_dash_t *
ngx_ts_dash_create(ngx_ts_dash_conf_t *conf, ngx_ts_stream_t *ts,
    ngx_str_t *name)
{
    size_t              len, dirlen;
    ngx_ts_dash_t      *dash;
    ngx_ts_dash_rep_t  *rep;
    ngx_ts_dash_set_t  *set;

    dash = ngx_pcalloc(ts->pool, sizeof(ngx_ts_dash_t));
    if (dash == NULL) {
        return NULL;
    }

    dash->conf = conf;
    dash->ts = ts;

    dirlen = conf->path->name.len + 1 + name->len;

    dash->path = ngx_pnalloc(ts->pool, dirlen + 1);
    if (dash->path == NULL) {
        return NULL;
    }

    ngx_sprintf(dash->path, "%V/%V%Z", &conf->path->name, name);

    /*XXX*/

    dash->nsets = 1;
    dash->sets = ngx_pcalloc(ts->pool, dash->nsets * sizeof(ngx_ts_dash_set_t));
    if (dash->sets == NULL) {
        return NULL;
    }

    set = dash->sets;

    set->nreps = 1;
    set->reps = ngx_pcalloc(ts->pool, set->nreps * sizeof(ngx_ts_dash_rep_t));
    if (set->reps == NULL) {
        return NULL;
    }

    rep = set->reps;

    rep->es = ts->progs->es; /* XXX first es whatever it is */

    rep->nsegs = conf->nsegs;
    rep->segs = ngx_pcalloc(ts->pool,
                            rep->nsegs * sizeof(ngx_ts_dash_segment_t));
    if (rep->segs == NULL) {
        return NULL;
    }

    len = dirlen + 1 + NGX_INT_T_LEN + 1 + NGX_INT_T_LEN + sizeof(".mp4");

    rep->path.data = ngx_pnalloc(ts->pool, len);
    if (rep->path.data == NULL) {
        return NULL;
    }

    rep->path.len = ngx_sprintf(rep->path.data, "%s/%ui.",
                                (ngx_uint_t) rep->es->pid)
                    - rep->path.data;

    return dash;
}


ngx_int_t
ngx_ts_dash_write_frame(ngx_ts_dash_t *dash, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs)
{
    size_t              size, n;
    u_char             *p;
    ngx_buf_t          *b;
    ngx_uint_t          i, j;
    ngx_chain_t        *cl;
    ngx_ts_stream_t    *ts;
    ngx_ts_dash_set_t  *set;
    ngx_ts_dash_rep_t  *rep;

    ts = dash->ts;

    for (i = 0; i < dash->nsets; i++) {
        set = &dash->sets[i];

        for (j = 0; j < set->nreps; j++) {
            rep =  &set->reps[j];

            if (rep->es == es) {
                goto found;
            }
        }
    }

    ngx_log_error(NGX_LOG_ERR, ts->log, 0, "TS elementary stream not found");

    return NGX_OK; /* XXX NGX_ERROR */

found:

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts dash frame pid:%ud",
                   (unsigned) rep->es->pid);

    if (ngx_ts_dash_close_segment(dash, rep) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_ts_dash_open_segment(dash, rep) != NGX_OK) {
        return NGX_ERROR;
    }

    for (cl = rep->data; cl->next; cl = cl->next);

    /* XXX parse AAC ADTS */

    /* XXX
     * ISO/IEC 14496-10:2004(E)
     * Annex B. Byte Stream Format, p. 216
     */

    /* XXX
     * ISO/IEC 14496-15:2004(E)
     * 5.3.4.2 Sample format, p. 15
     */

    size = 0;

    while (bufs) {
        n = ngx_min(bufs->buf->last - bufs->buf->pos,
                    cl->buf->end - cl->buf->last);

        ngx_memcpy(cl->buf->last, bufs->buf->pos, n);

        cl->buf->last += n;
        bufs->buf->pos += n;
        size += n;

        if (bufs->buf->pos == bufs->buf->last) {
            bufs = bufs->next;
        }

        if (cl->buf->last == cl->buf->end) {
            cl->next = ngx_ts_dash_get_buffer(dash);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
        }
    }

    rep->ndata += size;

    es = rep->es;

    rep->nsamples++;

    n = rep->es->video ? 16 : 4;

    for (cl = rep->meta; cl->next; cl = cl->next);

    b = cl->buf;

    if ((size_t) (b->end - b->last) < n) {
        cl->next = ngx_ts_dash_get_buffer(dash);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        b = cl->buf;
    }

    p = b->last;
    b->last += n;
    rep->nmeta += n;

    if (es->video) {
        /* sample_duration */
        if (rep->subs.sample_duration) {
            ngx_ts_dash_write32(rep->subs.sample_duration, es->pts - rep->pts);
        }

        rep->subs.sample_duration = p;
        p = ngx_ts_dash_write32(p, 0);

        /* sample_size */
        p = ngx_ts_dash_write32(p, size);

        /* sample_flags */
        p = ngx_ts_dash_write32(p, es->rand ? 0x00000000 : 0x00010000); /*XXX*/

        /* sample_composition_time_offset */
        ngx_ts_dash_write32(p, es->pts - es->dts);

    } else {
        /* sample_size */
        ngx_ts_dash_write32(p, size);
    }

    rep->pts = es->pts;

    return NGX_OK;
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
        return out;
    }

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
    file.name.len = ngx_sprintf(path->data + path->len, "%ui.mp4%Z", rep->seg)
                    - path->data - 1;

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
        if (ngx_create_dir(dash->path, 0700) == NGX_FILE_ERROR) {
            err = ngx_errno;

            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_CRIT, ts->log, err,
                              ngx_create_dir_n " \"%s\" failed", dash->path);
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
        ngx_ts_dash_write32(subs->sample_duration, rep->es->pts - rep->pts);
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
ngx_ts_dash_open_segment(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep)
{
    ngx_buf_t    *b;
    ngx_ts_es_t  *es;

    if (rep->meta) {
        return NGX_OK;
    }

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

    b = rep->meta->buf;

    b->last = ngx_ts_dash_write_styp(b->last);
    b->last = ngx_ts_dash_write_sidx(b->last, &rep->subs);
    b->last = ngx_ts_dash_write_moof(b->last, &rep->subs, es->video);

    rep->data = ngx_ts_dash_get_buffer(dash);
    if (rep->data == NULL) {
        return NGX_ERROR;
    }

    b = rep->data->buf;

    b->last = ngx_ts_dash_write_mdat(b->last, &rep->subs);

    return NGX_OK;
}


static u_char *
ngx_ts_dash_box(u_char *p, const char type[4])
{
    /*
     * class Box
     * ISO/IEC 14496-12:2008(E)
     * 4.2 Object Structure, p. 4
     */

    /* size */
    p += 4;

    /* type */
    p = ngx_cpymem(p, type, 4);

    return p;
}


static u_char *
ngx_ts_dash_full_box(u_char *p, const char type[4], u_char version,
    uint32_t flags)
{
    /*
     * class Box
     * ISO/IEC 14496-12:2008(E)
     * 4.2 Object Structure, p. 4
     */

    /* size */
    p += 4;

    /* version */
    *p++ = version;

    /* flags */
    *p++ = (u_char) (flags >> 16);
    *p++ = (u_char) (flags >> 8);
    *p++ = (u_char) flags;

    /* type */
    p = ngx_cpymem(p, type, 4);

    return p;
}


static u_char *
ngx_ts_dash_write64(u_char *p, uint64_t v)
{
    *p++ = (u_char) (v >> 56);
    *p++ = (u_char) (v >> 48);
    *p++ = (u_char) (v >> 40);
    *p++ = (u_char) (v >> 32);
    *p++ = (u_char) (v >> 24);
    *p++ = (u_char) (v >> 16);
    *p++ = (u_char) (v >> 8);
    *p++ = (u_char) v;

    return p;
}


static u_char *
ngx_ts_dash_write32(u_char *p, uint32_t v)
{
    *p++ = (u_char) (v >> 24);
    *p++ = (u_char) (v >> 16);
    *p++ = (u_char) (v >> 8);
    *p++ = (u_char) v;

    return p;
}


static uint32_t
ngx_ts_dash_read32(u_char *p)
{
    uint32_t  v;

    v = *p++;
    v = (v << 8) + *p++;
    v = (v << 8) + *p++;
    v = (v << 8) + *p;

    return v;
}


static u_char *
ngx_ts_dash_write_styp(u_char *p)
{
    /*
     * ETSI TS 126 244 V12.3.0 (2014-10)
     * 13.2 Segment types, p. 52
     */

    /*
     * ISO/IEC 14496-12:2008(E)
     * 4.3 File Type Box, p. 4
     */

    u_char  *ps;

    ps = p;

    p = ngx_ts_dash_box(p, "styp");

    /* major_brand */
    p = ngx_cpymem(p, "iso6", 4); /* XXX 3gh9 */

    /* TODO version */
    /* minor_version */
    p = ngx_ts_dash_write32(p, 1);

    /* TODO brands */
    /* compatible_brands */
    p = ngx_cpymem(p, "isom", 4);
    p = ngx_cpymem(p, "iso6", 4);
    p = ngx_cpymem(p, "dash", 4);

    /* size */
    ngx_ts_dash_write32(ps, p - ps);

    return p;
}


static u_char *
ngx_ts_dash_write_sidx(u_char *p, ngx_ts_dash_subs_t *subs)
{
    /*
     * ETSI TS 126 244 V12.3.0 (2014-10)
     * 13.4 Segment Index Box, p. 53
     */

    /* TODO ISO/IEC 14496-12:2012 entry */

    u_char  *ps;

    ps = p;

    p = ngx_ts_dash_full_box(p, "sidx", 1, 0);

    /* reference_ID */
    p = ngx_ts_dash_write32(p, 1);

    /* timescale */
    p = ngx_ts_dash_write32(p, 90000);

    /* earliest_presentation_time */
    subs->pts = p;
    p = ngx_ts_dash_write64(p, 0);

    /* first_offset */
    p = ngx_ts_dash_write64(p, 0);

    /* reference_count */
    p = ngx_ts_dash_write32(p, 1);

    /* referenced_size */
    subs->moof_mdat = p;
    p = ngx_ts_dash_write32(p, 0);

    /* subsegment_duration */
    subs->duration = p;
    p = ngx_ts_dash_write32(p, 0);

    /* starts_with_SAP, SAP_type, SAP_delta_time */
    p = ngx_ts_dash_write32(p, 0x80000000);

    /* size */
    ngx_ts_dash_write32(ps, p - ps);

    return p;
}


static u_char *
ngx_ts_dash_write_moof(u_char *p, ngx_ts_dash_subs_t *subs, ngx_uint_t video)
{
    /*
     * ISO/IEC 14496-12:2008(E)
     * 8.8.4 Movie Fragment Box, p. 45
     */

    u_char  *ps;

    subs->moof = p;

    ps = p;

    p = ngx_ts_dash_box(p, "moof");

    p = ngx_ts_dash_write_mfhd(p, subs);
    p = ngx_ts_dash_write_traf(p, subs, video);

    /* size */
    ngx_ts_dash_write32(ps, p - ps);

    return p;
}


static u_char *
ngx_ts_dash_write_mfhd(u_char *p, ngx_ts_dash_subs_t *subs)
{
    /*
     * ISO/IEC 14496-12:2008(E)
     * 8.8.5 Movie Fragment Header Box, p. 45
     */

    u_char  *ps;

    ps = p;

    p = ngx_ts_dash_full_box(p, "mfhd", 0, 0);

    /* sequence_number */
    subs->seq = p;
    p = ngx_ts_dash_write32(p, 0);

    /* size */
    ngx_ts_dash_write32(ps, p - ps);

    return p;
}


static u_char *
ngx_ts_dash_write_traf(u_char *p, ngx_ts_dash_subs_t *subs, ngx_uint_t video)
{
    /*
     * ISO/IEC 14496-12:2008(E)
     * 8.8.6 Track Fragment Box, p. 46
     */

    u_char  *ps;

    subs->traf = p;

    ps = p;

    p = ngx_ts_dash_box(p, "traf");

    p = ngx_ts_dash_write_tfhd(p);
    p = ngx_ts_dash_write_tfdt(p, subs);
    p = ngx_ts_dash_write_trun(p, subs, video);

    /* size */
    ngx_ts_dash_write32(ps, p - ps);

    return p;
}


static u_char *
ngx_ts_dash_write_tfhd(u_char *p)
{
    /*
     * ISO/IEC 14496-12:2008(E)
     * 8.8.7 Track Fragment Header Box, p. 46
     */

    u_char  *ps;

    ps = p;

    p = ngx_ts_dash_full_box(p, "tfhd", 0, 0);

    /* track_ID */
    p = ngx_ts_dash_write32(p, 1);

    /* size */
    ngx_ts_dash_write32(ps, p - ps);

    return p;
}


static u_char *
ngx_ts_dash_write_tfdt(u_char *p, ngx_ts_dash_subs_t *subs)
{
    /* 
     * ETSI TS 126 244 V12.3.0 (2014-10)
     * 13.5 Track Fragment Decode Time Box, p. 55
     */

    u_char  *ps;

    ps = p;

    p = ngx_ts_dash_full_box(p, "tfdt", 1, 0);

    /* baseMediaDecodeTime */
    subs->dts = p;
    p = ngx_ts_dash_write64(p, 0);

    /* size */
    ngx_ts_dash_write32(ps, p - ps);

    return p;
}


static u_char *
ngx_ts_dash_write_trun(u_char *p, ngx_ts_dash_subs_t *subs, ngx_uint_t video)
{
    /*
     * ISO/IEC 14496-12:2008(E)
     * 8.8.8 Track Fragment Run Box, p. 47
     */

    u_char    *ps;
    uint32_t   flags;

    flags = 0x000001         /* data-offset-present */
            | 0x000200;      /* sample-size-present */

    if (video) {
       flags |= 0x000100     /* sample-duration-present */
                | 0x000400   /* sample-flags-present */
                | 0x000800;  /* sample-composition-time-offset-present */
    }

    subs->trun = p;

    ps = p;

    p = ngx_ts_dash_full_box(p, "trun", 0, flags);

    /* sample_count */
    subs->nsamples = p;
    p = ngx_ts_dash_write32(p, 0);

    /* data_offset */
    subs->moof_data = p;
    p = ngx_ts_dash_write32(p, 0);

    /* size */
    ngx_ts_dash_write32(ps, p - ps);

    return p;
}


static u_char *
ngx_ts_dash_write_mdat(u_char *p, ngx_ts_dash_subs_t *subs)
{

    u_char  *ps;

    subs->mdat = p;

    ps = p;

    p = ngx_ts_dash_box(p, "mdat");

    /* size */
    ngx_ts_dash_write32(ps, p - ps);

    return p;
}


ngx_msec_t
ngx_ts_dash_file_manager(void *data)
{
    /* XXX */
    return 10000;
}
