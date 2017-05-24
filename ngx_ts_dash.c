
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_dash.h"


#define NGX_TS_DASH_BUFFER_SIZE  1024


ngx_ts_dash_t *
ngx_ts_dash_create(ngx_ts_dash_conf_t *conf, ngx_ts_stream_t *ts,
    ngx_str_t *name)
{
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
    if (hls->path == NULL) {
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

    rep->path.len = ngx_sprintf("%s/%ui.", (ngx_uint_t) es->pid)
                    - rep->path.data;

    return dash;
}


ngx_int_t
ngx_ts_dash_write_frame(ngx_ts_dash_t *dash, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs)
{
    ngx_uint_t          i, j;
    ngx_ts_dash_set_t  *set;
    ngx_ts_dash_rep_t  *rep;

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

    /* XXX append metadata */
    /* XXX append data, strip off h264/aac headers */

    /* XXX increment: trun_size, traf_size, sidx_ref_size */
    /* XXX increment data offset */
    return NGX_OK;
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
    set->start = rep->seg_pts;
    seg->duration = d;

    return NGX_OK;
}


static ngx_int_t
ngx_ts_dash_open_segment(ngx_ts_dash_t *dash, ngx_ts_dash_rep_t *rep)
{
    u_char           *p, *ps;
    ngx_buf_t        *b;
    ngx_ts_stream_t  *ts;

    ts = dash->ts;

    if (rep->meta) {
        return NGX_OK;
    }

    if (dash->free) {
        rep->meta = dash->free;
        dash->free = dash->free->next;
        b = rep->meta->buf;

    } else {
        rep->meta = ngx_alloc_chain_link(ts->pool);
        if (rep->meta == NULL) {
            return NGX_ERROR;
        }

        b = ngx_create_temp_buf(ts->pool, NGX_TS_DASH_BUFFER_SIZE);
        if (b == NULL) {
            return NGX_ERROR;
        }

        rep->meta->next = NULL;
        rep->meta->buf = b;
    }

    rep->seg_pts = es->pts;

    /* buffer is big enough to fit initial metadata */

    ngx_ts_dash_write_styp(b);
    ngx_ts_dash_write_sidx(b);
    ngx_ts_dash_write_moof(b);

    return NGX_OK;
}


static u_char *
ngx_ts_dash_box(ngx_buf_t *b, const char type[4])
{
    /*
     * class Box
     * ISO/IEC 14496-12:2008(E)
     * 4.2 Object Structure, p. 4
     */

    u_char  *p;

    p = b->last;

    /* size */
    b->last += 4;

    /* type */
    ngx_ts_dash_write_box(b, type);

    return p;
}


static void
ngx_ts_dash_write32(ngx_buf_t *b, uint32_t v)
{
    *b->last++ = (u_char) (v >> 24);
    *b->last++ = (u_char) (v >> 16);
    *b->last++ = (u_char) (v >> 8);
    *b->last++ = (u_char) v;
}


static void
ngx_ts_dash_write_size(ngx_buf_t *b, u_char *p)
{
    uint32_t  v;

    v = b->last - p;

    *p++ = (u_char) (v >> 24);
    *p++ = (u_char) (v >> 16);
    *p++ = (u_char) (v >> 8);
    *p++ = (u_char) v;
}


static void
ngx_ts_dash_write_box(ngx_buf_t *b, const char box[4])
{
    b->last = ngx_cpymem(b->last, box, 4);
}


static void
ngx_ts_dash_write_styp(ngx_buf_t *b)
{
    /*
     * ETSI TS 126 244 V12.3.0 (2014-10)
     * 13.2 Segment types, p. 52
     */

    /*
     * ISO/IEC 14496-12:2008(E)
     * 4.3 File Type Box, p. 4
     */

    u_char  *p;

    p = ngx_ts_dash_box(p, "styp");

    /* major_brand */
    ngx_ts_dash_write_box(p, "iso6");

    /* TODO version */
    /* minor_version */
    ngx_ts_dash_write32(p, 1);

    /* TODO brands */
    /* compatible_brands */
    ngx_ts_dash_write_box(p, "isom");
    ngx_ts_dash_write_box(p, "iso6");
    ngx_ts_dash_write_box(p, "dash");

    /* size */
    ngx_ts_dash_write_size(b, p);
}


static void
ngx_ts_dash_write_sidx(ngx_buf_t *b)
{
    /*
     * ETSI TS 126 244 V12.3.0 (2014-10)
     * 13.4 Segment Index Box, p. 53
     */

    u_char  *p;

    p = ngx_ts_dash_full_box(p, "sidx", 0);

    /* size */
    ngx_ts_dash_write_size(b, p);
}


static void
ngx_ts_dash_write_moof(ngx_buf_t *b)
{
    /*
     * ISO/IEC 14496-12:2008(E)
     * 8.8.4 Movie Fragment Box, p. 45
     */

    u_char  *p;

    ps = ngx_ts_dash_box(p, "moof");

    ngx_ts_dash_full_box(p, "mfhd", 4);

    /* sequence_number */
    ngx_ts_dash_write32(p, rep->seg);

    ps = ngx_ts_dash_box(p, "traf");

    /* XXX tfhd tfdt trun */

    b->last = p;
}


ngx_msec_t
ngx_ts_dash_file_manager(void *data)
{
    /* XXX */
    return 10000;
}
