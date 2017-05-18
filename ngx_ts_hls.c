
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_hls.h"


static void ngx_ts_hls_cleanup(void *data);
static ngx_int_t ngx_ts_hls_close_segment(ngx_ts_hls_t *hls);
static ngx_int_t ngx_ts_hls_update_playlist(ngx_ts_hls_t *hls);
static ngx_int_t ngx_ts_hls_open_segment(ngx_ts_hls_t *hls);

static ngx_int_t ngx_ts_hls_manage_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_ts_hls_manage_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_ts_hls_delete_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_ts_hls_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);


ngx_ts_hls_t *
ngx_ts_hls_create(ngx_ts_hls_conf_t *conf, ngx_ts_stream_t *ts, ngx_str_t *name)
{
    size_t               len;
    u_char              *p;
    ngx_ts_hls_t        *hls;
    ngx_pool_cleanup_t  *cln;

    hls = ngx_pcalloc(ts->pool, sizeof(ngx_ts_hls_t));
    if (hls == NULL) {
        return NULL;
    }

    hls->conf = conf;

    hls->ts = ngx_pcalloc(ts->pool, sizeof(ngx_ts_stream_t));
    if (hls->ts == NULL) {
        return NULL;
    }

    hls->ts = ts;

    hls->file.fd = NGX_INVALID_FILE;
    hls->file.log = ts->log;

    hls->nsegs = conf->nsegs;
    hls->segs = ngx_pcalloc(ts->pool,
                            sizeof(ngx_ts_hls_segment_t) * conf->nsegs);
    if (hls->segs == NULL) {
        return NULL;
    }

    /* .ts */

    len = conf->path->name.len + 1 + name->len + 1 + NGX_INT_T_LEN
          + sizeof(".ts");
    p = ngx_pnalloc(ts->pool, len);
    if (p == NULL) {
        return NULL;
    }

    hls->path.len = ngx_sprintf(p, "%V/%V", &conf->path->name, name) - p;
    hls->path.data = p;

    /* .m3u8 */

    len = conf->path->name.len + 1 + name->len + 1 + sizeof("index.m3u8");

    hls->m3u8_path = ngx_pnalloc(ts->pool, len);
    if (hls->m3u8_path == NULL) {
        return NULL;
    }

    ngx_sprintf(hls->m3u8_path, "%V/%V/index.m3u8%Z", &conf->path->name, name);

    /* .m3u8.tmp */

    len += sizeof(".tmp") - 1;

    hls->m3u8_tmp_path = ngx_pnalloc(ts->pool, len);
    if (hls->m3u8_tmp_path == NULL) {
        return NULL;
    }

    ngx_sprintf(hls->m3u8_tmp_path, "%s.tmp%Z", hls->m3u8_path);

    cln = ngx_pool_cleanup_add(ts->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_ts_hls_cleanup;
    cln->data = hls;

    return hls;
}


static void
ngx_ts_hls_cleanup(void *data)
{
    ngx_ts_hls_t *hls = data;

    int64_t                d, maxd;
    ngx_uint_t             n;
    ngx_ts_es_t           *es;
    ngx_ts_stream_t       *ts;
    ngx_ts_program_t      *prog;
    ngx_ts_hls_segment_t  *seg;

    ts = hls->ts;
    prog = ts->progs;

    if (prog == NULL) {
        return;
    }

    if (hls->file.fd != NGX_INVALID_FILE) {
        if (ngx_close_file(hls->file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, ts->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          hls->file.name.data);
        }

        hls->file.fd = NGX_INVALID_FILE;
    }

    maxd = 0;

    for (n = 0; n < prog->nes; n++) {
        es = &prog->es[n];
        if (es->ptsf) {
            d = es->pts - hls->seg_pts;
            if (maxd < d) {
                maxd = d;
            }
        }
    }

    seg = &hls->segs[hls->seg % hls->nsegs];
    seg->id = hls->seg;
    seg->duration = maxd;

    hls->seg++;
    hls->done = 1;

    (void) ngx_ts_hls_update_playlist(hls);
}


ngx_int_t
ngx_ts_hls_write_frame(ngx_ts_hls_t *hls, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs)
{
    ngx_chain_t      *out;
    ngx_ts_stream_t  *ts;

    ts = hls->ts;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts hls frame");

    if (ngx_ts_hls_close_segment(hls) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_ts_hls_open_segment(hls) != NGX_OK) {
        return NGX_ERROR;
    }

    out = ngx_ts_write_pes(ts, prog, es, bufs);
    if (out == NULL) {
        return NGX_ERROR;
    }

    if (ngx_write_chain_to_file(&hls->file, out, hls->file.offset, ts->pool)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    ngx_ts_free_chain(ts, &out);

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_close_segment(ngx_ts_hls_t *hls)
{
    int64_t                d, min_seg, max_seg;
    ngx_uint_t             n;
    ngx_ts_es_t           *es;
    ngx_ts_stream_t       *ts;
    ngx_ts_program_t      *prog;
    ngx_ts_hls_segment_t  *seg;

    ts = hls->ts;
    prog = ts->progs;

    if (hls->file.fd == NGX_INVALID_FILE) {
        /* segment not started */

        for (n = 0; n < prog->nes; n++) {
            es = &prog->es[n];

            if (es->ptsf) {
                d = es->pts - hls->seg_pts;

                if (d > 0) {
                    hls->seg_pts = es->pts;
                }
            }
        }

        return NGX_OK;
    }

    min_seg = (int64_t) hls->conf->min_seg * 90;
    max_seg = (int64_t) hls->conf->max_seg * 90;

    for (n = 0; n < prog->nes; n++) {
        es = &prog->es[n];

        if (es->ptsf) {
            d = es->pts - hls->seg_pts;

            if (d >= max_seg
                || (d >= min_seg && !prog->video)
                || (d >= min_seg && es->video && es->rand))
            {
                hls->seg_pts = es->pts;
                goto close;
            }
        }
    }

    return NGX_OK;

close:

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls close segment %ui", hls->seg);

    if (ngx_close_file(hls->file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ts->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", hls->file.name.data);
    }

    seg = &hls->segs[hls->seg % hls->nsegs];
    seg->id = hls->seg;
    seg->duration = d;

    hls->seg++;

    ngx_memzero(&hls->file, sizeof(ngx_file_t));

    hls->file.fd = NGX_INVALID_FILE;
    hls->file.log = ts->log;

    return ngx_ts_hls_update_playlist(hls);
}


static ngx_int_t
ngx_ts_hls_update_playlist(ngx_ts_hls_t *hls)
{
    size_t                 n;
    u_char                *p, *data;
    ssize_t                ret;
    uint64_t               maxd;
    ngx_fd_t               fd;
    ngx_uint_t             i, ms, td;
    ngx_ts_hls_segment_t  *seg;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, hls->ts->log, 0,
                   "ts hls update playlist");

    n = sizeof("#EXTM3U\n"
               "#EXT-X-VERSION:3\n"
               "#EXT-X-MEDIA-SEQUENCE:\n"
               "#EXT-X-TARGETDURATION:\n\n") - 1
        + 2 * NGX_INT_T_LEN;

    maxd = 0;

    for (i = 0; i < hls->nsegs; i++) {
        seg = &hls->segs[(hls->seg + i) % hls->nsegs];

        if (seg->duration) {
            if (maxd < seg->duration) {
                maxd = seg->duration;
            }

            n += sizeof("#EXTINF:.xxx,\n"
                        ".ts\n") - 1
                 + 2 * NGX_INT_T_LEN;
        }
    }

    if (hls->done) {
        n += sizeof("\n#EXT-X-ENDLIST\n") - 1;
    }

    data = ngx_alloc(n, hls->ts->log);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    ms = hls->seg <= hls->nsegs ? 0 : hls->seg - hls->nsegs;
    td = (maxd + 90000 - 1) / 90000;

    /* TODO output max_seg as TARGETDURATION to make it constant */
    p = ngx_sprintf(p, "#EXTM3U\n"
                       "#EXT-X-VERSION:3\n"
                       "#EXT-X-MEDIA-SEQUENCE:%ui\n"
                       "#EXT-X-TARGETDURATION:%ui\n\n", ms, td);

    for (i = 0; i < hls->nsegs; i++) {
        seg = &hls->segs[(hls->seg + i) % hls->nsegs];

        if (seg->duration) {
            p = ngx_sprintf(p, "#EXTINF:%.3f,\n"
                               "%ui.ts\n",
                            seg->duration / 90000., seg->id);
        }
    }

    if (hls->done) {
        p = ngx_cpymem(p, "\n#EXT-X-ENDLIST\n",
                       sizeof("\n#EXT-X-ENDLIST\n") - 1);
    }

    fd = ngx_open_file(hls->m3u8_tmp_path,
                       NGX_FILE_WRONLY,
                       NGX_FILE_TRUNCATE,
                       NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, hls->ts->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", hls->m3u8_tmp_path);
        ngx_free(data);
        return NGX_ERROR;
    }

    ret = ngx_write_fd(fd, data, p - data);

    if (ret < 0) {
        ngx_log_error(NGX_LOG_ALERT, hls->ts->log, ngx_errno,
                      ngx_write_fd_n " to \"%s\" failed", hls->m3u8_tmp_path);
        ngx_free(data);
        return NGX_ERROR;
    }

    if (ret != p - data) {
        ngx_log_error(NGX_LOG_ALERT, hls->ts->log, 0,
                      "incomplete write to \"%s\"", hls->m3u8_tmp_path);
        ngx_free(data);
        return NGX_ERROR;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, hls->ts->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", hls->m3u8_tmp_path);
        ngx_free(data);
        return NGX_ERROR;
    }

    if (ngx_rename_file(hls->m3u8_tmp_path, hls->m3u8_path) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, hls->ts->log, ngx_errno,
                ngx_rename_file_n " \"%s\" to \"%s\" failed",
                hls->m3u8_tmp_path, hls->m3u8_path);
        ngx_free(data);
        return NGX_ERROR;
    }

    ngx_free(data);

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_open_segment(ngx_ts_hls_t *hls)
{
    size_t            n;
    ngx_err_t         err;
    ngx_str_t        *path;
    ngx_uint_t        try;
    ngx_chain_t      *out, **ll;
    ngx_ts_stream_t  *ts;

    if (hls->file.fd != NGX_INVALID_FILE) {
        return NGX_OK;
    }

    ts = hls->ts;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls open segment %ui", hls->seg);

    path = &hls->path;

    for (try = 0; /* void */; try++) {
        n = ngx_sprintf(path->data + path->len, "/%ui.ts%Z", hls->seg)
            - path->data - 1;

        hls->file.name.data = path->data;
        hls->file.name.len = n;

        hls->file.fd = ngx_open_file(path->data,
                                     NGX_FILE_WRONLY,
                                     NGX_FILE_TRUNCATE,
                                     NGX_FILE_DEFAULT_ACCESS);

        if (hls->file.fd != NGX_INVALID_FILE) {
            break;
        }

        err = ngx_errno;

        if (try || (err != NGX_ENOENT && err != NGX_ENOTDIR)) {
            ngx_log_error(NGX_LOG_EMERG, ts->log, err,
                          ngx_open_file_n " \"%s\" failed", path->data);
            return NGX_ERROR;
        }

        path->data[path->len] = 0;

        /* XXX dir access mode */
        if (ngx_create_dir(path->data, 0700) == NGX_FILE_ERROR) {
            err = ngx_errno;

            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_CRIT, ts->log, err,
                              ngx_create_dir_n " \"%s\" failed", path->data);
                return NGX_ERROR;
            }
        }
    }

    if (hls->prologue == NULL) {
        out = ngx_ts_write_pat(ts);
        if (out == NULL) {
            return NGX_ERROR;
        }

        for (ll = &out; *ll; ll = &(*ll)->next);

        *ll = ngx_ts_write_pmt(ts, ts->progs);
        if (*ll == NULL) {
            return NGX_ERROR;
        }

        hls->prologue = out;
    }

    if (ngx_write_chain_to_file(&hls->file, hls->prologue, 0, ts->pool)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_msec_t
ngx_ts_hls_file_manager(void *data)
{
    ngx_ts_hls_conf_t *hls = data;

    ngx_tree_ctx_t  tree;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                  "ts hls file manager");

    tree.init_handler = NULL;
    tree.file_handler = ngx_ts_hls_manage_file;
    tree.pre_tree_handler = ngx_ts_hls_manage_directory;
    tree.post_tree_handler = ngx_ts_hls_delete_directory;
    tree.spec_handler = ngx_ts_hls_delete_file;
    tree.data = hls;
    tree.alloc = 0;
    tree.log = ngx_cycle->log;

    (void) ngx_walk_tree(&tree, &hls->path->name);

    return hls->max_seg * hls->nsegs;
}


static ngx_int_t
ngx_ts_hls_manage_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_ts_hls_conf_t *hls = ctx->data;

    time_t  age, max_age;

    age = ngx_time() - ctx->mtime;

    max_age = 0;

    if (path->len >= 5
        && ngx_memcmp(path->data + path->len - 5, ".m3u8", 5) == 0)
    {
        max_age = hls->max_seg * hls->nsegs / 1000;
    }

    if (path->len >= 3
        && ngx_memcmp(path->data + path->len - 3, ".ts", 3) == 0)
    {
        max_age = hls->max_seg * hls->nsegs / 500;
    }

    if (path->len >= 4
        && ngx_memcmp(path->data + path->len - 4, ".tmp", 3) == 0)
    {
        max_age = 10;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "ts hls file \"%s\", age:%T, max_age:%T",
                   path->data, age, max_age);

    if (age < max_age) {
        return NGX_OK;
    }

    return ngx_ts_hls_delete_file(ctx, path);
}


static ngx_int_t
ngx_ts_hls_manage_directory(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_delete_directory(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "ts hls delete dir: \"%s\"", path->data);

    /* non-empty directory will not be removed */

    /* TODO count files instead */

    (void) ngx_delete_dir(path->data);

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "ts hls file delete: \"%s\"", path->data);

    if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", path->data);
    }

    return NGX_OK;
}
