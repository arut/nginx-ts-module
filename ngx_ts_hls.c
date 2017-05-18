
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_hls.h"


static void ngx_ts_hls_cleanup(void *data);
static ngx_int_t ngx_ts_hls_close_segment(ngx_ts_hls_t *hls,
    ngx_ts_hls_variant_t *var);
static ngx_int_t ngx_ts_hls_update_playlist(ngx_ts_hls_t *hls,
    ngx_ts_hls_variant_t *var);
static ngx_int_t ngx_ts_hls_update_master_playlist(ngx_ts_hls_t *hls);
static ngx_int_t ngx_ts_hls_write_file(u_char *path, u_char *tmp_path,
    u_char *data, size_t len, ngx_log_t *log);
static ngx_int_t ngx_ts_hls_open_segment(ngx_ts_hls_t *hls,
    ngx_ts_hls_variant_t *var);

static ngx_int_t ngx_ts_hls_manage_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_ts_hls_manage_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_ts_hls_delete_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_ts_hls_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);


ngx_ts_hls_t *
ngx_ts_hls_create(ngx_ts_hls_conf_t *conf, ngx_ts_stream_t *ts, ngx_str_t *name)
{
    size_t                 len, dirlen;
    u_char                *p;
    ngx_uint_t             n;
    ngx_ts_hls_t          *hls;
    ngx_pool_cleanup_t    *cln;
    ngx_ts_program_t      *prog;
    ngx_ts_hls_variant_t  *var;

    hls = ngx_pcalloc(ts->pool, sizeof(ngx_ts_hls_t));
    if (hls == NULL) {
        return NULL;
    }

    hls->conf = conf;
    hls->ts = ts;

    dirlen = conf->path->name.len + 1 + name->len;

    hls->path = ngx_pnalloc(ts->pool, dirlen + 1);
    if (hls->path == NULL) {
        return NULL;
    }

    hls->nvars = ts->nprogs;
    hls->vars = ngx_pcalloc(ts->pool,
                            sizeof(ngx_ts_hls_variant_t) * ts->nprogs);
    if (hls->vars == NULL) {
        return NULL;
    }

    ngx_sprintf(hls->path, "%V/%V%Z", &conf->path->name, name);

    if (hls->nvars > 1) {
        /* index.m3u8 */

        len = dirlen + sizeof("/index.m3u8");

        hls->m3u8_path = ngx_pnalloc(ts->pool, len);
        if (hls->m3u8_path == NULL) {
            return NULL;
        }

        ngx_sprintf(hls->m3u8_path, "%s/index.m3u8%Z", hls->path);

        /* index.m3u8.tmp */

        len += sizeof(".tmp") - 1;

        hls->m3u8_tmp_path = ngx_pnalloc(ts->pool, len);
        if (hls->m3u8_tmp_path == NULL) {
            return NULL;
        }

        ngx_sprintf(hls->m3u8_tmp_path, "%s.tmp%Z", hls->m3u8_path);
    }

    for (n = 0; n < ts->nprogs; n++) {
        prog = &ts->progs[n];
        var = &hls->vars[n];

        var->prog = prog;
        var->file.fd = NGX_INVALID_FILE;
        var->file.log = ts->log;

        var->nsegs = conf->nsegs;
        var->segs = ngx_pcalloc(ts->pool,
                                sizeof(ngx_ts_hls_segment_t) * conf->nsegs);
        if (var->segs == NULL) {
            return NULL;
        }

        /* [<prog>.]<seg>.ts */

        len = dirlen + 1 + NGX_INT_T_LEN + sizeof(".ts");

        if (hls->nvars > 1) {
            len += NGX_INT_T_LEN + 1;
        }

        p = ngx_pnalloc(ts->pool, len);
        if (p == NULL) {
            return NULL;
        }

        var->path.data = p;

        if (hls->nvars > 1) {
            p = ngx_sprintf(p, "%s/%ui.", hls->path, (ngx_uint_t) prog->number);

        } else {
            p = ngx_sprintf(p, "%s/", hls->path);
        }

        var->path.len = p - var->path.data;

        /* (<prog>|index).m3u8 */

        len = dirlen + 1 + sizeof(".m3u8");

        if (hls->nvars > 1) {
            len += NGX_INT_T_LEN;

        } else {
            len += sizeof("index") - 1;
        }

        var->m3u8_path = ngx_pnalloc(ts->pool, len);
        if (var->m3u8_path == NULL) {
            return NULL;
        }

        if (hls->nvars > 1) {
            ngx_sprintf(var->m3u8_path, "%s/%ui.m3u8%Z",
                        hls->path, (ngx_uint_t) prog->number);

        } else {
            ngx_sprintf(var->m3u8_path, "%s/index.m3u8%Z", hls->path);
        }

        /* (<prog>|index).m3u8.tmp */

        len += sizeof(".tmp") - 1;

        var->m3u8_tmp_path = ngx_pnalloc(ts->pool, len);
        if (var->m3u8_tmp_path == NULL) {
            return NULL;
        }

        ngx_sprintf(var->m3u8_tmp_path, "%s.tmp%Z", var->m3u8_path);
    }

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
    ngx_uint_t             n, i;
    ngx_ts_es_t           *es;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_segment_t  *seg;
    ngx_ts_hls_variant_t  *var;

    hls->done = 1;

    ts = hls->ts;

    for (n = 0; n < hls->nvars; n++) {
        var = &hls->vars[n];

        if (var->file.fd != NGX_INVALID_FILE) {
            if (ngx_close_file(var->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, ts->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              var->file.name.data);
            }

            var->file.fd = NGX_INVALID_FILE;
        }

        maxd = 0;

        for (i = 0; i < var->prog->nes; i++) {
            es = &var->prog->es[i];

            if (es->ptsf) {
                d = es->pts - var->seg_pts;
                if (maxd < d) {
                    maxd = d;
                }
            }
        }

        seg = &var->segs[var->seg % var->nsegs];
        seg->id = var->seg++;
        seg->duration = maxd;

        (void) ngx_ts_hls_update_playlist(hls, var);
    }
}


ngx_int_t
ngx_ts_hls_write_frame(ngx_ts_hls_t *hls, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs)
{
    ngx_uint_t             n;
    ngx_chain_t           *out;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_variant_t  *var;

    ts = hls->ts;

    for (n = 0; n < hls->nvars; n++) {
        var = &hls->vars[n];
        if (prog == var->prog) {
            goto found;
        }
    }

    ngx_log_error(NGX_LOG_ERR, ts->log, 0, "TS program not found");

    return NGX_ERROR;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts hls frame v:%ud",
                   (unsigned) var->prog->number);

    if (ngx_ts_hls_close_segment(hls, var) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_ts_hls_open_segment(hls, var) != NGX_OK) {
        return NGX_ERROR;
    }

    out = ngx_ts_write_pes(ts, prog, es, bufs);
    if (out == NULL) {
        return NGX_ERROR;
    }

    if (ngx_write_chain_to_file(&var->file, out, var->file.offset, ts->pool)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    ngx_ts_free_chain(ts, &out);

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_close_segment(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var)
{
    int64_t                d, min_seg, max_seg;
    ngx_uint_t             n;
    ngx_ts_es_t           *es;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_segment_t  *seg;

    ts = hls->ts;

    if (var->file.fd == NGX_INVALID_FILE) {
        /* segment not started */

        for (n = 0; n < var->prog->nes; n++) {
            es = &var->prog->es[n];

            if (es->ptsf) {
                d = es->pts - var->seg_pts;

                if (d > 0) {
                    var->seg_pts = es->pts;
                }
            }
        }

        return NGX_OK;
    }

    min_seg = (int64_t) hls->conf->min_seg * 90;
    max_seg = (int64_t) hls->conf->max_seg * 90;

    for (n = 0; n < var->prog->nes; n++) {
        es = &var->prog->es[n];

        if (es->ptsf) {
            d = es->pts - var->seg_pts;

            if (d >= max_seg
                || (d >= min_seg && !var->prog->video)
                || (d >= min_seg && es->video && es->rand))
            {
                var->seg_pts = es->pts;
                goto close;
            }
        }
    }

    return NGX_OK;

close:

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls close segment v:%ud, n:%ui",
                   (unsigned) var->prog->number, var->seg);

    if (ngx_close_file(var->file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ts->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", var->file.name.data);
    }

    seg = &var->segs[var->seg % var->nsegs];
    seg->id = var->seg++;
    seg->duration = d;

    ngx_memzero(&var->file, sizeof(ngx_file_t));

    var->file.fd = NGX_INVALID_FILE;
    var->file.log = ts->log;

    if (ngx_ts_hls_update_playlist(hls, var) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_ts_hls_update_master_playlist(hls);
}


static ngx_int_t
ngx_ts_hls_update_playlist(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var)
{
    size_t                 len;
    u_char                *p, *data;
    uint64_t               maxd;
    ngx_int_t              rc;
    ngx_uint_t             i, ms, td;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_segment_t  *seg;

    ts = hls->ts;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls update playlist v:%ud",
                   (unsigned) var->prog->number);

    len = sizeof("#EXTM3U\n"
                 "#EXT-X-VERSION:3\n"
                 "#EXT-X-MEDIA-SEQUENCE:\n"
                 "#EXT-X-TARGETDURATION:\n\n") - 1
          + 2 * NGX_INT_T_LEN;

    maxd = 0;

    for (i = 0; i < var->nsegs; i++) {
        seg = &var->segs[(var->seg + i) % var->nsegs];

        if (seg->duration) {
            if (maxd < seg->duration) {
                maxd = seg->duration;
            }

            len += sizeof("#EXTINF:.xxx,\n"
                          ".ts\n") - 1
                   + 2 * NGX_INT_T_LEN;

            if (hls->nvars > 1) {
                len += NGX_INT_T_LEN + 1;
            }
        }
    }

    if (hls->done) {
        len += sizeof("\n#EXT-X-ENDLIST\n") - 1;
    }

    data = ngx_alloc(len, ts->log);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    ms = var->seg <= var->nsegs ? 0 : var->seg - var->nsegs;
    td = (hls->conf->max_seg + 999) / 1000;

    p = ngx_sprintf(p, "#EXTM3U\n"
                       "#EXT-X-VERSION:3\n"
                       "#EXT-X-MEDIA-SEQUENCE:%ui\n"
                       "#EXT-X-TARGETDURATION:%ui\n\n", ms, td);

    for (i = 0; i < var->nsegs; i++) {
        seg = &var->segs[(var->seg + i) % var->nsegs];

        if (seg->duration) {
            p = ngx_sprintf(p, "#EXTINF:%.3f,\n", seg->duration / 90000.);

            if (hls->nvars > 1) {
                p = ngx_sprintf(p, "%ui.%ui.ts\n",
                                (ngx_uint_t) var->prog->number, seg->id);

            } else {
                p = ngx_sprintf(p, "%ui.ts\n", seg->id);
            }
        }
    }

    if (hls->done) {
        p = ngx_cpymem(p, "\n#EXT-X-ENDLIST\n",
                       sizeof("\n#EXT-X-ENDLIST\n") - 1);
    }

    rc = ngx_ts_hls_write_file(var->m3u8_path, var->m3u8_tmp_path, data,
                               p - data, ts->log);

    ngx_free(data);

    return rc;
}


static ngx_int_t
ngx_ts_hls_update_master_playlist(ngx_ts_hls_t *hls)
{
    size_t                 len;
    u_char                *p, *data;
    ngx_int_t              rc;
    ngx_uint_t             n;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_variant_t  *var;

    /*XXX wait for all playlists before generating master */
    /*XXX touch file if it exists*/

    if (hls->nvars == 1) {
        return NGX_OK;
    }

    ts = hls->ts;

    len = sizeof("#EXTM3U\n") - 1;

    for (n = 0; n < hls->nvars; n++) {
        len += sizeof("#EXT-X-STREAM-INF:\n") - 1
               + NGX_INT_T_LEN + sizeof(".m3u8\n") - 1;

        /* var = &hls->vars[n]; */
        /* XXX add options */
        len += sizeof("BANDWIDTH=") - 1 + NGX_INT_T_LEN;
        /*XXX*/
    }

    data = ngx_alloc(len, ts->log);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    p = ngx_cpymem(p, "#EXTM3U\n", sizeof("#EXTM3U\n") - 1);

    for (n = 0; n < hls->nvars; n++) {
        var = &hls->vars[n];

        p = ngx_cpymem(p, "#EXT-X-STREAM-INF:",
                       sizeof("#EXT-X-STREAM-INF:") - 1);

        /* XXX add options */
        p = ngx_sprintf(p, "BANDWIDTH=%ui\n",
                        (ngx_uint_t) (var->prog->number * 1000));
        /*XXX*/

        p = ngx_sprintf(p, "%ui.m3u8\n", (ngx_uint_t) var->prog->number);
    }

    rc = ngx_ts_hls_write_file(hls->m3u8_path, hls->m3u8_tmp_path, data,
                               p - data, ts->log);

    ngx_free(data);

    return rc;
}


static ngx_int_t
ngx_ts_hls_write_file(u_char *path, u_char *tmp_path, u_char *data, size_t len,
    ngx_log_t *log)
{
    ssize_t   n;
    ngx_fd_t  fd;

    fd = ngx_open_file(tmp_path,
                       NGX_FILE_WRONLY,
                       NGX_FILE_TRUNCATE,
                       NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", tmp_path);
        ngx_free(data);
        return NGX_ERROR;
    }

    n = ngx_write_fd(fd, data, len);

    if (n < 0) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_write_fd_n " to \"%s\" failed", tmp_path);
        return NGX_ERROR;
    }

    if ((size_t) n != len) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "incomplete write to \"%s\"", tmp_path);
        return NGX_ERROR;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", tmp_path);
        return NGX_ERROR;
    }

    if (ngx_rename_file(tmp_path, path) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_rename_file_n " \"%s\" to \"%s\" failed",
                      tmp_path, path);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_open_segment(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var)
{
    size_t            n;
    ngx_err_t         err;
    ngx_str_t        *path;
    ngx_uint_t        try;
    ngx_chain_t      *out, **ll;
    ngx_ts_stream_t  *ts;

    if (var->file.fd != NGX_INVALID_FILE) {
        return NGX_OK;
    }

    ts = hls->ts;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls open segment v:%ud, n:%ui",
                   (unsigned) var->prog->number, var->seg);

    path = &var->path;

    n = ngx_sprintf(path->data + path->len, "%ui.ts%Z", var->seg) - path->data
        - 1;

    var->file.name.data = path->data;
    var->file.name.len = n;

    for (try = 0; /* void */; try++) {
        var->file.fd = ngx_open_file(path->data,
                                     NGX_FILE_WRONLY,
                                     NGX_FILE_TRUNCATE,
                                     NGX_FILE_DEFAULT_ACCESS);

        if (var->file.fd != NGX_INVALID_FILE) {
            break;
        }

        err = ngx_errno;

        if (try || (err != NGX_ENOENT && err != NGX_ENOTDIR)) {
            ngx_log_error(NGX_LOG_EMERG, ts->log, err,
                          ngx_open_file_n " \"%s\" failed", path->data);
            return NGX_ERROR;
        }

        /* XXX dir access mode */
        if (ngx_create_dir(hls->path, 0700) == NGX_FILE_ERROR) {
            err = ngx_errno;

            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_CRIT, ts->log, err,
                              ngx_create_dir_n " \"%s\" failed", hls->path);
                return NGX_ERROR;
            }
        }
    }

    if (var->prologue == NULL) {
        out = ngx_ts_write_pat(ts);
        if (out == NULL) {
            return NGX_ERROR;
        }

        for (ll = &out; *ll; ll = &(*ll)->next);

        *ll = ngx_ts_write_pmt(ts, var->prog);
        if (*ll == NULL) {
            return NGX_ERROR;
        }

        var->prologue = out;
    }

    if (ngx_write_chain_to_file(&var->file, var->prologue, 0, ts->pool)
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

    /* non-empty directory will not be removed anyway */

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
