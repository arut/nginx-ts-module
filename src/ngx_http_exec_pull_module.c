
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_shm_zone_t            *shm_zone;
    ngx_path_t                *log_path;
    ngx_uint_t                 log_mode;
} ngx_http_exec_pull_loc_conf_t;


typedef struct {
    ngx_rbtree_t               rbtree;
    ngx_rbtree_node_t          sentinel;
} ngx_http_exec_pull_sh_t;


typedef struct {
    ngx_http_exec_pull_sh_t   *sh;
    ngx_slab_pool_t           *shpool;
    ngx_http_complex_value_t   exec;
    ngx_msec_t                 timeout;
    ngx_queue_t                queue;
} ngx_http_exec_pull_t;


typedef struct {
    ngx_rbtree_node_t          node;

    /* node.data is used as update flag */

    ngx_pid_t                  pid;
    ngx_msec_t                 expire;

    ngx_http_exec_pull_t      *pull;       /* worker field */
    ngx_connection_t          *connection; /* worker field */
    ngx_queue_t                queue;      /* worker field */

    size_t                     len;
    u_char                     data[1];
} ngx_http_exec_pull_node_t;


static ngx_int_t ngx_http_exec_pull_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_exec_pull_run(ngx_http_request_t *r, char *exec,
    ngx_http_exec_pull_node_t *epn);
static char **ngx_http_exec_pull_parse_cmdline(ngx_http_request_t *r, char *p);
static void ngx_http_exec_pull_child(char *path, char **argv,
    ngx_str_t *log_path, ngx_uint_t log_mode, ngx_fd_t wd);
static void ngx_http_exec_pull_delete(ngx_http_exec_pull_node_t *epn);
static void ngx_http_exec_pull_event_handler(ngx_event_t *rev);
static void *ngx_http_exec_pull_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_exec_pull_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_exec_pull_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_exec_pull_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static void ngx_http_exec_pull_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static void ngx_http_exec_pull_cleanup(void *data);
static char *ngx_http_exec_pull(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_exec_pull_log_path(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_exec_pull_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_exec_pull_commands[] = {

    { ngx_string("exec_pull_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_exec_pull_zone,
      0,
      0,
      NULL },

    { ngx_string("exec_pull"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_exec_pull,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("exec_pull_log_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_exec_pull_log_path,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_exec_pull_module_ctx = {
    NULL,                                /* preconfiguration */
    ngx_http_exec_pull_init,             /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    ngx_http_exec_pull_create_loc_conf,  /* create location configuration */
    ngx_http_exec_pull_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_exec_pull_module = {
    NGX_MODULE_V1,
    &ngx_http_exec_pull_module_ctx,      /* module context */
    ngx_http_exec_pull_commands,         /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_exec_pull_handler(ngx_http_request_t *r)
{
    ngx_str_t                       exec;
    ngx_int_t                       rc;
    ngx_uint_t                      hash;
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_http_exec_pull_t           *pull;
    ngx_http_exec_pull_node_t      *epn;
    ngx_http_exec_pull_loc_conf_t  *elcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_exec_pull_module);
    if (elcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    pull = elcf->shm_zone->data;

    if (ngx_http_complex_value(r, &pull->exec, &exec) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (exec.len == 0) {
        return NGX_DECLINED;
    }

    hash = ngx_crc32_short(exec.data, exec.len);

    ngx_shmtx_lock(&pull->shpool->mutex);

    node = pull->sh->rbtree.root;
    sentinel = pull->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        epn = (ngx_http_exec_pull_node_t *) node;

        rc = ngx_memn2cmp(exec.data, epn->data, exec.len, epn->len);

        if (rc == 0) {
            epn->expire = ngx_current_msec;
            epn->node.data = 1;

            ngx_shmtx_unlock(&pull->shpool->mutex);
            return NGX_DECLINED;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    epn = ngx_slab_calloc_locked(pull->shpool,
                                 sizeof(ngx_http_exec_pull_node_t) + exec.len);
    if (epn == NULL) {
        ngx_shmtx_unlock(&pull->shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    epn->node.key = hash;
    epn->pull = pull;
    epn->len = exec.len;
    epn->expire = ngx_current_msec + pull->timeout;

    ngx_memcpy(epn->data, exec.data, exec.len + 1);

    ngx_rbtree_insert(&pull->sh->rbtree, &epn->node);

    ngx_queue_insert_head(&pull->queue, &epn->queue);

    ngx_shmtx_unlock(&pull->shpool->mutex);

    if (ngx_http_exec_pull_run(r, (char *) exec.data, epn) != NGX_OK) {
        ngx_http_exec_pull_delete(epn);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_exec_pull_run(ngx_http_request_t *r, char *exec,
    ngx_http_exec_pull_node_t *epn)
{
    char                           *path, **argv;
    ngx_fd_t                        pfd[2], rd, wd;
    ngx_pid_t                       pid;
    ngx_event_t                    *rev;
    ngx_connection_t               *ec;
    ngx_http_exec_pull_loc_conf_t  *elcf;

    /*
     * - it is safe here to use all node fields with
     *   no lock held, except for the expire field
     * - this function modifies exec string
     */

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "exec_pull run \"%s\"", epn->data);

    argv = ngx_http_exec_pull_parse_cmdline(r, exec);
    if (argv == NULL) {
        return NGX_ERROR;
    }

    if (*argv == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "bad exec \"%s\"", epn->data);
        return NGX_ERROR;
    }

    path = *argv++;

    if (pipe(pfd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      "pipe() failed");
        return NGX_ERROR;
    }

    rd = pfd[0];
    wd = pfd[1];

    pid = fork();

    if (pid == -1) {
        goto failed;
    }

    if (pid == 0) {
        elcf = ngx_http_get_module_loc_conf(r, ngx_http_exec_pull_module);

        ngx_http_exec_pull_child(path, argv,
                                 elcf->log_path ? &elcf->log_path->name : NULL,
                                 elcf->log_mode, wd);
    }

    epn->pid = pid;

    if (ngx_close_file(wd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_file_n " pipe write failed");

        wd = NGX_INVALID_FILE;
        goto failed;
    }

    wd = NGX_INVALID_FILE;

    ec = ngx_get_connection(rd, ngx_cycle->log);
    if (ec == NULL) {
        goto failed;
    }

    ec->data = epn;

    ec->read->log = ngx_cycle->log;
    ec->write->log = ngx_cycle->log;

    epn->connection = ec;

    rev = ec->read;
    rev->handler = ngx_http_exec_pull_event_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_add_timer(rev, epn->pull->timeout);

    return NGX_OK;

failed:

    if (rd != NGX_INVALID_FILE) {
        if (ngx_close_file(rd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_file_n " pipe read failed");
        }
    }

    if (wd != NGX_INVALID_FILE) {
        if (ngx_close_file(wd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_file_n " pipe write failed");
        }
    }

    return NGX_ERROR;
}


static char **
ngx_http_exec_pull_parse_cmdline(ngx_http_request_t *r, char *p)
{
    char         **pp, *s;
    ngx_array_t    values;

    if (ngx_array_init(&values, r->pool, 16, sizeof(char *)) != NGX_OK) {
        return NULL;
    }

    for ( ;; ) {
        for ( /* void */ ; *p == ' '; p++);

        if (*p == '\0') {
            break;
        }

        pp = ngx_array_push(&values);
        if (pp == NULL) {
            return NULL;
        }

        *pp = p;

        for ( /* void */ ; *p; p++) {
            if (*p == ' ' && p[-1] != '\\') {
                break;
            }
        }

        if (*p == '\0') {
            break;
        }

        *p++ = '\0';
    }

    pp = ngx_array_push(&values);
    if (pp == NULL) {
        return NULL;
    }

    *pp = NULL;

    for (pp = (char **) values.elts; *pp; pp++) {
        for (p = *pp; *p; p++) {
            if (*p == '\\') {
                for (s = p; *s; s++) {
                    *s = s[1];
                }
            }
        }
    }

    return (char **) values.elts;
}


static void
ngx_http_exec_pull_child(char *path, char **argv, ngx_str_t *log_path,
    ngx_uint_t log_mode, ngx_fd_t wd)
{
    char           **pp;
    u_char          *p;
    ngx_fd_t         null, out, err, fd, nfiles;
    ngx_pid_t        pid;
    struct rlimit    rlmt;

    null = ngx_open_file("/dev/null", NGX_FILE_RDWR, NGX_FILE_OPEN, 0);
    if (null == NGX_INVALID_FILE) {
        perror("open(\"/dev/null\") failed");
        exit(1);
    }

    out = null;
    err = null;

    if (log_path) {
        pid = ngx_getpid();
        
        if (log_mode & STDOUT_FILENO) {
            p = malloc(log_path->len + 1 + NGX_INT64_LEN + sizeof(".out"));

            if (p) {
                ngx_sprintf(p, "%V/%P.out%Z", log_path, pid);

                fd = ngx_open_file(p, NGX_FILE_WRONLY,
                                   NGX_FILE_CREATE_OR_OPEN|NGX_FILE_TRUNCATE,
                                   NGX_FILE_DEFAULT_ACCESS);

                if (fd == NGX_INVALID_FILE) {
                    perror(ngx_open_file_n " failed");
                } else {
                    out = fd;
                }
            }
        }

        if (log_mode & STDERR_FILENO) {
            p = malloc(log_path->len + 1 + NGX_INT64_LEN + sizeof(".err"));

            if (p) {
                ngx_sprintf(p, "%V/%P.err%Z", log_path, pid);

                fd = ngx_open_file(p, NGX_FILE_WRONLY,
                                   NGX_FILE_CREATE_OR_OPEN|NGX_FILE_TRUNCATE,
                                   NGX_FILE_DEFAULT_ACCESS);

                if (fd == NGX_INVALID_FILE) {
                    perror(ngx_open_file_n " failed");
                } else {
                    err = fd;
                }
            }
        }
    }

    if (dup2(null, STDIN_FILENO) == -1) {
        perror("dup2() stdin failed");
    }

    if (dup2(out, STDOUT_FILENO) == -1) {
        perror("dup2() stdout failed");
    }

    if (dup2(err, STDERR_FILENO) == -1) {
        perror("dup2() stderr failed");
    }

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        perror("getrlimit(RLIMIT_NOFILE) failed");
        exit(1);
    }

    nfiles = (ngx_fd_t) rlmt.rlim_cur;

    for (fd = STDERR_FILENO + 1; fd < nfiles; fd++) {
        if (fd != wd) {
            (void) ngx_close_file(fd);
        }
    }

    if (err != null) {
        (void) fprintf(stderr, "%s", path);

        for (pp = argv; *pp; pp++) {
            (void) fprintf(stderr, " %s", *pp);
        }

        (void) fprintf(stderr, "\n");
    }

    if (execv(path, argv) == -1) {
        perror("execv() failed");
        exit(1);
    }

    /* not reached */
}


static void
ngx_http_exec_pull_delete(ngx_http_exec_pull_node_t *epn)
{
    ngx_http_exec_pull_t  *pull;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "exec_pull delete pid:%P, \"%s\"", epn->pid, epn->data);

    pull = epn->pull;

    if (epn->pid) {
        if (kill(epn->pid, SIGTERM) != -1) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "kill(%P, SIGTERM) failed", epn->pid);
        }
    }

    if (epn->connection) {
        ngx_close_connection(epn->connection);
    }

    ngx_shmtx_lock(&pull->shpool->mutex);

    ngx_queue_remove(&epn->queue);
    ngx_rbtree_delete(&pull->sh->rbtree, &epn->node);
    ngx_slab_free_locked(pull->shpool, epn);

    ngx_shmtx_unlock(&pull->shpool->mutex);
}


static void
ngx_http_exec_pull_event_handler(ngx_event_t *rev)
{
    ngx_msec_t                  timeout;
    ngx_connection_t           *ec;
    ngx_http_exec_pull_node_t  *epn;

    ec = rev->data;
    epn = ec->data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "exec_pull event handler pid:%P, \"%s\"",
                   epn->pid, epn->data);

    if (rev->timedout && epn->node.data) {
        /* node was accessed, reschedule timer */

        timeout = epn->expire - ngx_current_msec;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                       "exec_pull reschedule %M", timeout);

        epn->node.data = 0;
        rev->timedout = 0;

        ngx_add_timer(rev, timeout);

        return;
    }

    ngx_http_exec_pull_delete(epn);
}


static void *
ngx_http_exec_pull_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_exec_pull_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_exec_pull_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->log_mode = 0;
     */

    conf->shm_zone = NGX_CONF_UNSET_PTR;
    conf->log_path = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_exec_pull_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_exec_pull_loc_conf_t *prev = parent;
    ngx_http_exec_pull_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);
    ngx_conf_merge_ptr_value(conf->log_path, prev->log_path, NULL);

    if (conf->log_mode == 0) {
        conf->log_mode = prev->log_mode;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_exec_pull_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                            *p;
    ssize_t                            size;
    ngx_str_t                         *value, name, s;
    ngx_int_t                          v;
    ngx_uint_t                         i;
    ngx_msec_t                         timeout;
    ngx_shm_zone_t                    *shm_zone;
    ngx_pool_cleanup_t                *cln;
    ngx_http_exec_pull_t              *pull;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    pull = ngx_pcalloc(cf->pool, sizeof(ngx_http_exec_pull_t));
    if (pull == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &pull->exec;
    ccv.zero = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    name.len = 0;
    timeout = 1000;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {

            s.data = value[i].data + 8;
            s.len = value[i].len - 8;

            v = ngx_parse_time(&s, 0);
            if (v == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid timeout value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            timeout = (ngx_msec_t) v;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter", &cmd->name);
        return NGX_CONF_ERROR;
    }

    ngx_queue_init(&pull->queue);

    pull->timeout = timeout;

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_exec_pull_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_exec_pull_init_zone;
    shm_zone->data = pull;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_exec_pull_cleanup;
    cln->data = pull;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_exec_pull_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_exec_pull_t  *opull = data;

    size_t                 len;
    ngx_http_exec_pull_t  *pull;

    pull = shm_zone->data;

    if (opull) {
        if (pull->exec.value.len != opull->exec.value.len
            || ngx_strncmp(pull->exec.value.data, opull->exec.value.data,
                           pull->exec.value.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "exec_pull \"%V\" uses the \"%V\" exec key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &pull->exec.value,
                          &opull->exec.value);
            return NGX_ERROR;
        }

        pull->sh = opull->sh;
        pull->shpool = opull->shpool;

        return NGX_OK;
    }

    pull->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        pull->sh = pull->shpool->data;
        return NGX_OK;
    }

    pull->sh = ngx_slab_alloc(pull->shpool, sizeof(ngx_http_exec_pull_sh_t));
    if (pull->sh == NULL) {
        return NGX_ERROR;
    }

    pull->shpool->data = pull->sh;

    ngx_rbtree_init(&pull->sh->rbtree, &pull->sh->sentinel,
                    ngx_http_exec_pull_rbtree_insert_value);

    len = sizeof(" in exec_pull zone \"\"") + shm_zone->shm.name.len;

    pull->shpool->log_ctx = ngx_slab_alloc(pull->shpool, len);
    if (pull->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(pull->shpool->log_ctx, " in exec_pull zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static void
ngx_http_exec_pull_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t          **p;
    ngx_http_exec_pull_node_t   *epn, *epnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            epn = (ngx_http_exec_pull_node_t *) node;
            epnt = (ngx_http_exec_pull_node_t *) temp;

            p = (ngx_memn2cmp(epn->data, epnt->data, epn->len, epnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static void
ngx_http_exec_pull_cleanup(void *data)
{
    ngx_http_exec_pull_t *pull = data;

    ngx_queue_t                *q;
    ngx_http_exec_pull_node_t  *epn;

    /* kill processes started by this worker */

    while (!ngx_queue_empty(&pull->queue)) {
        q = ngx_queue_head(&pull->queue);
        epn = ngx_queue_data(q, ngx_http_exec_pull_node_t, queue);
        ngx_http_exec_pull_delete(epn);
    }
}


static char *
ngx_http_exec_pull(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_exec_pull_loc_conf_t  *elcf = conf;

    ngx_str_t       *value, s;
    ngx_uint_t       i;
    ngx_shm_zone_t  *shm_zone;

    if (elcf->shm_zone != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        elcf->shm_zone = NULL;
        return NGX_OK;
    }

    shm_zone = NULL;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            shm_zone = ngx_shared_memory_add(cf, &s, 0,
                                             &ngx_http_exec_pull_module);
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter", &cmd->name);
        return NGX_CONF_ERROR;
    }

    elcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


static char *
ngx_http_exec_pull_log_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_exec_pull_loc_conf_t  *elcf = conf;

    ngx_str_t   *value;
    ngx_path_t  *path;
    ngx_uint_t   i, mode;

    if (elcf->log_path != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        elcf->log_path = NULL;
        return NGX_OK;
    }

    path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (path == NULL) {
        return NGX_CONF_ERROR;
    }

    path->name = value[1];

    if (path->name.data[path->name.len - 1] == '/') {
        path->name.len--;
    }

    if (ngx_conf_full_name(cf->cycle, &path->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    path->conf_file = cf->conf_file->file.name.data;
    path->line = cf->conf_file->line;

    if (ngx_add_path(cf, &path) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    mode = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "stdout") == 0) {
            mode |= STDOUT_FILENO;
            continue;
        }

        if (ngx_strcmp(value[i].data, "stderr") == 0) {
            mode |= STDERR_FILENO;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (mode == 0) {
        mode = STDOUT_FILENO|STDERR_FILENO;
    }

    elcf->log_path = path;
    elcf->log_mode = mode;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_exec_pull_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

#if nginx_version >= 1013004
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
#else
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
#endif
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_exec_pull_handler;

    return NGX_OK;
}
