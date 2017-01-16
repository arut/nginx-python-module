
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_python.h"
#include "ngx_stream_python_session.h"


typedef struct {
    PyObject                   *ns;
    size_t                      stack_size;
} ngx_stream_python_main_conf_t;


typedef struct {
    ngx_array_t                *access;   /* array of PyCodeObject * */
    ngx_array_t                *preread;  /* array of PyCodeObject * */
    ngx_array_t                *log;      /* array of PyCodeObject * */
    PyCodeObject               *content;
} ngx_stream_python_srv_conf_t;


typedef struct {
    ngx_uint_t                  phase;
    ngx_uint_t                  passed;
    PyObject                   *session;
    ngx_python_ctx_t           *python;
} ngx_stream_python_ctx_t;


static ngx_int_t ngx_stream_python_access_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_python_preread_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_python_log_handler(ngx_stream_session_t *s);
static void ngx_stream_python_content_handler(ngx_stream_session_t *s);
static void ngx_stream_python_content_event_handler(ngx_event_t *event);
static ngx_int_t ngx_stream_python_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static PyObject *ngx_stream_python_eval_code(ngx_stream_session_t *s,
    PyCodeObject *code, ngx_event_t *wake);

static char *ngx_stream_python_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_python_access(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_python_preread(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_python_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_python_content(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_stream_python_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_python_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_stream_python_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_python_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_stream_python_init(ngx_conf_t *cf);
static ngx_int_t ngx_stream_python_init_namespace(ngx_conf_t *cf);


static ngx_command_t  ngx_stream_python_commands[] = {

    { ngx_string("python"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_python_set_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_python_main_conf_t, ns),
      NULL },

    { ngx_string("python_include"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_python_include_set_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_python_main_conf_t, ns),
      NULL },

    { ngx_string("python_stack_size"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_python_main_conf_t, stack_size),
      NULL },

    { ngx_string("python_set"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_stream_python_set,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_access"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_python_access,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_preread"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_python_preread,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_log"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_python_log,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_content"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_python_content,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_python_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_python_init,                /* postconfiguration */

    ngx_stream_python_create_main_conf,    /* create main configuration */
    ngx_stream_python_init_main_conf,      /* init main configuration */

    ngx_stream_python_create_srv_conf,     /* create server configuration */
    ngx_stream_python_merge_srv_conf       /* merge server configuration */
};


ngx_module_t  ngx_stream_python_module = {
    NGX_MODULE_V1,
    &ngx_stream_python_module_ctx,         /* module context */
    ngx_stream_python_commands,            /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_stream_python_access_handler(ngx_stream_session_t *s)
{
    PyObject                       *ret;
    ngx_int_t                       rc;
    PyCodeObject                  **pcode;
    ngx_stream_python_ctx_t        *ctx;
    ngx_stream_python_srv_conf_t   *pscf;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_python_module);

    if (pscf->access == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python access handler");

    pcode = pscf->access->elts;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_python_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_stream_python_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_stream_set_ctx(s, ctx, ngx_stream_python_module);
    }

    while (ctx->phase < pscf->access->nelts) {
        ret = ngx_stream_python_eval_code(s, pcode[ctx->phase],
                                          s->connection->read);

        if (ret == NGX_PYTHON_AGAIN) {
            s->connection->read->handler = ngx_stream_session_handler;
            return NGX_AGAIN;
        }

        if (ret == NULL) {
            return NGX_ERROR;
        }

        rc = PyInt_Check(ret) ? PyInt_AsLong(ret) : NGX_DECLINED;

        Py_DECREF(ret);

        if (rc != NGX_OK && rc != NGX_DECLINED) {
            return rc;
        }

        if (rc == NGX_OK) {
            ctx->passed++;
        }

        ctx->phase++;
    }

    ctx->phase = 0;

    return ctx->passed ? NGX_OK : NGX_DECLINED;
}


static ngx_int_t
ngx_stream_python_preread_handler(ngx_stream_session_t *s)
{
    PyObject                       *ret;
    ngx_int_t                       rc;
    PyCodeObject                  **pcode;
    ngx_stream_python_ctx_t        *ctx;
    ngx_stream_python_srv_conf_t   *pscf;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_python_module);

    if (pscf->preread == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python preread handler");

    pcode = pscf->preread->elts;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_python_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_stream_python_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_stream_set_ctx(s, ctx, ngx_stream_python_module);
    }

    while (ctx->phase < pscf->preread->nelts) {
        ret = ngx_stream_python_eval_code(s, pcode[ctx->phase],
                                          s->connection->read);

        if (ret == NGX_PYTHON_AGAIN) {
            s->connection->read->handler = ngx_stream_session_handler;
            return NGX_DONE;
        }

        if (ret == NULL) {
            return NGX_ERROR;
        }

        rc = PyInt_Check(ret) ? PyInt_AsLong(ret) : NGX_DECLINED;

        Py_DECREF(ret);

        if (rc == NGX_OK) {
            break;
        }

        if (rc != NGX_DECLINED) {
            return rc;
        }

        ctx->phase++;
    }

    ctx->phase = 0;

    return NGX_DECLINED;
}


static ngx_int_t
ngx_stream_python_log_handler(ngx_stream_session_t *s)
{
    ngx_uint_t                      n;
    PyObject                       *ret;
    PyCodeObject                  **pcode;
    ngx_stream_python_srv_conf_t   *pscf;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_python_module);

    if (pscf->log == NULL) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python log handler");

    pcode = pscf->log->elts;

    for (n = 0; n < pscf->log->nelts; n++) {
        ret = ngx_stream_python_eval_code(s, pcode[n], NULL);
        Py_XDECREF(ret);
    }

    return NGX_OK;
}


static void
ngx_stream_python_content_handler(ngx_stream_session_t *s)
{
    ngx_stream_python_content_event_handler(s->connection->read);
}


static void
ngx_stream_python_content_event_handler(ngx_event_t *event)
{
    PyObject                      *ret;
    ngx_int_t                      rc;
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_python_srv_conf_t  *pscf;

    c = event->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream python content event handler");

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_python_module);

    ret = ngx_stream_python_eval_code(s, pscf->content, c->read);

    if (ret == NGX_PYTHON_AGAIN) {
        c->read->handler = ngx_stream_python_content_event_handler;
        c->write->handler = ngx_stream_python_content_event_handler;
        return;
    }

    if (ret == NULL) {
        ngx_stream_finalize_session(s, NGX_ERROR);
        return;
    }

    rc = PyInt_Check(ret) ? PyInt_AsLong(ret) : NGX_OK;

    Py_DECREF(ret);

    ngx_stream_finalize_session(s, rc);
}


static ngx_int_t
ngx_stream_python_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    PyCodeObject  *code = (PyCodeObject *) data;

    u_char      *p;
    PyObject    *ret, *str;
    Py_ssize_t   size;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python variable handler");

    ret = ngx_stream_python_eval_code(s, code, 0);
    if (ret == NULL) {
        return NGX_ERROR;
    }

    str = PyObject_Str(ret);
    Py_DECREF(ret);

    if (str == NULL) {
        PyErr_Clear();
        return NGX_ERROR;
    }

    if (PyString_AsStringAndSize(str, (char **) &p, &size) < 0) {
        PyErr_Clear();
        Py_DECREF(str);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python variable: \"%*s\"", (size_t) size, p);

    v->len = size;
    v->data = ngx_pnalloc(s->connection->pool, size);

    if (v->data == NULL) {
        Py_DECREF(str);
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, p, size);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    Py_DECREF(str);

    return NGX_OK;
}


static PyObject *
ngx_stream_python_eval_code(ngx_stream_session_t *s, PyCodeObject *code,
    ngx_event_t *wake)
{
    PyObject                       *result, *pr;
    ngx_stream_python_ctx_t        *ctx;
    ngx_python_create_ctx_t         pc;
    ngx_stream_core_srv_conf_t     *cscf;
    ngx_stream_python_main_conf_t  *pmcf;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python eval start code:%p, wake:%p", code, wake);

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_python_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_stream_python_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ngx_stream_set_ctx(s, ctx, ngx_stream_python_module);
    }

    if (ctx->session == NULL) {
        ctx->session = ngx_stream_python_session_create(s);
        if (ctx->session == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "python error: %s",
                          ngx_python_get_error(s->connection->pool));
            return NULL;
        }
    }

    pmcf = ngx_stream_get_module_main_conf(s, ngx_stream_python_module);

    if (ctx->python == NULL) {
        ngx_memzero(&pc, sizeof(ngx_python_create_ctx_t));

        pc.pool = s->connection->pool;
        pc.log = s->connection->log;
        pc.ns = pmcf->ns;
        pc.stack_size = pmcf->stack_size;

        ctx->python = ngx_python_create_ctx(&pc);
        if (ctx->python == NULL) {
            return NULL;
        }
    }

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    ngx_python_set_resolver(ctx->python, cscf->resolver,
                            cscf->resolver_timeout);

    pr = PyDict_GetItemString(pmcf->ns, "s");

    if (pr == NULL) {
        if (PyDict_SetItemString(pmcf->ns, "s", ctx->session) < 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "python error: %s",
                          ngx_python_get_error(s->connection->pool));
        }
    }

    result = ngx_python_eval(ctx->python, code, wake);

    if (pr == NULL) {
        if (PyDict_DelItemString(pmcf->ns, "s") < 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "python error: %s",
                          ngx_python_get_error(s->connection->pool));
        }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python eval end code:%p, wake:%p, result:%p",
                   code, wake, result);

    return result;
}


static void *
ngx_stream_python_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_python_main_conf_t  *pmcf;

    pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_python_main_conf_t));
    if (pmcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     pmcf->ns = NULL;
     */

    pmcf->stack_size = NGX_CONF_UNSET_SIZE;

    return pmcf;
}


static char *
ngx_stream_python_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_stream_python_main_conf_t *pmcf = conf;

    ngx_conf_init_size_value(pmcf->stack_size, 32768);

    return NGX_CONF_OK;
}


static void *
ngx_stream_python_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_python_srv_conf_t  *pscf;

    pscf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_python_srv_conf_t));
    if (pscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     pscf->content = NULL;
     */

    pscf->access = NGX_CONF_UNSET_PTR;
    pscf->preread = NGX_CONF_UNSET_PTR;
    pscf->log = NGX_CONF_UNSET_PTR;

    return pscf;
}


static char *
ngx_stream_python_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_python_srv_conf_t *prev = parent;
    ngx_stream_python_srv_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->access, prev->access, NULL);
    ngx_conf_merge_ptr_value(conf->preread, prev->preread, NULL);
    ngx_conf_merge_ptr_value(conf->log, prev->log, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_python_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_python_access_handler;

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_python_preread_handler;

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_python_log_handler;

    return NGX_OK;
}


static char *
ngx_stream_python_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t              *value;
    PyCodeObject           *code;
    ngx_stream_variable_t  *var;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    var = ngx_stream_add_variable(cf, &value[1], NGX_STREAM_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_python_init_namespace(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    code = ngx_python_compile(cf, value[2].data);
    if (code == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_stream_python_variable;
    var->data = (uintptr_t) code;

    return NGX_CONF_OK;
}


static char *
ngx_stream_python_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_python_srv_conf_t *pscf = conf;

    ngx_str_t      *value;
    PyCodeObject  **pcode;

    value = cf->args->elts;

    if (pscf->access == NGX_CONF_UNSET_PTR) {
        pscf->access = ngx_array_create(cf->pool, 1, sizeof(PyCodeObject *));
        if (pscf->access == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pcode = ngx_array_push(pscf->access);
    if (pcode == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_python_init_namespace(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *pcode = ngx_python_compile(cf, value[1].data);
    if (*pcode == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_python_preread(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_python_srv_conf_t *pscf = conf;

    ngx_str_t      *value;
    PyCodeObject  **pcode;

    value = cf->args->elts;

    if (pscf->preread == NGX_CONF_UNSET_PTR) {
        pscf->preread = ngx_array_create(cf->pool, 1, sizeof(PyCodeObject *));
        if (pscf->preread == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pcode = ngx_array_push(pscf->preread);
    if (pcode == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_python_init_namespace(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *pcode = ngx_python_compile(cf, value[1].data);
    if (*pcode == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_python_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_python_srv_conf_t *pscf = conf;

    ngx_str_t      *value;
    PyCodeObject  **pcode;

    value = cf->args->elts;

    if (pscf->log == NGX_CONF_UNSET_PTR) {
        pscf->log = ngx_array_create(cf->pool, 1, sizeof(PyCodeObject *));
        if (pscf->log == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pcode = ngx_array_push(pscf->log);
    if (pcode == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_python_init_namespace(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *pcode = ngx_python_compile(cf, value[1].data);
    if (*pcode == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_python_content(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_python_srv_conf_t *pscf = conf;

    ngx_str_t                   *value;
    ngx_stream_core_srv_conf_t  *cscf;

    value = cf->args->elts;

    if (pscf->content) {
        return "is duplicate";
    }

    if (ngx_stream_python_init_namespace(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    pscf->content = ngx_python_compile(cf, value[1].data);
    if (pscf->content == NULL) {
        return NGX_CONF_ERROR;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    cscf->handler = ngx_stream_python_content_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_python_init_namespace(ngx_conf_t *cf)
{
    ngx_stream_python_main_conf_t  *pmcf;

    pmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_python_module);

    if (pmcf->ns == NULL) {
        pmcf->ns = ngx_python_create_namespace(cf);
        if (pmcf->ns == NULL) {
            return NGX_ERROR;
        }
    }

    if (ngx_stream_python_session_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
