
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_python.h"
#include "ngx_http_python_request.h"


typedef struct {
    PyObject                   *ns;
    size_t                      stack_size;
} ngx_http_python_main_conf_t;


typedef struct {
    ngx_array_t                *access;  /* array of PyCodeObject * */
    ngx_array_t                *log;     /* array of PyCodeObject * */
    PyCodeObject               *content;
} ngx_http_python_loc_conf_t;


typedef struct {
    ngx_uint_t                  phase;
    ngx_uint_t                  passed;
    PyObject                   *request;
    ngx_python_ctx_t           *python;
} ngx_http_python_ctx_t;


static ngx_int_t ngx_http_python_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_python_log_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_python_content_handler(ngx_http_request_t *r);
static void ngx_http_python_content_event_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_python_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static PyObject *ngx_http_python_eval(ngx_http_request_t *r, PyCodeObject *code,
    ngx_event_t *wake);

static char *ngx_http_python_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_python_access(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_python_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_python_content(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_python_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_python_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_python_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_python_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_python_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_python_init_namespace(ngx_conf_t *cf);


static ngx_command_t  ngx_http_python_commands[] = {

    { ngx_string("python"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_python_set_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_python_main_conf_t, ns),
      NULL },

    { ngx_string("python_include"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_python_include_set_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_python_main_conf_t, ns),
      NULL },

    { ngx_string("python_stack_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_python_main_conf_t, stack_size),
      NULL },

    { ngx_string("python_set"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_python_set,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_python_access,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_python_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_content"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_python_content,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_python_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_python_init,                  /* postconfiguration */

    ngx_http_python_create_main_conf,      /* create main configuration */
    ngx_http_python_init_main_conf,        /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_python_create_loc_conf,       /* create location configuration */
    ngx_http_python_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_python_module = {
    NGX_MODULE_V1,
    &ngx_http_python_module_ctx,           /* module context */
    ngx_http_python_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
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
ngx_http_python_access_handler(ngx_http_request_t *r)
{
    PyObject                     *ret;
    ngx_int_t                     rc;
    PyCodeObject                **pcode;
    ngx_http_python_ctx_t        *ctx;
    ngx_http_python_loc_conf_t   *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_python_module);

    if (plcf->access == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python access handler");

    pcode = plcf->access->elts;

    ctx = ngx_http_get_module_ctx(r, ngx_http_python_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_python_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_python_module);
    }

    while (ctx->phase < plcf->access->nelts) {
        ret = ngx_http_python_eval(r, pcode[ctx->phase], r->connection->write);

        if (ret == NGX_PYTHON_AGAIN) {
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
ngx_http_python_log_handler(ngx_http_request_t *r)
{
    ngx_uint_t                    n;
    PyObject                     *ret;
    PyCodeObject                **pcode;
    ngx_http_python_loc_conf_t   *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_python_module);

    if (plcf->log == NULL) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python log handler");

    pcode = plcf->log->elts;

    for (n = 0; n < plcf->log->nelts; n++) {
        ret = ngx_http_python_eval(r, pcode[n], NULL);
        Py_XDECREF(ret);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_python_content_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python content handler");

    rc = ngx_http_read_client_request_body(r,
                                         ngx_http_python_content_event_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_http_python_content_event_handler(ngx_http_request_t *r)
{
    PyObject                    *ret;
    ngx_int_t                    rc;
    ngx_http_python_loc_conf_t  *plcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python content event handler");

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_python_module);

    ret = ngx_http_python_eval(r, plcf->content, r->connection->write);

    if (ret == NGX_PYTHON_AGAIN) {
        r->write_event_handler = ngx_http_python_content_event_handler;
        return;
    }

    if (ret == NULL) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    rc = PyInt_Check(ret) ? PyInt_AsLong(ret) : NGX_OK;

    Py_DECREF(ret);

    ngx_http_finalize_request(r, rc);
}


static ngx_int_t
ngx_http_python_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    PyCodeObject  *code = (PyCodeObject *) data;

    u_char      *p;
    PyObject    *ret, *str;
    Py_ssize_t   size;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python variable handler");

    ret = ngx_http_python_eval(r, code, NULL);
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

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python variable: \"%*s\"", (size_t) size, p);

    v->len = size;
    v->data = ngx_pnalloc(r->pool, size);

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
ngx_http_python_eval(ngx_http_request_t *r, PyCodeObject *code,
    ngx_event_t *wake)
{
    PyObject                     *result, *pr;
    ngx_http_python_ctx_t        *ctx;
    ngx_python_create_ctx_t       pc;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_python_main_conf_t  *pmcf;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python eval start code:%p, wake:%p", code, wake);

    ctx = ngx_http_get_module_ctx(r, ngx_http_python_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_python_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_python_module);
    }

    if (ctx->request == NULL) {
        ctx->request = ngx_http_python_request_create(r);
        if (ctx->request == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "python error: %s", ngx_python_get_error(r->pool));
            return NULL;
        }
    }

    pmcf = ngx_http_get_module_main_conf(r, ngx_http_python_module);

    if (ctx->python == NULL) {
        ngx_memzero(&pc, sizeof(ngx_python_create_ctx_t));

        pc.pool = r->pool;
        pc.log = r->connection->log;
        pc.ns = pmcf->ns;
        pc.stack_size = pmcf->stack_size;

        ctx->python = ngx_python_create_ctx(&pc);
        if (ctx->python == NULL) {
            return NULL;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_python_set_resolver(ctx->python, clcf->resolver,
                            clcf->resolver_timeout);

    pr = PyDict_GetItemString(pmcf->ns, "r");

    if (pr == NULL) {
        if (PyDict_SetItemString(pmcf->ns, "r", ctx->request) < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "python error: %s", ngx_python_get_error(r->pool));
        }
    }

    result = ngx_python_eval(ctx->python, code, wake);

    if (pr == NULL) {
        if (PyDict_DelItemString(pmcf->ns, "r") < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "python error: %s",
                          ngx_python_get_error(r->pool));
        }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python eval end code:%p, wake:%p, result:%p",
                   code, wake, result);

    return result;
}


static void *
ngx_http_python_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_python_main_conf_t  *pmcf;

    pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_python_main_conf_t));
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
ngx_http_python_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_python_main_conf_t *pmcf = conf;

    ngx_conf_init_size_value(pmcf->stack_size, 32768);

    return NGX_CONF_OK;
}


static void *
ngx_http_python_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_python_loc_conf_t  *plcf;

    plcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_python_loc_conf_t));
    if (plcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     plcf->content = NULL;
     */

    plcf->access = NGX_CONF_UNSET_PTR;
    plcf->log = NGX_CONF_UNSET_PTR;

    return plcf;
}


static char *
ngx_http_python_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_python_loc_conf_t *prev = parent;
    ngx_http_python_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->access, prev->access, NULL);
    ngx_conf_merge_ptr_value(conf->log, prev->log, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_python_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_python_access_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_python_log_handler;

    return NGX_OK;
}


static char *
ngx_http_python_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t            *value;
    PyCodeObject         *code;
    ngx_http_variable_t  *var;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    var = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_python_init_namespace(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    code = ngx_python_compile(cf, value[2].data);
    if (code == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_python_variable;
    var->data = (uintptr_t) code;

    return NGX_CONF_OK;
}


static char *
ngx_http_python_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_python_loc_conf_t *plcf = conf;

    ngx_str_t      *value;
    PyCodeObject  **pcode;

    value = cf->args->elts;

    if (plcf->access == NGX_CONF_UNSET_PTR) {
        plcf->access = ngx_array_create(cf->pool, 1, sizeof(PyCodeObject *));
        if (plcf->access == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pcode = ngx_array_push(plcf->access);
    if (pcode == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_python_init_namespace(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *pcode = ngx_python_compile(cf, value[1].data);
    if (*pcode == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_python_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_python_loc_conf_t *plcf = conf;

    ngx_str_t      *value;
    PyCodeObject  **pcode;

    value = cf->args->elts;

    if (plcf->log == NGX_CONF_UNSET_PTR) {
        plcf->log = ngx_array_create(cf->pool, 1, sizeof(PyCodeObject *));
        if (plcf->log == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pcode = ngx_array_push(plcf->log);
    if (pcode == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_python_init_namespace(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *pcode = ngx_python_compile(cf, value[1].data);
    if (*pcode == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_python_content(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_python_loc_conf_t *plcf = conf;

    ngx_str_t                 *value;
    ngx_http_core_loc_conf_t  *clcf;

    value = cf->args->elts;

    if (plcf->content) {
        return "is duplicate";
    }

    if (ngx_http_python_init_namespace(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    plcf->content = ngx_python_compile(cf, value[1].data);
    if (plcf->content == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_python_content_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_python_init_namespace(ngx_conf_t *cf)
{
    ngx_http_python_main_conf_t  *pmcf;

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_python_module);

    if (pmcf->ns == NULL) {
        pmcf->ns = ngx_python_create_namespace(cf);
        if (pmcf->ns == NULL) {
            return NGX_ERROR;
        }
    }

    if (ngx_http_python_request_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
