
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <Python.h>


typedef struct {
    ngx_array_t               modules;  /* ngx_http_python_module_t */
} ngx_http_python_main_conf_t;


typedef struct {
    u_char                   *name;
    PyObject                 *module;
} ngx_http_python_module_t;


typedef struct {
    u_char                   *name;
    ngx_http_complex_value_t  value;
} ngx_http_python_arg_t;


typedef struct {
    PyObject                 *func;
    u_char                   *name;
    ngx_int_t                 index;
    ngx_uint_t                nargs;
    ngx_uint_t                nkwargs;
    ngx_http_python_arg_t    *args;
} ngx_http_python_variable_t;


typedef struct {
    int                       dummy; /*XXX dummy */
} ngx_http_python_loc_conf_t;


static void *ngx_http_python_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_python_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_python_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_python_import(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_python_init(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_python_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_python_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static PyObject *ngx_http_python_variable_get_object(ngx_http_request_t *r,
    ngx_http_python_variable_t *pv);
static char *ngx_http_python_access(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_python_content(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_http_python_decref(void *data);
static PyObject *ngx_http_python_get_func(ngx_conf_t *cf,
    ngx_http_python_main_conf_t *pmcf, u_char *name);


static ngx_command_t  ngx_http_python_commands[] = {

    { ngx_string("python_import"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_python_import,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_init"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_python_init,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_set"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_python_set,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_python_access,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("python_content"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_python_content,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_python_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_python_create_main_conf,      /* create main configuration */
    NULL,                                  /* init main configuration */

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


static void *
ngx_http_python_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_python_main_conf_t  *pmcf;

    pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_python_main_conf_t));
    if (pmcf == NULL) {
        return NULL;
    }

    return pmcf;
}


static void *
ngx_http_python_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_python_loc_conf_t  *plcf;

    plcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_python_loc_conf_t));
    if (plcf == NULL) {
        return NULL;
    }

    return plcf;
}


static char *
ngx_http_python_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_python_loc_conf_t *prev = parent;
    ngx_http_python_loc_conf_t *conf = child;

    (void) prev;
    (void) conf;

    return NGX_CONF_OK;
}


static char *
ngx_http_python_import(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_python_main_conf_t *pmcf = conf;

	PyObject                  *module;
    ngx_str_t                 *value;
    ngx_pool_cleanup_t        *cln;
    ngx_http_python_module_t  *m;

    value = cf->args->elts;

    Py_Initialize();

    module = PyImport_ImportModule((char *) value[1].data);

    if (module == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "could not load Python module \"%s\"",
                           value[1].data);
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        Py_DECREF(module);
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_python_decref;
    cln->data = module;

    if (pmcf->modules.nalloc == 0) {
        if (ngx_array_init(&pmcf->modules, cf->pool, 1,
                           sizeof(ngx_http_python_module_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    m = ngx_array_push(&pmcf->modules);
    if (m == NULL) {
        return NGX_CONF_ERROR;
    }

    m->name = value[1].data;
    m->module = module;

    return NGX_CONF_OK;
}


static char *
ngx_http_python_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_python_main_conf_t *pmcf = conf;

    u_char      *p;
    PyObject    *func, *arg, *args, *kwargs, *ret;
    ngx_str_t   *value;
    ngx_uint_t   n, kwn;

    value = cf->args->elts;

    for (kwn = 0, n = 0; n < cf->args->nelts - 2; n++) {
        if (ngx_strchr(value[n + 2].data, '=')) {
            kwn++;
            continue;
        }

        if (kwn) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "positional argument \"%V\" "
                               "after a named argument", &value[n + 2]);
            return NGX_CONF_ERROR;
        }
    }

    func = ngx_http_python_get_func(cf, pmcf, value[1].data);
    if (func == NULL) {
        return NGX_CONF_ERROR;
    }

    ret = NULL;
    kwargs = NULL;
    arg = NULL;

    args = PyTuple_New(cf->args->nelts - 2 - kwn);
    if (args == NULL) {
        goto failed;
    }

    kwargs = PyDict_New();
    if (kwargs == NULL) {
        goto failed;
    }

    for (n = 0; n < cf->args->nelts - 2; n++) {
        p = (u_char *) ngx_strchr(value[n + 2].data, '=');

        if (p == NULL) {
            arg = PyString_FromString((char *) value[n + 2].data);
            if (arg == NULL) {
                goto failed;
            }

            if (PyTuple_SetItem(args, n, arg) < 0) {
                goto failed;
            }

        } else {
            *p++ = 0;

            arg = PyString_FromString((char *) p);
            if (arg == NULL) {
                goto failed;
            }

            if (PyDict_SetItemString(kwargs, (char *) value[n + 2].data, arg)
                < 0)
            {
                goto failed;
            }
        }

        Py_DECREF(arg);
        arg = NULL;
    }

    ret = PyEval_CallObjectWithKeywords(func, args, kwargs);

    if (ret == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "function raised an exception");
    }

failed:

    Py_XDECREF(func);
    Py_XDECREF(args);
    Py_XDECREF(kwargs);
    Py_XDECREF(arg);
    Py_XDECREF(ret);

    return NGX_CONF_OK;
}


static char *
ngx_http_python_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_python_main_conf_t *pmcf = conf;

    u_char                            *p;
    ngx_str_t                         *value, arg;
    ngx_uint_t                         n;
    ngx_pool_cleanup_t                *cln;
    ngx_http_variable_t               *var;
    ngx_http_python_variable_t        *pv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    pv = ngx_pcalloc(cf->pool, sizeof(ngx_http_python_variable_t));
    if (pv == NULL) {
        return NGX_CONF_ERROR;
    }

    var = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_python_variable;
    var->data = (uintptr_t) pv;

    if (value[2].len > 1 && value[2].data[0] == '$') {
        pv->name = (u_char *) ngx_strchr(value[2].data, '.');
        if (pv->name == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "function name missing in \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        value[2].data++;
        value[2].len = pv->name - value[2].data;

        *pv->name++ = 0;

        pv->index = ngx_http_get_variable_index(cf, &value[2]);
        if (pv->index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

    } else {
        pv->func = ngx_http_python_get_func(cf, pmcf, value[2].data);
        if (pv->func == NULL) {
            return NGX_CONF_ERROR;
        }

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            Py_DECREF(pv->func);
            return NGX_CONF_ERROR;
        }

        cln->handler = ngx_http_python_decref;
        cln->data = pv->func;
    }

    pv->nargs = cf->args->nelts - 3;
    pv->args = ngx_pcalloc(cf->pool,
                           sizeof(ngx_http_python_arg_t) * pv->nargs);
    if (pv->args == NULL) {
        return NGX_CONF_ERROR;
    }

    for (n = 0; n < pv->nargs; n++) {
        arg = value[n + 3];

        p = (u_char *) ngx_strchr(arg.data, '=');

        if (n > 0 && p == NULL && pv->args[n - 1].name) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "positional argument "
                               "\"%V\" after a named argument", &arg);
            return NGX_CONF_ERROR;
        }

        if (p) {
            pv->args[n].name = arg.data;
            pv->nkwargs++;

            *p++ = 0;

            arg.len = arg.data + arg.len - p;
            arg.data = p;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &arg;
        ccv.complex_value = &pv->args[n].value;
        ccv.zero = 1;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_python_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_python_variable_t *pv = (ngx_http_python_variable_t *) data;

    u_char      *p;
    PyObject    *obj, *str;
    Py_ssize_t   size;

    obj = ngx_http_python_variable_get_object(r, pv);
    if (obj == NULL) {
        return NGX_ERROR;
    }

    str = PyObject_Str(obj);

    Py_DECREF(obj);

    if (str == NULL) {
        return NGX_ERROR;
    }

    if (PyString_AsStringAndSize(str, (char **) &p, &size) < 0) {
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
    v->no_cacheable = 1;
    v->not_found = 0;

    Py_DECREF(str);

    return NGX_OK;
}


static PyObject *
ngx_http_python_variable_get_object(ngx_http_request_t *r,
    ngx_http_python_variable_t *pv)
{
    PyObject                    *obj, *func, *args, *kwargs, *arg, *ret;
    ngx_str_t                    value;
    ngx_uint_t                   n, i;
    ngx_http_variable_t         *v;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_python_variable_t  *ppv;

    func = NULL;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python get_object func: 0x%p, name: \"%s\", "
                   "index: %i, nargs: %ui, nkwargs: %ui",
                   pv->func, pv->name ? pv->name : (u_char *) "",
                   pv->index, pv->nargs, pv->nkwargs);

    if (pv->func == NULL) {
        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        v = cmcf->variables.elts;

        if (v[pv->index].get_handler != ngx_http_python_variable) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, 
                          "python variable required to call a python function");
            return NULL;
        }

        ppv = (ngx_http_python_variable_t *) v[pv->index].data;

        obj = ngx_http_python_variable_get_object(r, ppv);
        if (obj == NULL) {
            return NULL;
        }

        func = PyObject_GetAttrString(obj, (char *) pv->name);

        Py_DECREF(obj);

        if (func == NULL) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "function \"%s\" not found in object", pv->name);
            return NULL;
        }

        if (!PyCallable_Check(func)) {
            Py_DECREF(func);
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "\"%s\" is not a function", pv->name);
            return NULL;
        }
    }

    ret = NULL;
    kwargs = NULL;
    arg = NULL;

    args = PyTuple_New(pv->nargs - pv->nkwargs);
    if (args == NULL) {
        goto failed;
    }

    kwargs = PyDict_New();
    if (kwargs == NULL) {
        goto failed;
    }

    for (i = 0, n = 0; n < pv->nargs; n++) {
        if (ngx_http_complex_value(r, &pv->args[n].value, &value) != NGX_OK) {
            goto failed;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http python argument \"%s\" value: \"%s\"",
                       pv->name ? pv->name : (u_char *) "", value.data);

        arg = PyString_FromString((char *) value.data);
        if (arg == NULL) {
            goto failed;
        }

        if (pv->args[n].name) {
            if (PyDict_SetItemString(kwargs, (char *) pv->args[n].name, arg)
                < 0)
            {
                goto failed;
            }

        } else {
            if (PyTuple_SetItem(args, i++, arg) < 0) {
                goto failed;
            }
        }

        Py_DECREF(arg);
        arg = NULL;
    }

    ret = PyEval_CallObjectWithKeywords(func ? func : pv->func, args, kwargs);

    if (ret == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                      "function raised an exception");
    }

failed:

    Py_XDECREF(func);
    Py_XDECREF(args);
    Py_XDECREF(kwargs);
    Py_XDECREF(arg);

    return ret;
}


static char *
ngx_http_python_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_python_loc_conf_t *plcf = conf;

    (void) plcf;

    return NGX_CONF_OK;
}


static char *
ngx_http_python_content(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_python_loc_conf_t *plcf = conf;

    (void) plcf;

    return NGX_CONF_OK;
}


static void
ngx_http_python_decref(void *data)
{
    PyObject *obj = data;

    Py_DECREF(obj);
}


static PyObject *
ngx_http_python_get_func(ngx_conf_t *cf, ngx_http_python_main_conf_t *pmcf,
    u_char *name)
{
    u_char                    *p;
    PyObject                  *func;
    ngx_uint_t                 n;
    ngx_http_python_module_t  *modules;

    p = (u_char *) ngx_strchr(name, '.');
    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "missing module prefix in function name \"%s\"",
                           name);
        return NULL;
    }

    *p++ = '\0';

    modules = pmcf->modules.elts;

    for (n = 0; n < pmcf->modules.nelts; n++) {
        if (ngx_strcmp(modules[n].name, name) == 0) {

            func = PyObject_GetAttrString(modules[n].module, (char *) p);
            if (func == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "function \"%s\" not found in module \"%s\"",
                                   p, name);
                return NULL;
            }

            if (!PyCallable_Check(func)) {
                Py_DECREF(func);
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "\"%s\" in module \"%s\" is not a function",
                                   p, name);
                return NULL;
            }

            return func;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "module \"%s\" not imported",
                       name);

    return NULL;
}
