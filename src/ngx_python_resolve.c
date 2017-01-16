
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
#include "ngx_python.h"


#if !(NGX_PYTHON_SYNC)

typedef struct {
    int                 family;
    int                 type;
    int                 proto;
    int                 port;
    ngx_str_t           addr;
    ngx_str_t           host;
    PyObject           *result;
    ngx_python_ctx_t   *pctx;
} ngx_python_resolve_ctx_t;


static PyObject *ngx_python_resolve_gethostbyname(PyObject *self,
    PyObject *args);
static void ngx_python_resolve_gethostbyname_handler(ngx_resolver_ctx_t *ctx);
static PyObject *ngx_python_resolve_gethostbyname_ex(PyObject *self,
    PyObject *args);
static void ngx_python_resolve_gethostbyname_ex_handler(
    ngx_resolver_ctx_t *ctx);
static PyObject *ngx_python_resolve_getaddrinfo(PyObject *self,
    PyObject *args);
static void ngx_python_resolve_getaddrinfo_handler(ngx_resolver_ctx_t *ctx);
static PyObject *ngx_python_resolve_gethostbyaddr(PyObject *self,
    PyObject *args);
static void ngx_python_resolve_gethostbyaddr_handler(ngx_resolver_ctx_t *ctx);
static PyObject *ngx_python_resolve_getnameinfo(PyObject *self,
    PyObject *args);
static void ngx_python_resolve_getnameinfo_handler(ngx_resolver_ctx_t *ctx);

static PyObject *ngx_python_resolve_name(PyObject *self, ngx_str_t *host,
    ngx_resolver_handler_pt handler, ngx_python_resolve_ctx_t *rctx);
static PyObject *ngx_python_resolve_addr(PyObject *self, ngx_str_t *addr,
    ngx_resolver_handler_pt handler, ngx_python_resolve_ctx_t *rctx);

static PyObject *ngx_python_resolve_fmtaddr(struct sockaddr *sockaddr,
    ngx_uint_t addronly);
static PyObject *ngx_python_resolve_set_herror(int herr, char *msg);
static PyObject *ngx_python_resolve_set_gaierror(int gerr, char *msg);


static PyMethodDef ngx_python_resolve_functions[] = {

    { "gethostbyname",
      (PyCFunction) ngx_python_resolve_gethostbyname,
      METH_VARARGS,
      "resolve host name" },

    { "gethostbyname_ex",
      (PyCFunction) ngx_python_resolve_gethostbyname_ex,
      METH_VARARGS,
      "resolve host name" },

    { "getaddrinfo",
      (PyCFunction) ngx_python_resolve_getaddrinfo,
      METH_VARARGS,
      "resolve host name" },

    { "gethostbyaddr",
      (PyCFunction) ngx_python_resolve_gethostbyaddr,
      METH_VARARGS,
      "resolve address into host name" },

    { "getnameinfo",
      (PyCFunction) ngx_python_resolve_getnameinfo,
      METH_VARARGS,
      "resolve address into host name" },

    { NULL, NULL, 0, NULL }
};


static PyObject  *ngx_python_resolve_herror;
static PyObject  *ngx_python_resolve_gaierror;


static PyObject *
ngx_python_resolve_gethostbyname(PyObject *self, PyObject *args)
{
    int                        len;
    char                      *data;
    ngx_str_t                  host;
    ngx_python_resolve_ctx_t   rctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.gethostbyname()");

    if (!PyArg_ParseTuple(args, "s#:gethostbyname", &data, &len)) {
        return NULL;
    }

    host.data = (u_char *) data;
    host.len = len;

    ngx_memzero(&rctx, sizeof(ngx_python_resolve_ctx_t));

    return ngx_python_resolve_name(self, &host,
                                   ngx_python_resolve_gethostbyname_handler,
                                   &rctx);
}


static void
ngx_python_resolve_gethostbyname_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_python_resolve_ctx_t  *rctx = ctx->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.gethostbyname_handler()");

    if (ctx->state == NGX_RESOLVE_TIMEDOUT) {
        ngx_python_resolve_set_herror(TRY_AGAIN, "resolve timed out");
        goto failed;
    }

    if (ctx->state == NGX_RESOLVE_NXDOMAIN || ctx->naddrs == 0) {
        ngx_python_resolve_set_herror(HOST_NOT_FOUND, "host not found");
        goto failed;
    }

    if (ctx->state) {
        ngx_python_resolve_set_herror(NO_RECOVERY, "resolver error");
        goto failed;
    }

    rctx->result = ngx_python_resolve_fmtaddr(ctx->addrs[0].sockaddr, 1);

failed:

    if (rctx->pctx) {
        ngx_python_wakeup(rctx->pctx);
    }
}


static PyObject *
ngx_python_resolve_gethostbyname_ex(PyObject *self, PyObject *args)
{
    int                        len;
    char                      *data;
    ngx_str_t                  host;
    ngx_python_resolve_ctx_t   rctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.gethostbyname_ex()");

    if (!PyArg_ParseTuple(args, "s#:gethostbyname_ex", &data, &len)) {
        return NULL;
    }

    host.data = (u_char *) data;
    host.len = len;

    ngx_memzero(&rctx, sizeof(ngx_python_resolve_ctx_t));

    rctx.host = host;

    return ngx_python_resolve_name(self, &host,
                                   ngx_python_resolve_gethostbyname_ex_handler,
                                   &rctx);
}


static void
ngx_python_resolve_gethostbyname_ex_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_python_resolve_ctx_t  *rctx = ctx->data;

    PyObject    *list, *addr, *aliases;
    ngx_uint_t   i;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.gethostbyname_ex_handler()");

    list = NULL;

    if (ctx->state == NGX_RESOLVE_TIMEDOUT) {
        ngx_python_resolve_set_herror(TRY_AGAIN, "resolve timed out");
        goto failed;
    }

    if (ctx->state == NGX_RESOLVE_NXDOMAIN || ctx->naddrs == 0) {
        ngx_python_resolve_set_herror(HOST_NOT_FOUND, "host not found");
        goto failed;
    }

    if (ctx->state) {
        ngx_python_resolve_set_herror(NO_RECOVERY, "resolver error");
        goto failed;
    }

    list = PyList_New(0);
    if (list == NULL) {
        goto failed;
    }

    for (i = 0; i < ctx->naddrs; i++) {
        addr = ngx_python_resolve_fmtaddr(ctx->addrs[i].sockaddr, 1);
        if (addr == NULL) {
            goto failed;
        }

        if (PyList_Append(list, addr) < 0) {
            Py_DECREF(addr);
            goto failed;
        }

        Py_DECREF(addr);
    }

    aliases = PyList_New(0);
    if (aliases == NULL) {
        goto failed;
    }

    rctx->result = Py_BuildValue("(s#OO)", rctx->host.data, rctx->host.len,
                                 aliases, list);

    Py_DECREF(aliases);

failed:

    Py_XDECREF(list);

    if (rctx->pctx) {
        ngx_python_wakeup(rctx->pctx);
    }
}


static PyObject *
ngx_python_resolve_getaddrinfo(PyObject *self, PyObject *args)
{
    int                        len, family, type, proto, flags, port;
    char                      *data, *srv, *ps;
    PyObject                  *psrv;
    ngx_str_t                  host;
    struct servent            *se;
    ngx_python_resolve_ctx_t   rctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.getaddrinfo()");

    type = 0;
    proto = 0;
    flags = 0;
    family = AF_UNSPEC;

    if (!PyArg_ParseTuple(args, "s#O|iiii:getaddrinfo",
                          &data, &len, &psrv, &family, &type, &proto, &flags))
    {
        return NULL;
    }

    host.data = (u_char *) data;
    host.len = len;

    port = PyLong_AsLong(psrv);
    if (port == -1) {
        PyErr_Clear();

        srv = PyString_AsString(psrv);
        if (srv == NULL) {
            return NULL;
        }

        switch (type) {
        case SOCK_STREAM:
            ps = "tcp";
            break;

        case SOCK_DGRAM:
            ps = "udp";
            break;

        default:
            ps = NULL;
        }

        se = getservbyname(srv, ps);
        if (se == NULL) {
            PyErr_SetString(PyExc_RuntimeError, "unknown service name");
            return NULL;
        }

        port = ntohs(se->s_port);
    }

    ngx_memzero(&rctx, sizeof(ngx_python_resolve_ctx_t));

    rctx.family = family;
    rctx.port = port;
    rctx.type = type;
    rctx.proto = proto;

    return ngx_python_resolve_name(self, &host,
                                   ngx_python_resolve_getaddrinfo_handler,
                                   &rctx);
}


static void
ngx_python_resolve_getaddrinfo_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_python_resolve_ctx_t  *rctx = ctx->data;

    int               type;
    PyObject         *list, *addr, *entry;
    ngx_uint_t        i, j;
    struct sockaddr  *sa;

    static int socktypes[] = { SOCK_STREAM, SOCK_DGRAM };

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.getaddrinfo_handler()");

    list = NULL;

    if (ctx->state == NGX_RESOLVE_TIMEDOUT) {
        ngx_python_resolve_set_gaierror(EAI_AGAIN, "resolve timed out");
        goto failed;
    }

    if (ctx->state == NGX_RESOLVE_NXDOMAIN || ctx->naddrs == 0) {
        ngx_python_resolve_set_gaierror(NGX_RESOLVE_NXDOMAIN, "host not found");
        goto failed;
    }

    if (ctx->state) {
        ngx_python_resolve_set_gaierror(EAI_FAIL, "resolver error");
        goto failed;
    }

    list = PyList_New(0);
    if (list == NULL) {
        goto failed;
    }

    for (i = 0; i < ctx->naddrs; i++) {
        sa = ctx->addrs[i].sockaddr;

        if (rctx->family && rctx->family != sa->sa_family) {
            continue;
        }

        ngx_inet_set_port(sa, rctx->port);

        addr = ngx_python_resolve_fmtaddr(sa, 0);
        if (addr == NULL) {
            goto failed;
        }

        for (j = 0; j < 2; j++) {
            type = socktypes[j];

            if (rctx->type && rctx->type != type) {
                continue;
            }

            entry = Py_BuildValue("(iiisO)",
                                  sa->sa_family, type, rctx->proto, "", addr);
            if (entry == NULL) {
                Py_DECREF(addr);
                goto failed;
            }

            if (PyList_Append(list, entry) < 0) {
                Py_DECREF(entry);
                Py_DECREF(addr);
                goto failed;
            }

            Py_DECREF(entry);
        }

        Py_DECREF(addr);
    }

    rctx->result = list;

    list = NULL;

failed:

    Py_XDECREF(list);

    if (rctx->pctx) {
        ngx_python_wakeup(rctx->pctx);
    }
}


static PyObject *
ngx_python_resolve_gethostbyaddr(PyObject *self, PyObject *args)
{
    int                        len;
    char                      *data;
    ngx_str_t                  addr;
    ngx_python_resolve_ctx_t   rctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.gethostbyaddr()");

    if (!PyArg_ParseTuple(args, "s#:gethostbyaddr", &data, &len)) {
        return NULL;
    }

    addr.data = (u_char *) data;
    addr.len = len;

    ngx_memzero(&rctx, sizeof(ngx_python_resolve_ctx_t));

    rctx.addr = addr;

    return ngx_python_resolve_addr(self, &addr,
                                   ngx_python_resolve_gethostbyaddr_handler,
                                   &rctx);
}


static void
ngx_python_resolve_gethostbyaddr_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_python_resolve_ctx_t  *rctx = ctx->data;

    PyObject  *list, *entry;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.gethostbyaddr_handler()");

    list = NULL;

    if (ctx->state == NGX_RESOLVE_TIMEDOUT) {
        ngx_python_resolve_set_herror(TRY_AGAIN, "resolve timed out");
        goto failed;
    }

    if (ctx->state == NGX_RESOLVE_NXDOMAIN || ctx->name.len == 0) {
        ngx_python_resolve_set_herror(HOST_NOT_FOUND, "address not found");
        goto failed;
    }

    if (ctx->state) {
        ngx_python_resolve_set_herror(NO_RECOVERY, "resolver error");
        goto failed;
    }

    list = PyList_New(0);
    if (list == NULL) {
        goto failed;
    }

    entry = PyString_FromStringAndSize((char *) rctx->addr.data,
                                       rctx->addr.len);
    if (entry == NULL) {
        goto failed;
    }

    if (PyList_Append(list, entry) < 0) {
        Py_DECREF(entry);
        goto failed;
    }

    Py_DECREF(entry);

    rctx->result = Py_BuildValue("(s#OO)", ctx->name.data, ctx->name.len,
                                 Py_None, list);

failed:

    Py_XDECREF(list);

    if (rctx->pctx) {
        ngx_python_wakeup(rctx->pctx);
    }
}


static PyObject *
ngx_python_resolve_getnameinfo(PyObject *self, PyObject *args)
{
    int                        port, flags, len, fi, sid;
    char                      *data;
    PyObject                  *sa;
    ngx_str_t                  addr;
    ngx_python_resolve_ctx_t   rctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.getnameinfo()");

    if (!PyArg_ParseTuple(args, "Oi:getnameinfo", &sa, &flags)) {
        return NULL;
    }

    if (!PyArg_ParseTuple(sa, "s#i|II", &data, &len, &port, &fi, &sid)) {
        return NULL;
    }

    addr.data = (u_char *) data;
    addr.len = len;

    ngx_memzero(&rctx, sizeof(ngx_python_resolve_ctx_t));

    rctx.port = port;

    return ngx_python_resolve_addr(self, &addr,
                                   ngx_python_resolve_getnameinfo_handler,
                                   &rctx);
}


static void
ngx_python_resolve_getnameinfo_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_python_resolve_ctx_t  *rctx = ctx->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.getnameinfo_handler()");

    if (ctx->state == NGX_RESOLVE_TIMEDOUT) {
        ngx_python_resolve_set_gaierror(EAI_AGAIN, "resolve timed out");
        goto failed;
    }

    if (ctx->state == NGX_RESOLVE_NXDOMAIN || ctx->name.len == 0) {
        ngx_python_resolve_set_gaierror(NGX_RESOLVE_NXDOMAIN,
                                        "address not found");
        goto failed;
    }

    if (ctx->state) {
        ngx_python_resolve_set_gaierror(EAI_FAIL, "resolver error");
        goto failed;
    }

    rctx->result = Py_BuildValue("(s#i)", ctx->name.data, ctx->name.len,
                                 rctx->port);

failed:

    if (rctx->pctx) {
        ngx_python_wakeup(rctx->pctx);
    }
}


static PyObject *
ngx_python_resolve_name(PyObject *self, ngx_str_t *host,
    ngx_resolver_handler_pt handler, ngx_python_resolve_ctx_t *rctx)
{
    ngx_msec_t                  timeout;
    ngx_resolver_t             *resolver;
    ngx_python_ctx_t           *pctx;
    ngx_resolver_ctx_t         *ctx;
    static ngx_resolver_ctx_t   temp;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.resolve_name()");

    resolver = NULL;
    timeout = 0;

    pctx = ngx_python_get_ctx();
    if (pctx) {
        resolver = ngx_python_get_resolver(pctx, &timeout);
    }

    if (resolver == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "missing resolver");
        return NULL;
    }

    temp.name = *host;

    ctx = ngx_resolve_start(resolver, &temp);
    if (ctx == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "resolver error");
        return NULL;
    }

    if (ctx == NGX_NO_RESOLVER) {
        PyErr_SetString(PyExc_RuntimeError, "no resolver");
        return NULL;
    }

    ctx->name = *host;
    ctx->handler = handler;
    ctx->data = rctx;
    ctx->timeout = timeout;

    if (ngx_resolve_name(ctx) != NGX_OK) {
        PyErr_SetString(PyExc_RuntimeError, "resolver error");
        return NULL;
    }

    while (ctx->state == NGX_AGAIN) {
        rctx->pctx = pctx;

        if (ngx_python_yield() != NGX_OK) {
            break;
        }
    }

    ngx_resolve_name_done(ctx);

    return rctx->result;
}


static PyObject *
ngx_python_resolve_addr(PyObject *self, ngx_str_t *addr,
    ngx_resolver_handler_pt handler, ngx_python_resolve_ctx_t *rctx)
{
    in_addr_t             inaddr;
    socklen_t             socklen;
    ngx_msec_t            timeout;
    ngx_sockaddr_t        sa;
    ngx_resolver_t       *resolver;
    ngx_python_ctx_t     *pctx;
    struct sockaddr_in   *sin;
    ngx_resolver_ctx_t   *ctx;
#if (NGX_HAVE_INET6)
    struct in6_addr       inaddr6;
    struct sockaddr_in6  *sin6;
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.resolve_addr()");

    resolver = NULL;
    timeout = 0;

    pctx = ngx_python_get_ctx();
    if (pctx) {
        resolver = ngx_python_get_resolver(pctx, &timeout);
    }

    if (resolver == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "missing resolver");
        return NULL;
    }

    inaddr = ngx_inet_addr(addr->data, addr->len);
    if (inaddr != INADDR_NONE) {
        sin = (struct sockaddr_in *) &sa.sockaddr_in;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = inaddr;
        sin->sin_port = 0;
        socklen = sizeof(struct sockaddr_in);

#if (NGX_HAVE_INET6)
    } else if (ngx_inet6_addr(addr->data, addr->len, (u_char *) &inaddr6)
               == NGX_OK)
    {
        sin6 = (struct sockaddr_in6 *) &sa.sockaddr_in6;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = inaddr6;
        sin6->sin6_port = 0;
        socklen = sizeof(struct sockaddr_in6);
#endif

    } else {
        PyErr_SetString(PyExc_RuntimeError, "bad address");
        return NULL;
    }

    ctx = ngx_resolve_start(resolver, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    if (ctx == NGX_NO_RESOLVER) {
        PyErr_SetString(PyExc_RuntimeError, "no resolver");
        return NULL;
    }

    ctx->addr.sockaddr = &sa.sockaddr;
    ctx->addr.socklen = socklen;
    ctx->handler = handler;
    ctx->data = rctx;
    ctx->timeout = timeout;

    if (ngx_resolve_addr(ctx) != NGX_OK) {
        return NULL;
    }

    while (ctx->state == NGX_AGAIN) {
        rctx->pctx = pctx;

        if (ngx_python_yield() != NGX_OK) {
            break;
        }
    }

    ngx_resolve_addr_done(ctx);

    return rctx->result;
}


static PyObject *
ngx_python_resolve_fmtaddr(struct sockaddr *sockaddr, ngx_uint_t addronly)
{
    u_char                buffer[NGX_SOCKADDR_STRLEN];
    size_t                len;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (sockaddr->sa_family) {

#if (NGX_HAVE_INET6)

    case AF_INET6:

        sin6 = (struct sockaddr_in6 *) sockaddr;

        len = ngx_inet6_ntop((u_char *) &sin6->sin6_addr, buffer,
                             sizeof(buffer));

        if (addronly) {
            return PyString_FromStringAndSize((char *) buffer, len);
        }

        return Py_BuildValue("(s#iii)", buffer, (int) len,
                             (int) ntohs(sin6->sin6_port), 0, 0);

#endif

    default: /* AF_INET */

        sin = (struct sockaddr_in *) sockaddr;

        len = ngx_inet_ntop(AF_INET, &sin->sin_addr.s_addr, buffer,
                            sizeof(buffer));

        if (addronly) {
            return PyString_FromStringAndSize((char *) buffer, len);
        }

        return Py_BuildValue("(s#i)", buffer, (int) len,
                             (int) ntohs(sin->sin_port));
    }
}


static PyObject *
ngx_python_resolve_set_herror(int herr, char *msg)
{
    PyObject  *err;

    err = Py_BuildValue("(is)", herr, msg);
    if (err == NULL) {
        return NULL;
    }

    PyErr_SetObject(ngx_python_resolve_herror, err);
    Py_DECREF(err);

    return NULL;
}


static PyObject *
ngx_python_resolve_set_gaierror(int gerr, char *msg)
{
    PyObject  *err;

    err = Py_BuildValue("(is)", gerr, msg);
    if (err == NULL) {
        return NULL;
    }

    PyErr_SetObject(ngx_python_resolve_gaierror, err);
    Py_DECREF(err);

    return NULL;
}


ngx_int_t
ngx_python_resolve_install(ngx_conf_t *cf)
{
    PyObject     *sm, *fun, *socket_error;
    PyMethodDef  *fn;

    sm = PyImport_ImportModule("socket");
    if (sm == NULL) {
        return NGX_ERROR;
    }

    socket_error = PyObject_GetAttrString(sm, "error");
    if (socket_error == NULL) {
        Py_DECREF(sm);
        return NGX_ERROR;
    }

    ngx_python_resolve_herror = PyErr_NewException("socket.herror",
                                                    socket_error, NULL);
    if (ngx_python_resolve_herror == NULL) {
        Py_DECREF(sm);
        return NGX_ERROR;
    }

    ngx_python_resolve_gaierror = PyErr_NewException("socket.gaierror",
                                                     socket_error, NULL);
    if (ngx_python_resolve_gaierror == NULL) {
        Py_DECREF(sm);
        return NGX_ERROR;
    }

    if (PyObject_SetAttrString(sm, "herror", ngx_python_resolve_herror) < 0) {
        Py_DECREF(sm);
        return NGX_ERROR;
    }

    if (PyObject_SetAttrString(sm, "gaierror", ngx_python_resolve_gaierror) < 0)
    {
        Py_DECREF(sm);
        return NGX_ERROR;
    }

    for (fn = ngx_python_resolve_functions; fn->ml_name; fn++) {

        fun = PyCFunction_NewEx(fn, NULL, NULL);
        if (fun == NULL) {
            Py_DECREF(sm);
            return NGX_ERROR;
        }

        if (PyObject_SetAttrString(sm, fn->ml_name, fun) < 0) {
            Py_DECREF(fun);
            Py_DECREF(sm);
            return NGX_ERROR;
        }

        Py_DECREF(fun);
    }

    Py_DECREF(sm);
    return NGX_OK;
}

#endif
