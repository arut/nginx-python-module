
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
#include "ngx_python.h"

/* for PyMemberDef */
#include <structmember.h>


#if !(NGX_PYTHON_SYNC)

#define NGX_PYTHON_SOCKET_DEFAULT_TIMEOUT  60
#define NGX_PYTHON_SOCKET_DEFAULT_BUFSIZE  512


typedef struct {
    PyObject_HEAD
    int                   family;
    int                   type;
    int                   proto;
    double                timeout;
    ngx_pool_t           *pool;
    ngx_connection_t     *connection;
    ngx_addr_t           *local;
    PyObject             *weakreflist;
    unsigned              wrapper:1;
} ngx_python_socket_t;


typedef struct {
    PyObject_HEAD
    ngx_buf_t             buffer;
    ngx_python_socket_t  *socket;
    PyObject             *weakreflist;
} ngx_python_socket_file_t;


static PyObject *ngx_python_socket_unsupported(PyObject *self);
static PyObject *ngx_python_socket_unsupported_func(PyObject *self,
    PyObject *args);

static PyObject *ngx_python_socket_bind(ngx_python_socket_t *s, PyObject *addr);
static PyObject *ngx_python_socket_close(ngx_python_socket_t *s);
static PyObject *ngx_python_socket_connect(ngx_python_socket_t *s,
    PyObject *addr);
static PyObject *ngx_python_socket_connect_ex(ngx_python_socket_t *s,
    PyObject *addr);
static void ngx_python_socket_handler(ngx_event_t *event);
static PyObject *ngx_python_socket_fileno(ngx_python_socket_t *s);
static PyObject *ngx_python_socket_getpeername(ngx_python_socket_t *s);
static PyObject *ngx_python_socket_getsockname(ngx_python_socket_t *s);
static PyObject *ngx_python_socket_fmtaddr(struct sockaddr *sockaddr);
static PyObject *ngx_python_socket_getsockopt(ngx_python_socket_t *s,
    PyObject *args);
static PyObject *ngx_python_socket_makefile(ngx_python_socket_t *s,
    PyObject *args);
static PyObject *ngx_python_socket_recv(ngx_python_socket_t *s, PyObject *args);
static PyObject *ngx_python_socket_recv_into(ngx_python_socket_t *s,
    PyObject *args, PyObject *kwds);
static ssize_t ngx_python_socket_do_recv(ngx_python_socket_t *s, u_char *p,
    size_t len);
static PyObject *ngx_python_socket_recvfrom(ngx_python_socket_t *s,
    PyObject *args);
static PyObject *ngx_python_socket_recvfrom_into(ngx_python_socket_t *s,
    PyObject *args, PyObject *kwds);
static PyObject *ngx_python_socket_send(ngx_python_socket_t *s, PyObject *args);
static PyObject *ngx_python_socket_settimeout(ngx_python_socket_t *s,
    PyObject *arg);
static PyObject *ngx_python_socket_setblocking(ngx_python_socket_t *s,
    PyObject *arg);
static PyObject *ngx_python_socket_gettimeout(ngx_python_socket_t *s);
static PyObject *ngx_python_socket_setsockopt(ngx_python_socket_t *s,
    PyObject *args);
static PyObject *ngx_python_socket_shutdown(ngx_python_socket_t *s,
    PyObject *arg);
static int ngx_python_socket_getaddr(ngx_python_socket_t *s, PyObject *args,
    struct sockaddr *sockaddr, socklen_t *socklen);
static void ngx_python_socket_dealloc(ngx_python_socket_t *s);
static PyObject *ngx_python_socket_repr(ngx_python_socket_t *s);
static PyObject *ngx_python_socket_new(PyTypeObject *type, PyObject *args,
    PyObject *kwds);
static int ngx_python_socket_init(PyObject *self, PyObject *args,
    PyObject *kwds);
static double ngx_python_socket_getdefaulttimeout(ngx_python_socket_t *s);

static PyObject *ngx_python_socket_file_readline(ngx_python_socket_file_t *f,
    PyObject *args);
static PyObject *ngx_python_socket_file_read(ngx_python_socket_file_t *f,
    PyObject *args);
static PyObject *ngx_python_socket_file_get(ngx_python_socket_file_t *f,
    ngx_uint_t line, int max);
static PyObject *ngx_python_socket_file_write(ngx_python_socket_file_t *f,
    PyObject *args);
static PyObject *ngx_python_socket_file_fileno(ngx_python_socket_file_t *f);
static PyObject *ngx_python_socket_file_readlines(ngx_python_socket_file_t *f);
static PyObject *ngx_python_socket_file_writelines(ngx_python_socket_file_t *f,
    PyObject *sq);
static PyObject *ngx_python_socket_file_flush(ngx_python_socket_file_t *f);
static PyObject *ngx_python_socket_file_close(ngx_python_socket_file_t *f);
static PyObject *ngx_python_socket_file_isatty(ngx_python_socket_file_t *f);
static PyObject *ngx_python_socket_file_self(ngx_python_socket_file_t *f);
static PyObject *ngx_python_socket_file_exit(ngx_python_socket_file_t *f,
    PyObject *args);
static void ngx_python_socket_file_dealloc(ngx_python_socket_file_t *f);
static PyObject *ngx_python_socket_file_repr(ngx_python_socket_file_t *f);
static PyObject *ngx_python_socket_file_iternext(ngx_python_socket_file_t *f);


static PyMethodDef ngx_python_socket_methods[] = {

    { "accept",
      (PyCFunction) ngx_python_socket_unsupported,
      METH_NOARGS,
      "socket accept" },

    { "bind",
      (PyCFunction) ngx_python_socket_bind,
      METH_O,
      "socket bind" },

    { "close",
      (PyCFunction) ngx_python_socket_close,
      METH_NOARGS,
      "socket close" },

    { "connect",
      (PyCFunction) ngx_python_socket_connect,
      METH_O,
      "socket connect" },

    { "connect_ex",
      (PyCFunction) ngx_python_socket_connect_ex,
      METH_O,
      "socket connect_ex" },

    { "fileno",
      (PyCFunction) ngx_python_socket_fileno,
      METH_NOARGS,
      "socket file descriptor" },

    { "getpeername",
      (PyCFunction) ngx_python_socket_getpeername,
      METH_NOARGS,
      "get socket remote address" },

    { "getsockname",
      (PyCFunction) ngx_python_socket_getsockname,
      METH_NOARGS,
      "get socket local address" },

    { "getsockopt",
      (PyCFunction) ngx_python_socket_getsockopt,
      METH_VARARGS,
      "get socket option" },

    { "listen",
      (PyCFunction) ngx_python_socket_unsupported,
      METH_O,
      "socket listen" },

    { "makefile",
      (PyCFunction) ngx_python_socket_makefile,
      METH_VARARGS,
      "socket file buffer" },

    { "recv",
      (PyCFunction) ngx_python_socket_recv,
      METH_VARARGS,
      "socket recv" },

    { "recv_into",
      (PyCFunction) ngx_python_socket_recv_into,
      METH_VARARGS | METH_KEYWORDS,
      "socket recv into existing buffer" },

    { "recvfrom",
      (PyCFunction) ngx_python_socket_recvfrom,
      METH_VARARGS,
      "socket recvfrom" },

    { "recvfrom_into",
      (PyCFunction) ngx_python_socket_recvfrom_into,
      METH_VARARGS | METH_KEYWORDS,
      "socket recvfrom into buffer" },

    { "send",
      (PyCFunction) ngx_python_socket_send,
      METH_VARARGS,
      "socket send" },

    { "sendall",
      (PyCFunction) ngx_python_socket_send,
      METH_VARARGS,
      "socket send all" },

    { "sendto",
      (PyCFunction) ngx_python_socket_send,
      METH_VARARGS,
      "socket sendto" },

    { "setblocking",
      (PyCFunction) ngx_python_socket_setblocking,
      METH_O,
      "socket toggle blocking mode" },

    { "settimeout",
      (PyCFunction) ngx_python_socket_settimeout,
      METH_O,
      "set socket timeout" },

    { "gettimeout",
      (PyCFunction) ngx_python_socket_gettimeout,
      METH_NOARGS,
      "get socket timeout" },

    { "setsockopt",
      (PyCFunction) ngx_python_socket_setsockopt,
      METH_VARARGS,
      "set socket option" },

    { "shutdown",
      (PyCFunction) ngx_python_socket_shutdown,
      METH_O,
      "socket shutdown" },

    { NULL, NULL, 0, NULL }
};


static PyMemberDef ngx_python_socket_members[] = {

    { "family",
      T_INT,
      offsetof(ngx_python_socket_t, family),
      READONLY,
      "socket family" },

    { "type",
      T_INT,
      offsetof(ngx_python_socket_t, type),
      READONLY,
      "socket type" },

    { "proto",
      T_INT,
      offsetof(ngx_python_socket_t, proto),
      READONLY,
      "socket protocol" },

    { "timeout",
      T_DOUBLE,
      offsetof(ngx_python_socket_t, timeout),
      READONLY,
      "socket timeout"},

    { 0, 0, 0, 0, NULL }
};


static PyTypeObject  ngx_python_socket_type = {
    .ob_refcnt = 1,
    .tp_name = "NginxSocket",
    .tp_basicsize = sizeof(ngx_python_socket_t),
    .tp_dealloc = (destructor) ngx_python_socket_dealloc,
    .tp_repr = (reprfunc) ngx_python_socket_repr,
    .tp_getattro = PyObject_GenericGetAttr,
    .tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
    .tp_doc = "nginx socket",
    .tp_weaklistoffset = offsetof(ngx_python_socket_t, weakreflist),
    .tp_methods = ngx_python_socket_methods,
    .tp_members = ngx_python_socket_members,
    .tp_init = ngx_python_socket_init,
    .tp_alloc = PyType_GenericAlloc,
    .tp_new = ngx_python_socket_new,
    .tp_free = PyObject_Del
};


static PyMethodDef ngx_python_socket_file_methods[] = {

    { "readline",
      (PyCFunction) ngx_python_socket_file_readline,
      METH_VARARGS,
      "socket file read line" },

    { "read",
      (PyCFunction) ngx_python_socket_file_read,
      METH_VARARGS,
      "socket file read" },

    { "write",
      (PyCFunction) ngx_python_socket_file_write,
      METH_VARARGS,
      "socket file write" },

    { "fileno",
      (PyCFunction) ngx_python_socket_file_fileno,
      METH_NOARGS,
      "socket file descriptor" },

    { "seek",
      (PyCFunction) ngx_python_socket_unsupported,
      METH_VARARGS,
      "socket file seek" },

    { "truncate",
      (PyCFunction) ngx_python_socket_unsupported,
      METH_VARARGS,
      "socket file truncate" },

    { "tell",
      (PyCFunction) ngx_python_socket_unsupported,
      METH_NOARGS,
      "socket file tell" },

    { "readlines",
      (PyCFunction) ngx_python_socket_file_readlines,
      METH_VARARGS,
      "socket file read lines" },

    { "xreadlines",
      (PyCFunction) ngx_python_socket_file_self,
      METH_NOARGS,
      "socket file read lines" },

    { "writelines",
      (PyCFunction) ngx_python_socket_file_writelines,
      METH_O,
      "socket file write lines" },

    { "flush",
      (PyCFunction) ngx_python_socket_file_flush,
      METH_NOARGS,
      "flush socket file" },

    { "close",
      (PyCFunction) ngx_python_socket_file_close,
      METH_NOARGS,
      "close socket file" },

    { "isatty",
      (PyCFunction) ngx_python_socket_file_isatty,
      METH_NOARGS,
      "check if socket is atty" },

    { "__enter__",
      (PyCFunction) ngx_python_socket_file_self,
      METH_NOARGS,
      "enter with block" },

    { "__exit__",
      (PyCFunction) ngx_python_socket_file_exit,
      METH_VARARGS,
      "exit with block" },

    { NULL, NULL, 0, NULL }
};


static PyTypeObject  ngx_python_socket_file_type = {
    .ob_refcnt = 1,
    .tp_name = "NginxSocketFileObject",
    .tp_basicsize = sizeof(ngx_python_socket_file_t),
    .tp_dealloc = (destructor) ngx_python_socket_file_dealloc,
    .tp_repr = (reprfunc) ngx_python_socket_file_repr,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "nginx socket file object",
    .tp_iter = (getiterfunc) ngx_python_socket_file_self,
    .tp_iternext = (iternextfunc) ngx_python_socket_file_iternext,
    .tp_weaklistoffset = offsetof(ngx_python_socket_file_t, weakreflist),
    .tp_methods = ngx_python_socket_file_methods
};


static PyMethodDef ngx_python_socket_functions[] = {

    { "fromfd",
      (PyCFunction) ngx_python_socket_unsupported_func,
      METH_VARARGS,
      "socket from file descriptor" },

    { "socketpair",
      (PyCFunction) ngx_python_socket_unsupported_func,
      METH_VARARGS,
      "create a socketpair" },

    { NULL, NULL, 0, NULL }
};


static PyObject  *ngx_python_socket_error;
static PyObject  *ngx_python_socket_timeout;


static PyObject *
ngx_python_socket_unsupported(PyObject *self)
{
    PyErr_SetString(PyExc_RuntimeError, "unsupported call");
    return NULL;
}


static PyObject *
ngx_python_socket_unsupported_func(PyObject *self, PyObject *args)
{
    PyErr_SetString(PyExc_RuntimeError, "unsupported call");
    return NULL;
}


static PyObject *
ngx_python_socket_bind(ngx_python_socket_t *s, PyObject *addr)
{
    socklen_t        socklen;
    ngx_addr_t      *local;
    ngx_sockaddr_t   sa;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.bind()");

    if (ngx_python_socket_getaddr(s, addr, &sa.sockaddr, &socklen) < 0) {
        return NULL;
    }

    local = ngx_palloc(s->pool, sizeof(ngx_addr_t));
    if (local == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "allocation failed");
        return NULL;
    }

    local->sockaddr = ngx_palloc(s->pool, socklen);
    if (local->sockaddr == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "allocation failed");
        return NULL;
    }

    ngx_memcpy(local->sockaddr, &sa.sockaddr, socklen);
    local->socklen = socklen;

    local->name.data = ngx_pnalloc(s->pool, NGX_SOCKADDR_STRLEN);
    if (local->name.data == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "allocation failed");
        return NULL;
    }

    local->name.len = ngx_sock_ntop(&sa.sockaddr, socklen, local->name.data,
                                    NGX_SOCKADDR_STRLEN, 1);

    s->local = local;

    Py_RETURN_NONE;
}


static PyObject *
ngx_python_socket_close(ngx_python_socket_t *s)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.close()");

    /*
     * Keep connection alive.
     * Socket can still be referenced by a makefile()'d file object.
     */

    Py_RETURN_NONE;
}


static PyObject *
ngx_python_socket_connect(ngx_python_socket_t *s, PyObject *addr)
{
    long       err;
    PyObject  *ret;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.connect()");

    ret = ngx_python_socket_connect_ex(s, addr);
    if (ret == NULL) {
        return NULL;
    }

    err = PyLong_AsLong(ret);

    Py_DECREF(ret);

    if (err == -1) {
        return NULL;
    }

    if (err) {
        ngx_set_errno(err);
        PyErr_SetFromErrno(ngx_python_socket_error);
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject *
ngx_python_socket_connect_ex(ngx_python_socket_t *s, PyObject *addr)
{
    u_char                  buffer[NGX_SOCKADDR_STRLEN];
    socklen_t               socklen, len;
    ngx_err_t               err;
    ngx_str_t               name;
    ngx_int_t               rc;
    ngx_event_t            *rev, *wev;
    ngx_sockaddr_t          sa;
    ngx_connection_t       *c;
    ngx_peer_connection_t   peer;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.connect_ex()");

    if (ngx_python_socket_getaddr(s, addr, &sa.sockaddr, &socklen) < 0) {
        return NULL;
    }

    if (s->connection) {
        PyErr_SetString(ngx_python_socket_error, "socket already connected");
        return NULL;
    }

    name.data = buffer;
    name.len = ngx_sock_ntop(&sa.sockaddr, socklen, buffer, NGX_SOCKADDR_STRLEN,
                             1);

    ngx_memzero(&peer, sizeof(ngx_peer_connection_t));

    peer.sockaddr = &sa.sockaddr;
    peer.socklen = socklen;
    peer.local = s->local;
    peer.name = &name;
    peer.get = ngx_event_get_peer;
    peer.log = ngx_cycle->log;
    peer.log_error = NGX_ERROR_ERR;
    peer.type = s->type;

    rc = ngx_event_connect_peer(&peer);

    c = peer.connection;

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        if (c) {
            ngx_close_connection(c);
        }

        return PyLong_FromLong(NGX_ECONNREFUSED);
    }

    s->connection = c;
    c->pool = s->pool;

    rev = c->read;
    wev = c->write;

    rev->handler = ngx_python_socket_handler;
    wev->handler = ngx_python_socket_handler;

    if (rc == NGX_AGAIN) {
        c->data = ngx_python_get_ctx();

        ngx_add_timer(rev, s->timeout * 1000);

        do {
            if (ngx_python_yield() != NGX_OK) {
                err = 0;
                goto failed;
            }

            if (rev->timedout) {
                err = NGX_ETIMEDOUT;
                goto failed;
            }

        } while (!rev->ready && !wev->ready);

#if (NGX_HAVE_KQUEUE)

        if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
            if (c->write->pending_eof || c->read->pending_eof) {
                if (c->write->pending_eof) {
                    err = c->write->kq_errno;

                } else {
                    err = c->read->kq_errno;
                }

                goto failed;
            }

        } else
#endif
        {
            err = 0;
            len = sizeof(int);

            /*
             * BSDs and Linux return 0 and set a pending error in err
             * Solaris returns -1 and sets errno
             */

            if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
                           == -1)
            {
                err = ngx_socket_errno;
            }

            if (err) {
                goto failed;
            }
        }

        ngx_del_timer(rev);
    }

    c->data = NULL;

    return PyLong_FromLong(0);

failed:

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    ngx_close_connection(s->connection);
    s->connection = NULL;

    if (err == 0) {
        return NULL;
    }

    return PyLong_FromLong(err);
}


static void
ngx_python_socket_handler(ngx_event_t *event)
{
    ngx_connection_t  *c;
    ngx_python_ctx_t  *ctx;

    c = event->data;
    ctx = c->data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "python socket event handler c:%p w:%d", c, event->write);

    if (ctx) {
        ngx_python_wakeup(ctx);
    }
}


static PyObject *
ngx_python_socket_fileno(ngx_python_socket_t *s)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.fileno()");

    return PyInt_FromLong(s->connection ? s->connection->fd : -1);
}


static PyObject *
ngx_python_socket_getpeername(ngx_python_socket_t *s)
{
    socklen_t          socklen;
    ngx_sockaddr_t     sa;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.getpeername()");

    c = s->connection;

    if (c == NULL) {
        PyErr_SetString(ngx_python_socket_error, "socket not connected");
        return NULL;
    }

    socklen = sizeof(ngx_sockaddr_t);

    if (getpeername(c->fd, &sa.sockaddr, &socklen) == -1) {
        PyErr_SetFromErrno(ngx_python_socket_error);
        return NULL;
    }

    return ngx_python_socket_fmtaddr(&sa.sockaddr);
}


static PyObject *
ngx_python_socket_getsockname(ngx_python_socket_t *s)
{
    socklen_t          socklen;
    ngx_sockaddr_t     sa;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.getsockname()");

    c = s->connection;

    if (c == NULL) {
        PyErr_SetString(ngx_python_socket_error, "socket not connected");
        return NULL;
    }

    socklen = sizeof(ngx_sockaddr_t);

    if (getsockname(c->fd, &sa.sockaddr, &socklen) == -1) {
        PyErr_SetFromErrno(ngx_python_socket_error);
        return NULL;
    }

    return ngx_python_socket_fmtaddr(&sa.sockaddr);
}


static PyObject *
ngx_python_socket_fmtaddr(struct sockaddr *sockaddr)
{
    u_char                buffer[NGX_SOCKADDR_STRLEN];
    size_t                len;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_UNIX_DOMAIN)
    struct sockaddr_un   *saun;
#endif
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (sockaddr->sa_family) {

#if (NGX_HAVE_UNIX_DOMAIN)

    case AF_UNIX:

        saun = (struct sockaddr_un *) sockaddr;

        return PyString_FromString(saun->sun_path);

#endif

#if (NGX_HAVE_INET6)

    case AF_INET6:

        sin6 = (struct sockaddr_in6 *) sockaddr;

        len = ngx_inet6_ntop((u_char *) &sin6->sin6_addr, buffer,
                             sizeof(buffer));

        return Py_BuildValue("(s#iii)", buffer, (int) len,
                             (int) ntohs(sin6->sin6_port), 0, 0);

#endif

    default: /* AF_INET */

        sin = (struct sockaddr_in *) sockaddr;

        len = ngx_inet_ntop(AF_INET, &sin->sin_addr.s_addr, buffer,
                            sizeof(buffer));

        return Py_BuildValue("(s#i)", buffer, (int) len,
                             (int) ntohs(sin->sin_port));
    }
}


static PyObject *
ngx_python_socket_getsockopt(ngx_python_socket_t *s, PyObject *args)
{
    int                level, optname, len, value;
    PyObject          *str;
    socklen_t          slen;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.getsockopt()");

    c = s->connection;

    if (c == NULL) {
        PyErr_SetString(ngx_python_socket_error, "socket not connected");
        return NULL;
    }

    len = 0;

    if (!PyArg_ParseTuple(args, "ii|i:getsockopt", &level, &optname, &len)) {
        return NULL;
    }

    if (len == 0) {
        slen = sizeof(int);

        if (getsockopt(c->fd, level, optname, &value, &slen)) {
            PyErr_SetFromErrno(ngx_python_socket_error);
            return NULL;
        }

        return PyInt_FromLong(value);
    }

    str = PyString_FromStringAndSize(NULL, len);
    if (str == NULL) {
        return NULL;
    }

    slen = len;

    if (getsockopt(c->fd, level, optname, PyString_AS_STRING(str), &slen)) {
        Py_DECREF(str);
        PyErr_SetFromErrno(ngx_python_socket_error);
        return NULL;
    }

    if (_PyString_Resize(&str, slen) < 0) {
        return NULL;
    }

    return str;
}


static PyObject *
ngx_python_socket_makefile(ngx_python_socket_t *s, PyObject *args)
{
    int                        bufsize;
    char                      *mode;
    u_char                    *p;
    ngx_python_socket_file_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.makefile()");

    bufsize = NGX_PYTHON_SOCKET_DEFAULT_BUFSIZE;

    if (!PyArg_ParseTuple(args, "|si:makefile", &mode, &bufsize)) {
        return NULL;
    }

    if (bufsize == 0) {
        bufsize = NGX_PYTHON_SOCKET_DEFAULT_BUFSIZE;
    }

    p = ngx_pnalloc(s->pool, bufsize);
    if (p == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "could not create buffer");
        return NULL;
    }

    f = PyObject_New(ngx_python_socket_file_t, &ngx_python_socket_file_type);
    if (f == NULL) {
        return NULL;
    }

    ngx_memzero(&f->buffer, sizeof(ngx_buf_t));

    f->buffer.start = p;
    f->buffer.pos = p;
    f->buffer.last = p;
    f->buffer.end = p + bufsize;

    f->socket = s;
    f->weakreflist = NULL;

    Py_INCREF(s);

    return (PyObject *) f;
}


static PyObject *
ngx_python_socket_recv(ngx_python_socket_t *s, PyObject *args)
{
    int        len;
    u_char    *p;
    ssize_t    n;
    PyObject  *ret;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.recv()");

    if (!PyArg_ParseTuple(args, "i:recv", &len)) {
        return NULL;
    }

    if (len < 0) {
        PyErr_SetString(PyExc_ValueError, "negative buffer size");
        return NULL;
    }

    ret = PyString_FromStringAndSize(NULL, len);
    if (ret == NULL) {
        return NULL;
    }

    p = (u_char *) PyString_AS_STRING(ret);

    n = ngx_python_socket_do_recv(s, p, len);
    if (n < 0) {
        Py_DECREF(ret);
        return NULL;
    }

    if (n != len) {
        if (_PyString_Resize(&ret, n) < 0) {
            return NULL;
        }
    }

    return ret;
}


static PyObject *
ngx_python_socket_recv_into(ngx_python_socket_t *s, PyObject *args,
    PyObject *kwds)
{
    int        len, flags;
    ssize_t    n;
    Py_buffer  buf;

    static char *kwlist[] = { "buffer", "nbytes", "flags", 0 };

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.recv_into()");

    len = 0;
    flags = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "w*|ii:recv_into", kwlist,
                                     &buf, &len, &flags))
    {
        return NULL;
    }

    if (len < 0) {
        PyErr_SetString(PyExc_ValueError, "negative buffer size");
        PyBuffer_Release(&buf);
        return NULL;
    }

    if (len == 0) {
        len = buf.len;
    }

    if (buf.len < len) {
        PyErr_SetString(PyExc_ValueError, "buffer is too small");
        PyBuffer_Release(&buf);
        return NULL;
    }

    n = ngx_python_socket_do_recv(s, buf.buf, len);

    PyBuffer_Release(&buf);

    if (n < 0) {
        return NULL;
    }

    return PyInt_FromSsize_t(n);
}


static ssize_t
ngx_python_socket_do_recv(ngx_python_socket_t *s, u_char *p,
    size_t len)
{
    ssize_t            n;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.do_recv()");

    c = s->connection;

    if (c == NULL) {
        PyErr_SetString(ngx_python_socket_error, "socket not connected");
        return -1;
    }

    rev = c->read;

    if (rev->eof) {
        return 0;
    }

    if (!s->wrapper) {
        c->data = ngx_python_get_ctx();
    }

    for ( ;; ) {
        if (!rev->ready) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                n = -1;
                break;
            }

            ngx_add_timer(rev, s->timeout * 1000);

            if (ngx_python_yield() != NGX_OK) {
                ngx_del_timer(rev);
                n = -1;
                break;
            }

            if (rev->timedout) {
                PyErr_SetString(ngx_python_socket_timeout, "timed out");
                n = -1;
                break;
            }
        }

        n = c->recv(c, p, len);

        if (n >= 0) {
            break;
        }

        if (n == NGX_ERROR) {
            PyErr_SetString(ngx_python_socket_error, "recv error");
            n = -1;
            break;
        }

        /* n == NGX_AGAIN */
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    if (!s->wrapper) {
        c->data = NULL;
    }

    return n;
}


static PyObject *
ngx_python_socket_recvfrom(ngx_python_socket_t *s, PyObject *args)
{
    PyObject  *ret, *addr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.recvfrom()");

    /* no support for unconnected sockets */

    ret = ngx_python_socket_recv(s, args);
    if (ret == NULL) {
        return NULL;
    }

    addr = ngx_python_socket_getpeername(s);
    if (addr == NULL) {
        Py_DECREF(ret);
        return NULL;
    }

    return Py_BuildValue("(OO)", ret, addr);
}


static PyObject *
ngx_python_socket_recvfrom_into(ngx_python_socket_t *s, PyObject *args,
    PyObject *kwds)
{
    PyObject  *ret, *addr;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.recvfrom_into()");

    /* no support for unconnected sockets */

    ret = ngx_python_socket_recv_into(s, args, kwds);
    if (ret == NULL) {
        return NULL;
    }

    addr = ngx_python_socket_getpeername(s);
    if (addr == NULL) {
        Py_DECREF(ret);
        return NULL;
    }

    return Py_BuildValue("(OO)", ret, addr);
}


static PyObject *
ngx_python_socket_send(ngx_python_socket_t *s, PyObject *args)
{
    u_char            *p;
    size_t             len;
    ssize_t            n;
    Py_buffer          buf;
    ngx_event_t       *wev;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.send()");

    if (!PyArg_ParseTuple(args, "s*:send", &buf)) {
        return NULL;
    }

    c = s->connection;

    if (c == NULL) {
        PyBuffer_Release(&buf);
        PyErr_SetString(ngx_python_socket_error, "socket not connected");
        return NULL;
    }

    wev = c->write;

    if (!s->wrapper) {
        c->data = ngx_python_get_ctx();
    }

    p = buf.buf;
    len = buf.len;
    n = 0;

    while (len) {
        if (!wev->ready) {
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                n = -1;
                break;
            }

            ngx_add_timer(wev, s->timeout * 1000);

            if (ngx_python_yield() != NGX_OK) {
                ngx_del_timer(wev);
                n = -1;
                break;
            }

            if (wev->timedout) {
                PyErr_SetString(ngx_python_socket_timeout, "timed out");
                n = -1;
                break;
            }
        }

        n = c->send(c, p, len);

        if (n == NGX_ERROR) {
            PyErr_SetString(ngx_python_socket_error, "recv error");
            n = -1;
            break;
        }

        if (n > 0) {
            p += n;
            len -= n;
        }
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (!s->wrapper) {
        c->data = NULL;
    }

    PyBuffer_Release(&buf);

    if (n == -1) {
        return NULL;
    }

    return PyInt_FromLong(buf.len);
}


static PyObject *
ngx_python_socket_setblocking(ngx_python_socket_t *s, PyObject *arg)
{
    long  blocking;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.setblocking()");

    blocking = PyInt_AsLong(arg);
    if (blocking == -1 && PyErr_Occurred()) {
        return NULL;
    }

    if (!blocking) {
        PyErr_SetString(ngx_python_socket_error,
                        "could not set socket to non-blocking mode");
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject *
ngx_python_socket_settimeout(ngx_python_socket_t *s, PyObject *arg)
{
    double  timeout;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.settimeout()");

    timeout = NGX_PYTHON_SOCKET_DEFAULT_TIMEOUT;

    if (arg != Py_None) {
        timeout = PyFloat_AsDouble(arg);

        if (timeout < 0.0) {
            if (!PyErr_Occurred()) {
                PyErr_SetString(PyExc_ValueError, "negatvie timeout");
            }

            return NULL;
        }
    }

    s->timeout = timeout;

    Py_RETURN_NONE;
}


static PyObject *
ngx_python_socket_gettimeout(ngx_python_socket_t *s)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.gettimeout()");

    return PyFloat_FromDouble(s->timeout);
}


static PyObject *
ngx_python_socket_setsockopt(ngx_python_socket_t *s, PyObject *args)
{
    int                level, optname, len, value;
    char              *buffer;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.setsockopt()");

    c = s->connection;

    if (c == NULL) {
        PyErr_SetString(ngx_python_socket_error, "socket not connected");
        return NULL;
    }

    if (PyArg_ParseTuple(args, "iii:setsockopt", &level, &optname, &value)) {
        buffer = (char *) &value;
        len = sizeof(int);

    } else {
        PyErr_Clear();

        if (!PyArg_ParseTuple(args, "iis#:setsockopt", &level, &optname,
                              &buffer, &len))
        {
            return NULL;
        }
    }

    if (setsockopt(c->fd, level, optname, buffer, len)) {
        PyErr_SetFromErrno(ngx_python_socket_error);
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject *
ngx_python_socket_shutdown(ngx_python_socket_t *s, PyObject *arg)
{
    int  how;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.shutdown()");

    how = PyInt_AsLong(arg);
    if (how == -1 && PyErr_Occurred()) {
        return NULL;
    }

    if (s->connection) {
        if (shutdown(s->connection->fd, how)) {
            PyErr_SetFromErrno(ngx_python_socket_error);
            return NULL;
        }
    }

    Py_RETURN_NONE;
}


static int
ngx_python_socket_getaddr(ngx_python_socket_t *s, PyObject *args,
    struct sockaddr *sockaddr, socklen_t *socklen)
{
    int                   port;
    char                 *host;
    in_addr_t             inaddr;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_UNIX_DOMAIN)
    u_char               *p;
    Py_ssize_t            len;
    struct sockaddr_un   *saun;
#endif
#if (NGX_HAVE_INET6)
    unsigned int          fi, sid;
    struct in6_addr       inaddr6;
    struct sockaddr_in6  *sin6;
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.getaddr()");

    switch (s->family) {

#if (NGX_HAVE_UNIX_DOMAIN)

    case AF_UNIX:

        if (!PyString_Check(args)) {
            PyErr_Format(PyExc_TypeError, "UNIX address must be a string");
            return -1;
        }

        if (PyString_AsStringAndSize(args, &host, &len) < 0) {
            return -1;
        }

        if (len > (Py_ssize_t) NGX_UNIX_ADDRSTRLEN - 1) {
            PyErr_SetString(PyExc_ValueError, "bad UNIX address");
            return -1;
        }

        saun = (struct sockaddr_un *) sockaddr;
        saun->sun_family = AF_UNIX;

        p = ngx_cpymem(saun->sun_path, host, len);
        *p = '\0';

        *socklen = sizeof(struct sockaddr_un);

        break;

#endif

#if (NGX_HAVE_INET6)

    case AF_INET6:

        if (!PyTuple_Check(args)) {
            PyErr_Format(PyExc_TypeError, "IPv6 address must be a tuple");
            return -1;
        }

        if (!PyArg_ParseTuple(args, "eti|II", "idna", &host, &port, &fi, &sid))
        {
            return -1;
        }

        /* TODO resolver */

        if (ngx_inet6_addr((u_char *) host, ngx_strlen(host), inaddr6.s6_addr)
            != NGX_OK)
        {
            PyMem_Free(host);
            PyErr_SetString(PyExc_ValueError, "bad IPv6 address");
            return -1;
        }

        PyMem_Free(host);

        if (port < 0 || port > 65535) {
            PyErr_SetString(PyExc_OverflowError, "port out of range 0-65535");
            return -1;
        }

        sin6 = (struct sockaddr_in6 *) sockaddr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = inaddr6;
        sin6->sin6_port = htons((in_port_t) port);

        *socklen = sizeof(struct sockaddr_in6);

        break;

#endif

    default: /* AF_INET */

        if (!PyTuple_Check(args)) {
            PyErr_Format(PyExc_TypeError, "IP address must be tuple");
            return -1;
        }

        if (!PyArg_ParseTuple(args, "eti:getaddr", "idna", &host, &port)) {
            return -1;
        }

        /* TODO resolver */

        inaddr = ngx_inet_addr((u_char *) host, ngx_strlen(host));
        if (inaddr == INADDR_NONE) {
            PyMem_Free(host);
            PyErr_SetString(PyExc_ValueError, "bad IP address");
            return -1;
        }

        PyMem_Free(host);

        if (port < 0 || port > 65535) {
            PyErr_SetString(PyExc_OverflowError, "port out of range 0-65535");
            return -1;
        }

        sin = (struct sockaddr_in *) sockaddr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = inaddr;
        sin->sin_port = htons((in_port_t) port);

        *socklen = sizeof(struct sockaddr_in);

        break;
    }

    return 0;
}


static void
ngx_python_socket_dealloc(ngx_python_socket_t *s)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.dealloc()");

    if (!s->wrapper) {
        if (s->connection) {
            ngx_close_connection(s->connection);
        }

        ngx_destroy_pool(s->pool);
    }

    if (s->weakreflist) {
        PyObject_ClearWeakRefs((PyObject *) s);
    }

    Py_TYPE(s)->tp_free((PyObject *) s);
}


static PyObject *
ngx_python_socket_repr(ngx_python_socket_t *s)
{
    char  buffer[47 + NGX_INT64_LEN * 4];

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.repr()");

    ngx_sprintf((u_char *) buffer,
                 "<nginx socket, fd=%d, family=%d, type=%d, protocol=%d>%Z",
                 s->connection ? (int) s->connection->fd : -1,
                 s->family, s->type, s->proto);

    return PyString_FromString(buffer);
}


PyObject *
ngx_python_socket_create_wrapper(ngx_connection_t *c)
{
    ngx_python_socket_t  *s;

    s = PyObject_New(ngx_python_socket_t, &ngx_python_socket_type);
    if (s == NULL) {
        return NULL;
    }

    s->family = c->sockaddr->sa_family;
    s->type = c->type;
    s->proto = 0;
    s->timeout = NGX_PYTHON_SOCKET_DEFAULT_TIMEOUT;
    s->pool = c->pool;
    s->connection = c;
    s->local = NULL;
    s->weakreflist = NULL;
    s->wrapper = 1;

    return (PyObject *) s;
}


static PyObject *
ngx_python_socket_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyObject             *obj;
    ngx_python_socket_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket.new()");

    obj = type->tp_alloc(type, 0);
    if (obj == NULL) {
        return NULL;
    }

    s = (ngx_python_socket_t *) obj;

    s->pool = ngx_create_pool(1024, ngx_cycle->log);
    if (s->pool == NULL) {
        Py_DECREF(obj);
        PyErr_SetString(PyExc_RuntimeError, "could not create pool");
        return NULL;
    }

    s->family = AF_INET;
    s->type = SOCK_STREAM;
    s->proto = 0;
    s->timeout = NGX_PYTHON_SOCKET_DEFAULT_TIMEOUT;
    s->connection = NULL;
    s->local = NULL;
    s->weakreflist = NULL;
    s->wrapper = 0;

    return obj;
}


static int
ngx_python_socket_init(PyObject *self, PyObject *args, PyObject *kwds)
{
    int                   family, type, proto;
    ngx_python_socket_t  *s;

    static char *keywords[] = { "family", "type", "proto", 0 };

    s = (ngx_python_socket_t *) self;

    family = AF_INET;
    type = SOCK_STREAM;
    proto = 0;

    if (PyArg_ParseTupleAndKeywords(args, kwds, "|iii:socket",
                                    keywords, &family, &type, &proto) < 0)
    {
        return -1;
    }

    if (family != AF_INET
#if (NGX_HAVE_INET6)
        && family != AF_INET6
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        && family != AF_UNIX
#endif
       )
    {
        PyErr_SetString(PyExc_ValueError, "unsupported family");
        return -1;
    }

    s->family = family;
    s->type = type;
    s->proto = proto;
    s->timeout = ngx_python_socket_getdefaulttimeout(s);

    return 0;
}


static double
ngx_python_socket_getdefaulttimeout(ngx_python_socket_t *s)
{
    double     timeout;
    PyObject  *tm, *func, *ret;

    timeout = NGX_PYTHON_SOCKET_DEFAULT_TIMEOUT;
    func = NULL;
    ret = NULL;

    tm = PyImport_ImportModule("socket");
    if (tm == NULL) {
        goto done;
    }

    func = PyObject_GetAttrString(tm, "getdefaulttimeout");
    if (func == NULL || !PyCallable_Check(func)) {
        goto done;
    }

    ret = PyObject_CallFunctionObjArgs(func, NULL);
    if (ret == NULL || !PyFloat_Check(ret)) {
        goto done;
    }

    timeout = PyFloat_AS_DOUBLE(ret);

done:

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socket default timeout:%f", timeout);

    Py_XDECREF(ret);
    Py_XDECREF(func);
    Py_XDECREF(tm);

    return timeout;
}


static PyObject *
ngx_python_socket_file_readline(ngx_python_socket_file_t *f, PyObject *args)
{
    int  n;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.readline()");

    n = -1;

    if (!PyArg_ParseTuple(args, "|i:readline", &n)) {
        return NULL;
    }

    return ngx_python_socket_file_get(f, 1, n);
}


static PyObject *
ngx_python_socket_file_read(ngx_python_socket_file_t *f, PyObject *args)
{
    int  n;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.read()");

    n = -1;

    if (!PyArg_ParseTuple(args, "|i:read", &n)) {
        return NULL;
    }

    return ngx_python_socket_file_get(f, 0, n);
}


static PyObject *
ngx_python_socket_file_get(ngx_python_socket_file_t *f, ngx_uint_t line,
    int max)
{
    u_char      *p, *last, *dst;
    ssize_t      n;
    PyObject    *ret;
    ngx_buf_t   *b;
    ngx_uint_t   done;
    Py_ssize_t   size;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.get()");

    size = max <= 0 ? 128 : max;

    ret = PyString_FromStringAndSize(NULL, size);
    if (ret == NULL) {
        return NULL;
    }

    dst = (u_char *) PyString_AS_STRING(ret);

    b = &f->buffer;

    done = 0;

    while (size) {
        if (b->pos < b->last) {
            last = b->last;

            if (last > b->pos + size) {
                last = b->pos + size;
            }

            n = last - b->pos;

            if (line) {
                p = ngx_strlchr(b->pos, last, LF);

                if (p) {
                    n = p - b->pos + 1;
                    done = 1;
                }
            }

            dst = ngx_cpymem(dst, b->pos, n);

            b->pos += n;
            size -= n;

            if (done) {
                break;
            }

            if (size == 0) {
                if (max > 0) {
                    break;
                }

                n = PyString_Size(ret);

                if (_PyString_Resize(&ret, n * 2) < 0) {
                    Py_DECREF(ret);
                    return NULL;
                }

                dst = (u_char *) PyString_AS_STRING(ret);
                dst += n;
                size = n;
            }
        }

        if (b->pos == b->last) {
            b->pos = b->start;
            b->last = b->start;

            n = ngx_python_socket_do_recv(f->socket, b->last, b->end - b->last);
            if (n < 0) {
                Py_DECREF(ret);
                return NULL;
            }

            if (n == 0) {
                break;
            }

            b->last += n;
        }
    }

    if (size) {
        if (_PyString_Resize(&ret, PyString_Size(ret) - size) < 0) {
            Py_DECREF(ret);
            return NULL;
        }
    }

    return ret;
}


static PyObject *
ngx_python_socket_file_write(ngx_python_socket_file_t *f, PyObject *args)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.write()");

    return ngx_python_socket_send(f->socket, args);
}


static PyObject *
ngx_python_socket_file_fileno(ngx_python_socket_file_t *f)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.fileno()");

    return ngx_python_socket_fileno(f->socket);
}


static PyObject *
ngx_python_socket_file_readlines(ngx_python_socket_file_t *f)
{
    PyObject          *ret, *line;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.readlines()");

    ret = PyList_New(0);
    if (ret == NULL) {
        return NULL;
    }

    c = f->socket->connection;
    if (c == NULL) {
        PyErr_SetString(ngx_python_socket_error, "socket not connected");
        return NULL;
    }

    while (!c->read->eof) {
        line = ngx_python_socket_file_get(f, 1, -1);
        if (line == NULL) {
            Py_DECREF(ret);
            return NULL;
        }

        if (PyList_Append(ret, line) < 0) {
            Py_DECREF(line);
            Py_DECREF(ret);
            return NULL;
        }
    }

    return ret;
}


static PyObject *
ngx_python_socket_file_writelines(ngx_python_socket_file_t *f, PyObject *sq)
{
    PyObject  *it, *line, *tl;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.writelines()");

    it = PyObject_GetIter(sq);
    if (it == NULL) {
        return NULL;
    }

    for ( ;; ) {
        line = PyIter_Next(it);
        if (line == NULL) {
            if (PyErr_Occurred()) {
                break;
            }

            Py_DECREF(it);
            Py_RETURN_NONE;
        }

        tl = Py_BuildValue("(O)", line);
        if (tl == NULL) {
            Py_DECREF(line);
            break;
        }

        Py_DECREF(line);

        if (ngx_python_socket_send(f->socket, tl) == NULL) {
            Py_DECREF(tl);
            break;
        }

        Py_DECREF(tl);
    }

    Py_DECREF(it);
    return NULL;
}


static PyObject *
ngx_python_socket_file_flush(ngx_python_socket_file_t *f)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.flush()");

    Py_RETURN_NONE;
}


static PyObject *
ngx_python_socket_file_close(ngx_python_socket_file_t *f)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.close()");

    Py_RETURN_NONE;
}


static PyObject *
ngx_python_socket_file_isatty(ngx_python_socket_file_t *f)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.isatty()");

    return PyBool_FromLong(0);
}


static PyObject *
ngx_python_socket_file_self(ngx_python_socket_file_t *f)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.self()");

    Py_INCREF(f);
    return (PyObject *) f;
}


static PyObject *
ngx_python_socket_file_exit(ngx_python_socket_file_t *f, PyObject *args)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.__exit__()");

    Py_RETURN_NONE;
}


static void
ngx_python_socket_file_dealloc(ngx_python_socket_file_t *f)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.dealloc()");

    Py_DECREF(f->socket);

    if (f->weakreflist) {
        PyObject_ClearWeakRefs((PyObject *) f);
    }

    Py_TYPE(f)->tp_free((PyObject *) f);
}


static PyObject *
ngx_python_socket_file_repr(ngx_python_socket_file_t *f)
{
    return ngx_python_socket_repr(f->socket);
}


static PyObject *
ngx_python_socket_file_iternext(ngx_python_socket_file_t *f)
{
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python socketfile.iternext()");

    c = f->socket->connection;
    if (c == NULL) {
        PyErr_SetString(ngx_python_socket_error, "socket not connected");
        return NULL;
    }

    if (c->read->eof) {
        return NULL;
    }

    return ngx_python_socket_file_get(f, 1, -1);
}


ngx_int_t
ngx_python_socket_install(ngx_conf_t *cf)
{
    PyObject     *sm, *fun;
    PyMethodDef  *fn;

    if (PyType_Ready(&ngx_python_socket_type) < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "could not add %s type",
                           ngx_python_socket_type.tp_name);
        return NGX_ERROR;
    }

    if (PyType_Ready(&ngx_python_socket_file_type) < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "could not add %s type",
                           ngx_python_socket_file_type.tp_name);
        return NGX_ERROR;
    }

    ngx_python_socket_error = PyErr_NewException("socket.error", PyExc_IOError,
                                                 NULL);
    if (ngx_python_socket_error == NULL) {
        return NGX_ERROR;
    }

    ngx_python_socket_timeout = PyErr_NewException("socket.timeout",
                                                   ngx_python_socket_error,
                                                   NULL);
    if (ngx_python_socket_timeout == NULL) {
        return NGX_ERROR;
    }

    sm = PyImport_ImportModule("socket");
    if (sm == NULL) {
        return NGX_ERROR;
    }

    if (PyObject_SetAttrString(sm, "socket",
                               (PyObject *) &ngx_python_socket_type) < 0)
    {
        Py_DECREF(sm);
        return NGX_ERROR;
    }

    if (PyObject_SetAttrString(sm, "error", ngx_python_socket_error) < 0) {
        Py_DECREF(sm);
        return NGX_ERROR;
    }

    if (PyObject_SetAttrString(sm, "timeout", ngx_python_socket_timeout) < 0) {
        Py_DECREF(sm);
        return NGX_ERROR;
    }

    for (fn = ngx_python_socket_functions; fn->ml_name; fn++) {

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
