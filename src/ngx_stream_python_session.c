
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_stream_python_session.h"


/*
 * Stream session:
 *
 *   buf
 *   sock
 *   var{}
 *   ctx{}
 *   log()
 */


typedef struct {
    PyObject_HEAD
    ngx_stream_session_t          *session;
    PyObject                      *ctx;
    PyObject                      *sock;
} ngx_stream_python_session_t;


typedef struct {
    PyObject_HEAD
    ngx_stream_python_session_t   *ps;
} ngx_stream_python_session_var_t;


static PyObject *ngx_stream_python_session_log(
    ngx_stream_python_session_t* self, PyObject* args);
static PyObject *ngx_stream_python_session_var(
    ngx_stream_python_session_t *self);
static PyObject *ngx_stream_python_session_ctx(
    ngx_stream_python_session_t *self);
static PyObject *ngx_stream_python_session_get_buf(
    ngx_stream_python_session_t *self);
static PyObject *ngx_stream_python_session_get_sock(
    ngx_stream_python_session_t *self);
static void ngx_stream_python_session_dealloc(
    ngx_stream_python_session_t *self);

static PyObject *ngx_stream_python_session_var_subscript(
    ngx_stream_python_session_var_t *self, PyObject *key);
static void ngx_stream_python_session_var_dealloc(
    ngx_stream_python_session_var_t *self);

static void ngx_stream_python_session_cleanup(void *data);


static PyMethodDef ngx_stream_python_session_methods[] = {

    { "log",
      (PyCFunction) ngx_stream_python_session_log,
      METH_VARARGS,
      "output a message to the error log" },

    { NULL, NULL, 0, NULL }
};


static PyGetSetDef ngx_stream_python_session_getset[] = {

    { "var",
      (getter) ngx_stream_python_session_var,
      NULL,
      "nginx per-session variables",
      NULL },

    { "ctx",
      (getter) ngx_stream_python_session_ctx,
      NULL,
      "nginx per-session context",
      NULL },

    { "buf",
      (getter) ngx_stream_python_session_get_buf,
      NULL,
      "stream buffer",
      NULL },

    { "sock",
      (getter) ngx_stream_python_session_get_sock,
      NULL,
      "stream socket",
      NULL },

    { NULL, NULL, NULL, NULL, NULL }
};


static PyTypeObject  ngx_stream_python_session_type = {
    .ob_refcnt = 1,
    .tp_name = "ngx.StreamSession",
    .tp_basicsize = sizeof(ngx_stream_python_session_t),
    .tp_dealloc = (destructor) ngx_stream_python_session_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Stream session",
    .tp_methods = ngx_stream_python_session_methods,
    .tp_getset = ngx_stream_python_session_getset
};


static PyMappingMethods ngx_stream_python_session_var_mapping = {
    NULL,                                          /*mp_length*/
    (binaryfunc) ngx_stream_python_session_var_subscript,
                                                   /*mp_subscript*/
    NULL,                                          /*mp_ass_subscript*/
};


static PyTypeObject  ngx_stream_python_session_var_type = {
    .ob_refcnt = 1,
    .tp_name = "ngx.StreamVariables",
    .tp_basicsize = sizeof(ngx_stream_python_session_var_t),
    .tp_dealloc = (destructor) ngx_stream_python_session_var_dealloc,
    .tp_as_mapping = &ngx_stream_python_session_var_mapping,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Stream variables"
};


static PyObject  *ngx_stream_python_session_error;


static PyObject *
ngx_stream_python_session_log(ngx_stream_python_session_t* self, PyObject* args)
{
    int                    level;
    const char            *msg;
    ngx_stream_session_t  *s;

    s = self->session;
    if (s == NULL) {
        PyErr_SetString(ngx_stream_python_session_error, "session finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python log()");

    level = NGX_LOG_INFO;

    if (!PyArg_ParseTuple(args, "s|i:log", &msg, &level)) {
        return NULL;
    }

    ngx_log_error((ngx_uint_t) level, s->connection->log, 0, msg);

    Py_RETURN_NONE;
}


static PyObject *
ngx_stream_python_session_var(ngx_stream_python_session_t *self)
{
    ngx_stream_session_t             *s;
    ngx_stream_python_session_var_t  *pv;

    s = self->session;
    if (s == NULL) {
        PyErr_SetString(ngx_stream_python_session_error, "session finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python var");

    pv = PyObject_New(ngx_stream_python_session_var_t,
                      &ngx_stream_python_session_var_type);
    if (pv == NULL) {
        return NULL;
    }

    pv->ps = self;

    Py_INCREF(self);

    return (PyObject *) pv;
}


static PyObject *
ngx_stream_python_session_ctx(ngx_stream_python_session_t *self)
{
    ngx_stream_session_t  *s;

    s = self->session;
    if (s == NULL) {
        PyErr_SetString(ngx_stream_python_session_error, "session finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python ctx");

    Py_INCREF(self->ctx);

    return self->ctx;
}


static PyObject *
ngx_stream_python_session_get_buf(ngx_stream_python_session_t *self)
{
    ngx_buf_t             *b;
    ngx_stream_session_t  *s;

    s = self->session;
    if (s == NULL) {
        PyErr_SetString(ngx_stream_python_session_error, "session finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python get buf");

    b = s->connection->buffer;
    if (b == NULL) {
        return PyString_FromStringAndSize(NULL, 0);
    }

    return PyString_FromStringAndSize((char *) b->pos, b->last - b->pos);
}


static PyObject *
ngx_stream_python_session_get_sock(ngx_stream_python_session_t *self)
{
    ngx_stream_session_t  *s;

    s = self->session;
    if (s == NULL) {
        PyErr_SetString(ngx_stream_python_session_error, "session finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python get sock");

    Py_INCREF(self->sock);

    return self->sock;
}


static void
ngx_stream_python_session_dealloc(ngx_stream_python_session_t *self)
{
    Py_XDECREF(self->ctx);
    Py_XDECREF(self->sock);

    self->ob_type->tp_free((PyObject*) self);
}


static PyObject *
ngx_stream_python_session_var_subscript(ngx_stream_python_session_var_t *self,
    PyObject *key)
{
    char                         *data;
    ngx_str_t                     name;
    ngx_uint_t                    hash;
    Py_ssize_t                    len;
    ngx_stream_session_t         *s;
    ngx_stream_variable_value_t  *vv;

    s = self->ps->session;
    if (s == NULL) {
        PyErr_SetString(ngx_stream_python_session_error, "session finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python var subscript()");

    if (PyString_AsStringAndSize(key, &data, &len) < 0 ) {
        return NULL;
    }

    name.data = (u_char *) data;
    name.len = len;

    hash = ngx_hash_strlow(name.data, name.data, name.len);

    vv = ngx_stream_get_variable(s, &name, hash);
    if (vv == NULL) {
        PyErr_SetNone(ngx_stream_python_session_error);
        return NULL;
    }

    if (vv->not_found) {
        return PyString_FromStringAndSize(NULL, 0);
    }

    return PyString_FromStringAndSize((char *) vv->data, vv->len);
}


static void
ngx_stream_python_session_var_dealloc(ngx_stream_python_session_var_t *self)
{
    Py_DECREF(self->ps);

    self->ob_type->tp_free((PyObject*) self);
}


ngx_int_t
ngx_stream_python_session_init(ngx_conf_t *cf)
{
    static ngx_int_t  initialized;

    if (initialized) {
        return NGX_OK;
    }

    initialized = 1;

    if (PyType_Ready(&ngx_stream_python_session_type) < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "could not add %s type",
                           ngx_stream_python_session_type.tp_name);
        return NGX_ERROR;
    }

    if (PyType_Ready(&ngx_stream_python_session_var_type) < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "could not add %s type",
                           ngx_stream_python_session_var_type.tp_name);
        return NGX_ERROR;
    }

    ngx_stream_python_session_error = PyErr_NewException(
                                                       "ngx.StreamSessionError",
                                                       PyExc_RuntimeError,
                                                       NULL);
    if (ngx_stream_python_session_error == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


PyObject *
ngx_stream_python_session_create(ngx_stream_session_t *s)
{
    ngx_pool_cleanup_t           *cln;
    ngx_stream_python_session_t  *ps;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python create session");

    ps = PyObject_New(ngx_stream_python_session_t,
                      &ngx_stream_python_session_type);
    if (ps == NULL) {
        return NULL;
    }

    ps->session = s;

    ps->ctx = PyDict_New();
    if (ps->ctx == NULL) {
        Py_DECREF(ps);
        return NULL;
    }

#if !(NGX_PYTHON_SYNC)
    ps->sock = ngx_python_socket_create_wrapper(s->connection);
    if (ps->sock == NULL) {
        Py_DECREF(ps);
        return NULL;
    }
#endif

    cln = ngx_pool_cleanup_add(s->connection->pool, 0);
    if (cln == NULL) {
        Py_DECREF(ps);
        PyErr_SetNone(ngx_stream_python_session_error);
        return NULL;
    }

    cln->handler = ngx_stream_python_session_cleanup;
    cln->data = ps;

    Py_INCREF(ps);

    return (PyObject *) ps;
}


static void
ngx_stream_python_session_cleanup(void *data)
{
    ngx_stream_python_session_t *ps = data;

    ps->session = NULL;

    Py_DECREF(ps);
}
