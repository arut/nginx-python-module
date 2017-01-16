
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_python_request.h"


/*
 * HTTP request:
 *
 *   hi{}
 *   ho{}
 *   var{}
 *   arg{}
 *   ctx{}
 *   status
 *   log()
 *   sendHeader()
 *   send()
 */


typedef struct {
    PyObject_HEAD
    ngx_http_request_t          *request;
    PyObject                    *ctx;
} ngx_http_python_request_t;


typedef struct {
    PyObject_HEAD
    ngx_http_python_request_t   *pr;
    ngx_uint_t                   out;  /* unsigned  out:1; */
} ngx_http_python_request_hdr_t;


typedef struct {
    PyObject_HEAD
    ngx_http_python_request_t   *pr;
} ngx_http_python_request_arg_t;


typedef struct {
    PyObject_HEAD
    ngx_http_python_request_t   *pr;
} ngx_http_python_request_var_t;


static PyObject *ngx_http_python_request_log(ngx_http_python_request_t* self,
    PyObject* args);
static PyObject *ngx_http_python_request_send_header(
    ngx_http_python_request_t* self);
static PyObject *ngx_http_python_request_send(ngx_http_python_request_t* self,
    PyObject* args);
static PyObject *ngx_http_python_request_hi(ngx_http_python_request_t *self);
static PyObject *ngx_http_python_request_ho(ngx_http_python_request_t *self);
static PyObject *ngx_http_python_request_arg(ngx_http_python_request_t *self);
static PyObject *ngx_http_python_request_var(ngx_http_python_request_t *self);
static PyObject *ngx_http_python_request_ctx(ngx_http_python_request_t *self);
static PyObject *ngx_http_python_request_get_status(
    ngx_http_python_request_t *self);
static int ngx_http_python_request_set_status(ngx_http_python_request_t *self,
    PyObject *value);
static void ngx_http_python_request_dealloc(ngx_http_python_request_t *self);

static PyObject *ngx_http_python_request_hdr_subscript(
    ngx_http_python_request_hdr_t *self, PyObject *key);
static int ngx_http_python_request_hdr_ass_subscript(
    ngx_http_python_request_hdr_t *self, PyObject *key, PyObject *value);
static ngx_table_elt_t *ngx_http_python_find_header(ngx_list_t *headers,
    u_char *data, size_t len);
static void ngx_http_python_request_hdr_dealloc(
    ngx_http_python_request_hdr_t *self);

static PyObject *ngx_http_python_request_arg_subscript(
    ngx_http_python_request_arg_t *self, PyObject *key);
static void ngx_http_python_request_arg_dealloc(
    ngx_http_python_request_arg_t *self);

static PyObject *ngx_http_python_request_var_subscript(
    ngx_http_python_request_var_t *self, PyObject *key);
static void ngx_http_python_request_var_dealloc(
    ngx_http_python_request_var_t *self);

static void ngx_http_python_request_cleanup(void *data);


static PyMethodDef ngx_http_python_request_methods[] = {

    { "log",
      (PyCFunction) ngx_http_python_request_log,
      METH_VARARGS,
      "output a message to the error log" },

    { "sendHeader",
      (PyCFunction) ngx_http_python_request_send_header,
      METH_NOARGS,
      "send output headers to the client" },

    { "send",
      (PyCFunction) ngx_http_python_request_send,
      METH_VARARGS,
      "send a piece of response body to the client" },

    { NULL, NULL, 0, NULL }
};


static PyGetSetDef ngx_http_python_request_getset[] = {

    { "hi",
      (getter) ngx_http_python_request_hi,
      NULL,
      "HTTP input headers",
      NULL },

    { "ho",
      (getter) ngx_http_python_request_ho,
      NULL,
      "HTTP output headers",
      NULL },

    { "arg",
      (getter) ngx_http_python_request_arg,
      NULL,
      "nginx per-request variables",
      NULL },

    { "var",
      (getter) ngx_http_python_request_var,
      NULL,
      "nginx per-request variables",
      NULL },

    { "ctx",
      (getter) ngx_http_python_request_ctx,
      NULL,
      "nginx per-request context",
      NULL },

    { "status",
      (getter) ngx_http_python_request_get_status,
      (setter) ngx_http_python_request_set_status,
      "HTTP response status",
      NULL },

    { NULL, NULL, NULL, NULL, NULL }
};


/* 
 * We use C99 designated initializers for PyTypeObject globals
 * since nginx enables -Wmissing-field-initializers option
 * and more fields of PyTypeObject are added in later versions.
 * However, this does not allow us to use the PyObject_HEAD_INIT
 * macro.
 */

static PyTypeObject  ngx_http_python_request_type = {
    .ob_refcnt = 1,
    .tp_name = "ngx.HttpRequest",
    .tp_basicsize = sizeof(ngx_http_python_request_t),
    .tp_dealloc = (destructor) ngx_http_python_request_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "HTTP request",
    .tp_methods = ngx_http_python_request_methods,
    .tp_getset = ngx_http_python_request_getset
};


#if 0
static PyTypeObject  ngx_http_python_request_type = {
    PyObject_HEAD_INIT(NULL)
    0,                                             /* ob_size */
    "ngx.HttpRequest",                             /* tp_name */
    sizeof(ngx_http_python_request_t),             /* tp_basicsize */
    0,                                             /* tp_itemsize */
    (destructor) ngx_http_python_request_dealloc,  /* tp_dealloc */
    0,                                             /* tp_print */
    0,                                             /* tp_getattr */
    0,                                             /* tp_setattr */
    0,                                             /* tp_compare */
    0,                                             /* tp_repr */
    0,                                             /* tp_as_number */
    0,                                             /* tp_as_sequence */
    0,                                             /* tp_as_mapping */
    0,                                             /* tp_hash */
    0,                                             /* tp_call */
    0,                                             /* tp_str */
    0,                                             /* tp_getattro */
    0,                                             /* tp_setattro */
    0,                                             /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                            /* tp_flags */
    "HTTP request",                                /* tp_doc */
    0,                                             /* tp_traverse */
    0,                                             /* tp_clear */
    0,                                             /* tp_richcompare */
    0,                                             /* tp_weaklistoffset */
    0,                                             /* tp_iter */
    0,                                             /* tp_iternext */
    ngx_http_python_request_methods,               /* tp_methods */
    NULL,                                          /* tp_members */
    ngx_http_python_request_getset,                /* tp_getset */
};
#endif


static PyMappingMethods ngx_http_python_request_hdr_mapping = {
    NULL,                                          /*mp_length*/
    (binaryfunc) ngx_http_python_request_hdr_subscript,
                                                   /*mp_subscript*/
    (objobjargproc) ngx_http_python_request_hdr_ass_subscript,
                                                   /*mp_ass_subscript*/
};


static PyTypeObject  ngx_http_python_request_hdr_type = {
    .ob_refcnt = 1,
    .tp_name = "ngx.HttpHeaders",
    .tp_basicsize = sizeof(ngx_http_python_request_hdr_t),
    .tp_dealloc = (destructor) ngx_http_python_request_hdr_dealloc,
    .tp_as_mapping = &ngx_http_python_request_hdr_mapping,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "HTTP headers"
};


#if 0
static PyTypeObject  ngx_http_python_request_hdr_type = {
    PyObject_HEAD_INIT(NULL)
    0,                                             /* ob_size */
    "ngx.HttpHeaders",                             /* tp_name */
    sizeof(ngx_http_python_request_hdr_t),         /* tp_basicsize */
    0,                                             /* tp_itemsize */
    (destructor) ngx_http_python_request_hdr_dealloc,
                                                   /* tp_dealloc */
    0,                                             /* tp_print */
    0,                                             /* tp_getattr */
    0,                                             /* tp_setattr */
    0,                                             /* tp_compare */
    0,                                             /* tp_repr */
    0,                                             /* tp_as_number */
    0,                                             /* tp_as_sequence */
    &ngx_http_python_request_hdr_mapping,          /* tp_as_mapping */
    0,                                             /* tp_hash */
    0,                                             /* tp_call */
    0,                                             /* tp_str */
    0,                                             /* tp_getattro */
    0,                                             /* tp_setattro */
    0,                                             /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                            /* tp_flags */
    "HTTP headers",                                /* tp_doc */
};
#endif


static PyMappingMethods ngx_http_python_request_arg_mapping = {
    NULL,                                          /*mp_length*/
    (binaryfunc) ngx_http_python_request_arg_subscript,
                                                   /*mp_subscript*/
    NULL,                                          /*mp_ass_subscript*/
};


static PyTypeObject  ngx_http_python_request_arg_type = {
    .ob_refcnt = 1,
    .tp_name = "ngx.HttpArguments",
    .tp_basicsize = sizeof(ngx_http_python_request_arg_t),
    .tp_dealloc = (destructor) ngx_http_python_request_arg_dealloc,
    .tp_as_mapping = &ngx_http_python_request_arg_mapping,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "HTTP arguments"
};


#if 0
static PyTypeObject  ngx_http_python_request_arg_type = {
    PyObject_HEAD_INIT(NULL)
    0,                                             /* ob_size */
    "ngx.HttpArguments",                           /* tp_name */
    sizeof(ngx_http_python_request_arg_t),         /* tp_basicsize */
    0,                                             /* tp_itemsize */
    (destructor) ngx_http_python_request_arg_dealloc,
                                                   /* tp_dealloc */
    0,                                             /* tp_print */
    0,                                             /* tp_getattr */
    0,                                             /* tp_setattr */
    0,                                             /* tp_compare */
    0,                                             /* tp_repr */
    0,                                             /* tp_as_number */
    0,                                             /* tp_as_sequence */
    &ngx_http_python_request_arg_mapping,          /* tp_as_mapping */
    0,                                             /* tp_hash */
    0,                                             /* tp_call */
    0,                                             /* tp_str */
    0,                                             /* tp_getattro */
    0,                                             /* tp_setattro */
    0,                                             /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                            /* tp_flags */
    "HTTP arguments",                              /* tp_doc */
};
#endif


static PyMappingMethods ngx_http_python_request_var_mapping = {
    NULL,                                          /*mp_length*/
    (binaryfunc) ngx_http_python_request_var_subscript,
                                                   /*mp_subscript*/
    NULL,                                          /*mp_ass_subscript*/
};


static PyTypeObject  ngx_http_python_request_var_type = {
    .ob_refcnt = 1,
    .tp_name = "ngx.HttpVariables",
    .tp_basicsize = sizeof(ngx_http_python_request_var_t),
    .tp_dealloc = (destructor) ngx_http_python_request_var_dealloc,
    .tp_as_mapping = &ngx_http_python_request_var_mapping,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "HTTP variables"
};


#if 0
static PyTypeObject  ngx_http_python_request_var_type = {
    PyObject_HEAD_INIT(NULL)
    0,                                             /* ob_size */
    "ngx.HttpVariables",                           /* tp_name */
    sizeof(ngx_http_python_request_var_t),         /* tp_basicsize */
    0,                                             /* tp_itemsize */
    (destructor) ngx_http_python_request_var_dealloc,
                                                   /* tp_dealloc */
    0,                                             /* tp_print */
    0,                                             /* tp_getattr */
    0,                                             /* tp_setattr */
    0,                                             /* tp_compare */
    0,                                             /* tp_repr */
    0,                                             /* tp_as_number */
    0,                                             /* tp_as_sequence */
    &ngx_http_python_request_var_mapping,          /* tp_as_mapping */
    0,                                             /* tp_hash */
    0,                                             /* tp_call */
    0,                                             /* tp_str */
    0,                                             /* tp_getattro */
    0,                                             /* tp_setattro */
    0,                                             /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                            /* tp_flags */
    "HTTP variables",                              /* tp_doc */
};
#endif


static PyObject  *ngx_http_python_request_error;


static PyObject *
ngx_http_python_request_log(ngx_http_python_request_t* self, PyObject* args)
{
    int                  level;
    const char          *msg;
    ngx_http_request_t  *r;

    r = self->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python log()");

    level = NGX_LOG_INFO;

    if (!PyArg_ParseTuple(args, "s|i:log", &msg, &level)) {
        return NULL;
    }

    ngx_log_error((ngx_uint_t) level, r->connection->log, 0, msg);

    Py_RETURN_NONE;
}


static PyObject *
ngx_http_python_request_send_header(ngx_http_python_request_t* self)
{
    ngx_http_request_t  *r;

    r = self->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python sendHeader()");

    if (ngx_http_send_header(r) == NGX_ERROR) {
        PyErr_SetNone(ngx_http_python_request_error);
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject *
ngx_http_python_request_send(ngx_http_python_request_t* self, PyObject* args)
{
    int                  len, flags;
    char                *data;
    ngx_buf_t           *b;
    ngx_chain_t          cl;
    ngx_http_request_t  *r;

    r = self->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python send()");

    flags = 0;
    len = 0;

    if (!PyArg_ParseTuple(args, "z#|i:send", &data, &len, &flags)) {
        return NULL;
    }

    if (len) {
        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            PyErr_SetNone(ngx_http_python_request_error);
            return NULL;
        }

        b->last = ngx_cpymem(b->last, data, len);

    } else {
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            PyErr_SetNone(ngx_http_python_request_error);
            return NULL;
        }

        b->sync = 1;
    }

    if (flags & 1) {
        b->last_in_chain = 1;
        b->last_buf = (r == r->main);
    }

    if (flags & 2) {
        b->flush = 1;
    }

    cl.buf = b;
    cl.next = NULL;

    if (ngx_http_output_filter(r, &cl) == NGX_ERROR) {
        PyErr_SetNone(ngx_http_python_request_error);
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject *
ngx_http_python_request_hi(ngx_http_python_request_t *self)
{
    ngx_http_request_t             *r;
    ngx_http_python_request_hdr_t  *ph;

    r = self->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http python hi");

    ph = PyObject_New(ngx_http_python_request_hdr_t,
                      &ngx_http_python_request_hdr_type);
    if (ph == NULL) {
        return NULL;
    }

    ph->pr = self;
    ph->out = 0;

    Py_INCREF(self);

    return (PyObject *) ph;
}


static PyObject *
ngx_http_python_request_ho(ngx_http_python_request_t *self)
{
    ngx_http_request_t             *r;
    ngx_http_python_request_hdr_t  *ph;

    r = self->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http python ho");

    ph = PyObject_New(ngx_http_python_request_hdr_t,
                      &ngx_http_python_request_hdr_type);
    if (ph == NULL) {
        return NULL;
    }

    ph->pr = self;
    ph->out = 1;

    Py_INCREF(self);

    return (PyObject *) ph;
}


static PyObject *
ngx_http_python_request_arg(ngx_http_python_request_t *self)
{
    ngx_http_request_t             *r;
    ngx_http_python_request_arg_t  *pa;

    r = self->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python arg");

    pa = PyObject_New(ngx_http_python_request_arg_t,
                      &ngx_http_python_request_arg_type);
    if (pa == NULL) {
        return NULL;
    }

    pa->pr = self;

    Py_INCREF(self);

    return (PyObject *) pa;
}


static PyObject *
ngx_http_python_request_var(ngx_http_python_request_t *self)
{
    ngx_http_request_t             *r;
    ngx_http_python_request_var_t  *pv;

    r = self->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python var");

    pv = PyObject_New(ngx_http_python_request_var_t,
                      &ngx_http_python_request_var_type);
    if (pv == NULL) {
        return NULL;
    }

    pv->pr = self;

    Py_INCREF(self);

    return (PyObject *) pv;
}


static PyObject *
ngx_http_python_request_ctx(ngx_http_python_request_t *self)
{
    ngx_http_request_t  *r;

    r = self->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python ctx");

    Py_INCREF(self->ctx);

    return self->ctx;
}


static PyObject *
ngx_http_python_request_get_status(ngx_http_python_request_t *self)
{
    ngx_http_request_t  *r;

    r = self->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python get status");

    return PyLong_FromLong(r->headers_out.status);
}


static int
ngx_http_python_request_set_status(ngx_http_python_request_t *self,
    PyObject *value)
{
    long                 status;
    ngx_http_request_t  *r;

    r = self->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return -1;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python set status");

    status = PyLong_AsLong(value);
    if (status < 0) {
        return -1;
    }

    r->headers_out.status = status;

    return 0;
}


static void
ngx_http_python_request_dealloc(ngx_http_python_request_t *self)
{
    Py_DECREF(self->ctx);

    self->ob_type->tp_free((PyObject*) self);
}


static PyObject *
ngx_http_python_request_hdr_subscript(ngx_http_python_request_hdr_t *self,
    PyObject *key)
{
    char                *data;
    Py_ssize_t           len;
    ngx_list_t          *headers;
    ngx_table_elt_t     *h;
    ngx_http_request_t  *r;

    r = self->pr->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python hdr subscript()");

    if (PyString_AsStringAndSize(key, &data, &len) < 0 ) {
        return NULL;
    }

    headers = self->out ? &r->headers_out.headers : &r->headers_in.headers;

    h = ngx_http_python_find_header(headers, (u_char *) data, len);

    if (h == NULL || h->hash == 0) {
        return PyString_FromStringAndSize(NULL, 0);
    }

    return PyString_FromStringAndSize((char *) h->value.data, h->value.len);
}


static int
ngx_http_python_request_hdr_ass_subscript(ngx_http_python_request_hdr_t *self,
    PyObject *key, PyObject *value)
{
    char                *data, *vdata;
    u_char              *p;
    PyObject            *vs;
    Py_ssize_t           len, vlen;
    ngx_list_t          *headers;
    ngx_table_elt_t     *h;
    ngx_http_request_t  *r;

    r = self->pr->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return -1;
    }

    if (!self->out) {
        PyErr_SetString(ngx_http_python_request_error, "read-only header");
        return -1;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python hdr ass_subscript()");

    vs = NULL;

    if (PyString_AsStringAndSize(key, &data, &len) < 0) {
        goto failed;
    }

    vlen = 0;

    if (value) {
        vs = PyObject_Str(value);
        if (vs == NULL) {
            goto failed;
        }

        if (PyString_AsStringAndSize(vs, &vdata, &vlen) < 0) {
            goto failed;
        }
    }

    headers = &r->headers_out.headers;

    h = ngx_http_python_find_header(headers, (u_char *) data, len);

    if (vlen == 0) {
        if (h) {
            h->hash = 0;
        }

        goto done;
    }

    if (h == NULL) {
        h = ngx_list_push(headers);
        if (h == NULL) {
            PyErr_SetNone(ngx_http_python_request_error);
            goto failed;
        }

        h->hash = 1;

        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            PyErr_SetNone(ngx_http_python_request_error);
            goto failed;
        }

        ngx_memcpy(p, data, len);
        h->key.data = p;
        h->key.len = len;
    }

    p = ngx_pnalloc(r->pool, vlen);
    if (p == NULL) {
        PyErr_SetNone(ngx_http_python_request_error);
        goto failed;
    }

    ngx_memcpy(p, vdata, vlen);
    h->value.data = p;
    h->value.len = vlen;

done:

    Py_XDECREF(vs);
    return 0;

failed:

    Py_XDECREF(vs);
    return -1;
}


static ngx_table_elt_t *
ngx_http_python_find_header(ngx_list_t *headers, u_char *data, size_t len)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    part = &headers->part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                return NULL;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].key.len == len
            && ngx_strncasecmp(header[i].key.data, data, len) == 0)
        {
            return &header[i];
        }
    }
}


static void
ngx_http_python_request_hdr_dealloc(ngx_http_python_request_hdr_t *self)
{
    Py_DECREF(self->pr);

    self->ob_type->tp_free((PyObject*) self);
}


static PyObject *
ngx_http_python_request_arg_subscript(ngx_http_python_request_arg_t *self,
    PyObject *key)
{
    char                *data;
    ngx_str_t            value;
    Py_ssize_t           len;
    ngx_http_request_t  *r;

    r = self->pr->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python arg subscript()");

    if (PyString_AsStringAndSize(key, &data, &len) < 0 ) {
        return NULL;
    }

    if (ngx_http_arg(r, (u_char *) data, len, &value) != NGX_OK) {
        return PyString_FromStringAndSize(NULL, 0);
    }

    return PyString_FromStringAndSize((char *) value.data, value.len);
}


static void
ngx_http_python_request_arg_dealloc(ngx_http_python_request_arg_t *self)
{
    Py_DECREF(self->pr);

    self->ob_type->tp_free((PyObject*) self);
}


static PyObject *
ngx_http_python_request_var_subscript(ngx_http_python_request_var_t *self,
    PyObject *key)
{
    char                       *data;
    ngx_str_t                   name;
    ngx_uint_t                  hash;
    Py_ssize_t                  len;
    ngx_http_request_t         *r;
    ngx_http_variable_value_t  *vv;

    r = self->pr->request;
    if (r == NULL) {
        PyErr_SetString(ngx_http_python_request_error, "request finalized");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python var subscript()");

    if (PyString_AsStringAndSize(key, &data, &len) < 0 ) {
        return NULL;
    }

    name.data = (u_char *) data;
    name.len = len;

    hash = ngx_hash_strlow(name.data, name.data, name.len);

    vv = ngx_http_get_variable(r, &name, hash);
    if (vv == NULL) {
        PyErr_SetNone(ngx_http_python_request_error);
        return NULL;
    }

    if (vv->not_found) {
        return PyString_FromStringAndSize(NULL, 0);
    }

    return PyString_FromStringAndSize((char *) vv->data, vv->len);
}


static void
ngx_http_python_request_var_dealloc(ngx_http_python_request_var_t *self)
{
    Py_DECREF(self->pr);

    self->ob_type->tp_free((PyObject*) self);
}


ngx_int_t
ngx_http_python_request_init(ngx_conf_t *cf)
{
    static ngx_int_t  initialized;

    if (initialized) {
        return NGX_OK;
    }

    initialized = 1;

    if (PyType_Ready(&ngx_http_python_request_type) < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "could not add %s type",
                           ngx_http_python_request_type.tp_name);
        return NGX_ERROR;
    }

    if (PyType_Ready(&ngx_http_python_request_hdr_type) < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "could not add %s type",
                           ngx_http_python_request_hdr_type.tp_name);
        return NGX_ERROR;
    }

    if (PyType_Ready(&ngx_http_python_request_arg_type) < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "could not add %s type",
                           ngx_http_python_request_arg_type.tp_name);
        return NGX_ERROR;
    }

    if (PyType_Ready(&ngx_http_python_request_var_type) < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "could not add %s type",
                           ngx_http_python_request_var_type.tp_name);
        return NGX_ERROR;
    }

    ngx_http_python_request_error = PyErr_NewException("ngx.HTTPRequestError",
                                                       PyExc_RuntimeError,
                                                       NULL);
    if (ngx_http_python_request_error == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


PyObject *
ngx_http_python_request_create(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t         *cln;
    ngx_http_python_request_t  *pr;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http python create request");

    pr = PyObject_New(ngx_http_python_request_t, &ngx_http_python_request_type);
    if (pr == NULL) {
        return NULL;
    }

    pr->request = r;

    pr->ctx = PyDict_New();
    if (pr->ctx == NULL) {
        Py_DECREF(pr);
        return NULL;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        Py_DECREF(pr);
        PyErr_SetNone(ngx_http_python_request_error);
        return NULL;
    }

    cln->handler = ngx_http_python_request_cleanup;
    cln->data = pr;

    Py_INCREF(pr);

    return (PyObject *) pr;
}


static void
ngx_http_python_request_cleanup(void *data)
{
    ngx_http_python_request_t *pr = data;

    pr->request = NULL;

    Py_DECREF(pr);
}
