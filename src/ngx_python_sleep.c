
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_python.h"


#if !(NGX_PYTHON_SYNC)

static PyObject *ngx_python_sleep(PyObject *self, PyObject *args);
static void ngx_python_sleep_handler(ngx_event_t *ev);


static PyMethodDef ngx_python_sleep_function = {
    "sleep",
    (PyCFunction) ngx_python_sleep,
    METH_VARARGS,
    "non-blocking sleep"
};


static PyObject *
ngx_python_sleep(PyObject *self, PyObject *args)
{
    double            secs;
    ngx_event_t       event;
    ngx_connection_t  c;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python time.sleep()");

    if (!PyArg_ParseTuple(args, "d:sleep", &secs)) {
        return NULL;
    }

    ngx_memzero(&c, sizeof(ngx_connection_t));

    c.data = ngx_python_get_ctx();

    ngx_memzero(&event, sizeof(ngx_event_t));

    event.data = &c;
    event.handler = ngx_python_sleep_handler;
    event.log = ngx_cycle->log;

    ngx_add_timer(&event, secs * 1000);

    do {
        if (ngx_python_yield() != NGX_OK) {
            ngx_del_timer(&event);
            return NULL;
        }
    } while (!event.timedout);

    Py_RETURN_NONE;
}


static void
ngx_python_sleep_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;
    ngx_python_ctx_t  *ctx;

    c = ev->data;
    ctx = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "python time.sleep() event handler");

    ngx_python_wakeup(ctx);
}


ngx_int_t
ngx_python_sleep_install(ngx_conf_t *cf)
{
    PyObject  *sleep, *tm;

    tm = PyImport_ImportModule("time");
    if (tm == NULL) {
        return NGX_ERROR;
    }

    sleep = PyCFunction_NewEx(&ngx_python_sleep_function, NULL, NULL);
    if (sleep == NULL) {
        Py_DECREF(tm);
        return NGX_ERROR;
    }

    if (PyObject_SetAttrString(tm, "sleep", sleep) < 0) {
        Py_DECREF(sleep);
        Py_DECREF(tm);
        return NGX_ERROR;
    }

    Py_DECREF(sleep);
    Py_DECREF(tm);
    return NGX_OK;
}

#endif
