
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_STREAM_PYTHON_SESSION_H_INCLUDED_
#define _NGX_STREAM_PYTHON_SESSION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_python.h"


ngx_int_t ngx_stream_python_session_init(ngx_conf_t *cf);
PyObject *ngx_stream_python_session_create(ngx_stream_session_t *s);


#endif /* _NGX_STREAM_PYTHON_SESSION_H_INCLUDED_ */
