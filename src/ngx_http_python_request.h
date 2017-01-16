
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_HTTP_PYTHON_REQUEST_H_INCLUDED_
#define _NGX_HTTP_PYTHON_REQUEST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_python.h"


ngx_int_t ngx_http_python_request_init(ngx_conf_t *cf);
PyObject *ngx_http_python_request_create(ngx_http_request_t *r);


#endif /* _NGX_HTTP_PYTHON_REQUEST_H_INCLUDED_ */
