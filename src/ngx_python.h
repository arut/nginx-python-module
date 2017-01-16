
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_PYTHON_H_INCLUDED_
#define _NGX_PYTHON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <Python.h>


#define NGX_PYTHON_AGAIN  (void *) -1


typedef struct ngx_python_ctx_s  ngx_python_ctx_t;

typedef struct {
    ngx_pool_t  *pool;
    ngx_log_t   *log;
    PyObject    *ns;
    size_t       stack_size;
} ngx_python_create_ctx_t;


#if !(NGX_PYTHON_SYNC)

ngx_python_ctx_t *ngx_python_get_ctx();
ngx_int_t ngx_python_yield();
void ngx_python_wakeup(ngx_python_ctx_t *ctx);

ngx_int_t ngx_python_sleep_install(ngx_conf_t *cf);
ngx_int_t ngx_python_socket_install(ngx_conf_t *cf);
ngx_int_t ngx_python_resolve_install(ngx_conf_t *cf);
PyObject *ngx_python_socket_create_wrapper(ngx_connection_t *c);

#endif

ngx_python_ctx_t *ngx_python_create_ctx(ngx_python_create_ctx_t *pc);
PyObject *ngx_python_eval(ngx_python_ctx_t *ctx, PyCodeObject *code,
    ngx_event_t *wake);

void ngx_python_set_resolver(ngx_python_ctx_t *ctx, ngx_resolver_t *resolver,
    ngx_msec_t timeout);
ngx_resolver_t *ngx_python_get_resolver(ngx_python_ctx_t *ctx,
    ngx_msec_t *timeout);

char *ngx_python_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_python_include_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
PyCodeObject *ngx_python_compile(ngx_conf_t *cf, u_char *script);
PyObject *ngx_python_create_namespace(ngx_conf_t *cf);
u_char *ngx_python_get_error(ngx_pool_t *pool);


#endif /* _NGX_PYTHON_H_INCLUDED_ */
