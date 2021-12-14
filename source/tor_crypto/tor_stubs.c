void *tor_malloc_(size_t size)
{
    return malloc(size);
}

void *tor_malloc_zero_(size_t size)
{
    void* retval = tor_malloc_(size);
    if (retval) {
        memset(retval, 0x00, size);
    }
    return retval;
}

void tor_assertion_failed_(
    const char *fname,
    unsigned int line,
    const char *func,
    const char *expr,
    const char *fmt,
    ...)
{
    (void)fname;
    (void)line;
    (void)func;
    (void)expr;
    (void)fmt;
}

void tor_abort_(void)
{
    abort();
}

void log_fn_(int severity, log_domain_mask_t domain, const char *fn,
    const char *format, ...)
{
    (void)severity;
    (void)domain;
    (void)fn;
    (void)format;
}