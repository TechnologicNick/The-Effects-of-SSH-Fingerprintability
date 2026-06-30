#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "umac.h"

static PyObject *
compute_tag(PyObject *self, PyObject *args)
{
    int digest_size;
    const unsigned char *key;
    const unsigned char *nonce;
    const unsigned char *data;
    Py_ssize_t key_len;
    Py_ssize_t nonce_len;
    Py_ssize_t data_len;
    unsigned char tag[16];
    int ok;

    (void)self;

    if (!PyArg_ParseTuple(
            args,
            "iy#y#y#",
            &digest_size,
            &key,
            &key_len,
            &nonce,
            &nonce_len,
            &data,
            &data_len)) {
        return NULL;
    }

    if (key_len != 16) {
        PyErr_SetString(PyExc_ValueError, "UMAC key must be 16 bytes");
        return NULL;
    }
    if (nonce_len != 8) {
        PyErr_SetString(PyExc_ValueError, "UMAC nonce must be 8 bytes");
        return NULL;
    }
    if (digest_size != 8 && digest_size != 16) {
        PyErr_SetString(PyExc_ValueError, "UMAC digest size must be 8 or 16");
        return NULL;
    }

    if (digest_size == 8) {
        struct umac_ctx *ctx = umac_new(key);
        if (ctx == NULL) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to allocate UMAC context");
            return NULL;
        }
        ok = umac_update(ctx, data, (long)data_len);
        if (ok != 0) {
            ok = umac_final(ctx, tag, nonce);
        }
        umac_delete(ctx);
        if (ok == 0) {
            PyErr_SetString(PyExc_RuntimeError, "UMAC-64 computation failed");
            return NULL;
        }
        return PyBytes_FromStringAndSize((const char *)tag, 8);
    }

    {
        struct umac_ctx *ctx = umac128_new(key);
        if (ctx == NULL) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to allocate UMAC128 context");
            return NULL;
        }
        ok = umac128_update(ctx, data, (long)data_len);
        if (ok != 0) {
            ok = umac128_final(ctx, tag, nonce);
        }
        umac128_delete(ctx);
        if (ok == 0) {
            PyErr_SetString(PyExc_RuntimeError, "UMAC-128 computation failed");
            return NULL;
        }
    }
    return PyBytes_FromStringAndSize((const char *)tag, 16);
}

static PyMethodDef OpenSSHUmacMethods[] = {
    {"compute_tag", compute_tag, METH_VARARGS, "Compute an OpenSSH-compatible UMAC tag."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef openssh_umac_module = {
    PyModuleDef_HEAD_INIT,
    "openssh_umac",
    "OpenSSH UMAC wrapper",
    -1,
    OpenSSHUmacMethods,
};

PyMODINIT_FUNC
PyInit_openssh_umac(void)
{
    return PyModule_Create(&openssh_umac_module);
}
