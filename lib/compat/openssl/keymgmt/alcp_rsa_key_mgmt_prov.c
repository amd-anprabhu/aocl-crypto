/*
 * Copyright (C) 2024-2025, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 notice,
 *    this list of conditions and the following disclaimer in the
 documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/alcp.h"
#include "debug.h"
#include "provider/alcp_provider.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>


static const OSSL_DISPATCH* get_default_keymgmt_dispatch(void)
{
    static const OSSL_DISPATCH* default_dispatch = NULL;
    static int initialized = 0;
    
    if (!initialized) {
        OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
        if (default_provider) {
            int no_cache = 0;
            const OSSL_ALGORITHM* algorithms = OSSL_PROVIDER_query_operation(default_provider, OSSL_OP_KEYMGMT, &no_cache);
            if (algorithms) {
                // Find the RSA algorithm in the algorithms array
                for (int i = 0; algorithms[i].algorithm_names != NULL; i++) {
                    if (strstr(algorithms[i].algorithm_names, "RSA") != NULL) {
                        default_dispatch = algorithms[i].implementation;
                        break;
                    }
                }
            }
            OSSL_PROVIDER_unload(default_provider);
            initialized = 1;
        } else {
            printf("Failed to load default provider\n");
        }
    }
    return default_dispatch;
}

// Define a generic function pointer type for dispatch functions
// This avoids ISO C errors when casting function pointers to void*
typedef void (*generic_dispatch_func)(void);

static generic_dispatch_func get_dispatch_function(int func_id)
{
    const OSSL_DISPATCH* dispatch = get_default_keymgmt_dispatch();
    if (!dispatch) {
        return NULL;
    }
    
    for (int i = 0; dispatch[i].function_id != 0; i++) {
        if (dispatch[i].function_id == func_id) {
            return (generic_dispatch_func)dispatch[i].function;
        }
    }
    return NULL;
}

static void*
alcp_prov_keymgmt_rsa_newdata(void* provctx)
{
    typedef void* (*fun_ptr)(void*);
    ENTER();
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_NEW);
    if (!fun)
        return NULL;
    EXIT();
    return fun(provctx);
}

static void
alcp_prov_keymgmt_rsa_freedata(void* keydata)
{
    typedef void (*fun_ptr)(void*);
    ENTER();
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_FREE);
    if (!fun)
        return;
    EXIT();
    fun(keydata);
}

static int
alcp_prov_keymgmt_rsa_has(const void* keydata, int selection)
{
    typedef int (*fun_ptr)(const void*, int);
    ENTER();
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_HAS);
    if (!fun)
        return 0;
    EXIT();
    return fun(keydata, selection);
}

static int
alcp_prov_keymgmt_rsa_import(void*            keydata,
                             int              selection,
                             const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void*, int, const OSSL_PARAM*);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_IMPORT);
    ENTER();
    if (!fun)
        return 0;
    EXIT();
    return fun(keydata, selection, params);
}

static const OSSL_PARAM*
alcp_prov_keymgmt_rsa_import_types(int selection)
{
    typedef const OSSL_PARAM* (*fun_ptr)(int);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_IMPORT_TYPES);
    ENTER();
    if (!fun)
        return NULL;
    EXIT();
    return fun(selection);
}

static void*
alcp_prov_keymgmt_rsa_gen_init(void*            provctx,
                               int              selection,
                               const OSSL_PARAM params[])
{
    typedef void* (*fun_ptr)(void*, int, const OSSL_PARAM*);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_GEN_INIT);
    ENTER();
    if (!fun)
        return NULL;
    EXIT();
    return fun(provctx, selection, params);
}

static int
alcp_prov_keymgmt_rsa_gen_set_params(void* genctx, const OSSL_PARAM params[])
{
     typedef int (*fun_ptr)(void*, const OSSL_PARAM*);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS);
    ENTER();
    if (!fun)
        return 0;
    EXIT();
    return fun(genctx, params);
}

static const OSSL_PARAM*
alcp_prov_keymgmt_rsa_gen_settable_params(ossl_unused void* genctx,
                                          ossl_unused void* provctx)
{
    typedef const OSSL_PARAM* (*fun_ptr)(void*, void*);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS);
    ENTER();
    if (!fun)
        return NULL;
    EXIT();
    return fun(genctx, provctx);
}

static void*
alcp_prov_keymgmt_rsa_gen(void* genctx, OSSL_CALLBACK* osslcb, void* cbarg)
{
    typedef void* (*fun_ptr)(void*, OSSL_CALLBACK*, void*);
    RSA*    rsa = NULL;
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_GEN);
    ENTER();
    if (!fun)
        goto end;
    EXIT();
    rsa = fun(genctx, osslcb, cbarg);
end:
    return rsa;
}

static void
alcp_prov_keymgmt_rsa_gen_cleanup(void* genctx)
{
    typedef void (*fun_ptr)(void*);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_GEN_CLEANUP);
    ENTER();
    if (!fun)
        return;
    EXIT();
    fun(genctx);
}

static void*
alcp_prov_keymgmt_rsa_load(const void* reference, size_t reference_sz)
{
    typedef void* (*fun_ptr)(const void*, size_t);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_LOAD);
    ENTER();
    if (!fun)
        return NULL;
    EXIT();
    return fun(reference, reference_sz);
}

static int
alcp_prov_keymgmt_rsa_get_params(void* key, OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void*, OSSL_PARAM*);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_GET_PARAMS);
    ENTER();
    if (!fun)
        return 0;
    EXIT();
    return fun(key, params);
}

static const OSSL_PARAM*
alcp_prov_keymgmt_rsa_gettable_params(void* provctx)
{
    typedef const OSSL_PARAM* (*fun_ptr)(void*);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS);
    ENTER();
    if (!fun)
        return NULL;
    EXIT();
    return fun(provctx);
}

static int
alcp_prov_keymgmt_rsa_match(const void* keydata1,
                            const void* keydata2,
                            int         selection)
{
    typedef int (*fun_ptr)(const void*, const void*, int);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_MATCH);
    ENTER();
    if (!fun)
        return 0;
    EXIT();
    return fun(keydata1, keydata2, selection);
}

static int
alcp_prov_keymgmt_rsa_validate(const void* keydata,
                               int         selection,
                               int         checktype)
{
    typedef int (*fun_ptr)(const void*, int, int);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_VALIDATE);
    ENTER();
    if (!fun)
        return 0;
    EXIT();
    return fun(keydata, selection, checktype);
}

static int
alcp_prov_keymgmt_rsa_export(void*          keydata,
                             int            selection,
                             OSSL_CALLBACK* param_callback,
                             void*          cbarg)
{
    typedef int (*fun_ptr)(void*, int, OSSL_CALLBACK*, void*);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_EXPORT);
    ENTER();
    if (!fun)
        return 0;
    EXIT();
    return fun(keydata, selection, param_callback, cbarg);
}

static const OSSL_PARAM*
alcp_prov_keymgmt_rsa_export_types(int selection)
{
    typedef const OSSL_PARAM* (*fun_ptr)(int);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_EXPORT_TYPES);
    ENTER();
    if (!fun)
        return NULL;
    EXIT();
    return fun(selection);
}

static void*
alcp_prov_keymgmt_rsa_dup(const void* keydata_from, int selection)
{
    typedef void* (*fun_ptr)(const void*, int);
    fun_ptr fun = (fun_ptr)get_dispatch_function(OSSL_FUNC_KEYMGMT_DUP);
    ENTER();
    if (!fun)
        return NULL;
    EXIT();
    return fun(keydata_from, selection);
}


const OSSL_DISPATCH alcp_prov_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))alcp_prov_keymgmt_rsa_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))alcp_prov_keymgmt_rsa_freedata },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))alcp_prov_keymgmt_rsa_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))alcp_prov_keymgmt_rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (void (*)(void))alcp_prov_keymgmt_rsa_import_types },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,
      (void (*)(void))alcp_prov_keymgmt_rsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))alcp_prov_keymgmt_rsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))alcp_prov_keymgmt_rsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))alcp_prov_keymgmt_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
      (void (*)(void))alcp_prov_keymgmt_rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))alcp_prov_keymgmt_rsa_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
      (void (*)(void))alcp_prov_keymgmt_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))alcp_prov_keymgmt_rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))alcp_prov_keymgmt_rsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE,
      (void (*)(void))alcp_prov_keymgmt_rsa_validate },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))alcp_prov_keymgmt_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))alcp_prov_keymgmt_rsa_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))alcp_prov_keymgmt_rsa_dup },
    { 0, NULL }
};

static const char ASYM_CIPHERS_DEF_PROP[] = "provider=alcp,fips=no";

const OSSL_ALGORITHM alc_prov_keymgmt[] = { { ALCP_PROV_NAMES_RSA,
                                              ASYM_CIPHERS_DEF_PROP,
                                              alcp_prov_rsa_keymgmt_functions,
                                              ALCP_PROV_RSA_DESC },
                                            { NULL, NULL, NULL } };
