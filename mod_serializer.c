/*
 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 
 * Copyright 2021 Hannu Veini
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * Apache web server module to make parallel requests serial.
 * 
 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */


#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "apr_hash.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_main.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"


/*
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Configuration structure
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
typedef struct
{
    char *skip_methods;
    char *lockdir;
    char *prefix;
    char *mime;
    char *resp;
    int enabled;
    apr_int64_t errorCode;
    apr_int64_t timeout;
    apr_int64_t quelen;
    apr_int64_t setmap;
} serializer_module_config_t;
#define SERIALIZER_ENABLED      0b000000001
#define SERIALIZER_SKIP_METHODS 0b000000010
#define SERIALIZER_LOCKDIR      0b000000100
#define SERIALIZER_PREFIX       0b000001000
#define SERIALIZER_MIME         0b000010000
#define SERIALIZER_RESP         0b000100000
#define SERIALIZER_ERRORCODE    0b001000000
#define SERIALIZER_TIMEOUT      0b010000000
#define SERIALIZER_QUELEN       0b100000000

/*
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    static variables
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
static apr_pool_t *serializer_conf_pool;
static server_rec *sr;

/*
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Macros
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#ifdef DEBUG

#define DEBUG_RLOG(r,...) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "DEBUG:" __VA_ARGS__);
#define DEBUG_LOG(...) ap_log_error(APLOG_MARK, APLOG_ERR, 0, sr, "DEBUG:" __VA_ARGS__);

#define PRINT_SERIALIZER_CONFIG(conf,r,firstpart) \
ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "DEBUG:%s on%s='%d', skip%s='%s', ld%s='%s', prefix%s='%s', mime%s='%s', resp%s='%s', ec%s='%ld', to%s='%ld', ql%s='%ld',handler='%s', uri='%s'", firstpart,\
              (0 < (SERIALIZER_ENABLED & conf->enabled)) ? "+" : "-",\
              conf->enabled,\
              (0 < (SERIALIZER_SKIP_METHODS & conf->setmap)) ? "+" : "-",\
              conf->skip_methods,\
              (0 < (SERIALIZER_LOCKDIR & conf->setmap)) ? "+" : "-",\
              conf->lockdir,\
              (0 < (SERIALIZER_PREFIX & conf->setmap)) ? "+" : "-",\
              conf->prefix,\
              (0 < (SERIALIZER_MIME & conf->setmap)) ? "+" : "-",\
              conf->mime,\
              (0 < (SERIALIZER_RESP & conf->setmap)) ? "+" : "-",\
              conf->resp,\
              (0 < (SERIALIZER_ERRORCODE & conf->setmap)) ? "+" : "-",\
              conf->errorCode,\
              (0 < (SERIALIZER_TIMEOUT & conf->setmap)) ? "+" : "-",\
              conf->timeout,\
              (0 < (SERIALIZER_QUELEN & conf->setmap)) ? "+" : "-",\
              conf->quelen,r->handler,r->uri);
#else

#define DEBUG_RLOG(r, ...) ;
#define DEBUG_LOG(...) ;
#define PRINT_SERIALIZER_CONFIG(conf, r, firstpart) ;

#endif

/*
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    prototype
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/
module AP_MODULE_DECLARE_DATA serializer_module;

/**
 * 
 * wait in que as long as earlier file exists, or timeout.
 * Remover any 5-min old files.
 *
 * Returns:
 * 0, ok to contimue
 * 1, timeout
 * 2, queue full
 * 3, error
 * 4, file exists for same client
 */
int wait_in_que(request_rec *r,serializer_module_config_t *config, char *lockfile, apr_time_t timeout)
{

    //get the file to wait, i.e. the timestamp before lockfile
    apr_status_t rv;
    apr_dir_t *dir=NULL;
    apr_finfo_t dirent;
    int filecount = 0;
    int chkFileCount=1;
    int ret=0;
    char *fileToWait=NULL;
    apr_sleep(10); // wait 10 micro seconds, to ensure other exact same time process has time to write a lock file 
    while (1)
    {
        if (NULL != dir){
            apr_dir_close(dir);
            dir=NULL;
        }
        //timeout?
        if (0 != config->timeout && timeout < apr_time_now())
        {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "serializer: Timeout when waiting '%s'", r->uri);
            DEBUG_RLOG(r, "serializer: Timeout ftw='%s'", fileToWait)
            ret = 1;
            break;
        }
        // wait the earlier lock file to go a way
        if (NULL != fileToWait)
        {
            apr_sleep(5000); // wait 5 milli seconds==0.005sec
            struct stat stats;
            //try to get file stat
            if (0 != stat(fileToWait, &stats))
            {
#ifdef DEBUG
                apr_time_t t = apr_time_now() - (timeout - ((apr_time_t)config->timeout * 1000000));
                DEBUG_RLOG(r, "serializer: ftw='%s' gone in '%ld' microSecs", fileToWait, t)
#endif
                fileToWait = NULL;
            }
            continue;
        }
        rv = apr_dir_open(&dir, config->lockdir, r->pool);
        if (rv != APR_SUCCESS)
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to open dir '%s'", config->lockdir);
            ret=3;
            break;
        }
#ifdef DEBUG
        apr_int64_t tFirst=0;
        const char *fFirst=NULL;
#endif
        //go throug all files in the dir
        while ((apr_dir_read(&dirent, APR_FINFO_NAME | APR_FINFO_TYPE, dir)) == APR_SUCCESS)
        {
            // file is in  same queue
            if (APR_REG == dirent.filetype &&
                strlen(dirent.name) > (31 + strlen(config->prefix)) &&
                0 == memcmp(dirent.name, config->prefix, strlen(config->prefix)))
            {
                //remove any 5 minutes old file
                // in practice, this should not ever happen, but just to be safe
                char *ft = apr_psprintf(r->pool, "%s", "00000000000000000000");
                memcpy(ft, &dirent.name[strlen(config->prefix)], 20);
                apr_int64_t t = apr_atoi64(ft);
                if (0 == t || apr_time_now() > (300000000 + t))
                {
                    char *f_with_path = apr_psprintf(r->pool, "%s/%s", config->lockdir, dirent.name);
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Removing over 5 min old file '%s'", f_with_path);
                    apr_file_remove((const char *)f_with_path, r->pool);
                    continue;
                }
#ifdef DEBUG
                if(0==tFirst){
                    tFirst = t;
                    fFirst = dirent.name;
                }else if(t<tFirst){
                    tFirst = t;
                    fFirst = dirent.name;
                }
#endif
                //check if the file to compare is created earlier than lockfile file to wait
                if ( 0 < strcmp(lockfile, dirent.name))
                {
                    //Any file already for this same client
                    char *ff = apr_psprintf(r->pool, "%s", "000");
                    memcpy(ff, &dirent.name[strlen(config->prefix) + 20], 3);
                    int family = apr_atoi64(ff);
                    char *fp = apr_psprintf(r->pool, "%s", "00000000");
                    memcpy(fp, &dirent.name[strlen(config->prefix) + 23], 8);
                    int port = apr_atoi64(fp);
                    char *ip = (char *)&dirent.name[strlen(config->prefix) + 31];
                    if (r->connection->client_addr->family == family &&
                        r->connection->client_addr->port == port &&
                        0 == strcmp(r->useragent_ip, ip))
                    {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Skip same client '%s'", dirent.name);
                        fileToWait = NULL;
                        ret = 4;
                        break;
                    }
                    if (NULL == fileToWait)
                    {
                        // initial
                        fileToWait = (char *)dirent.name;
//                        DEBUG_RLOG(r, "0ftw='%s'", fileToWait)
                    }
                    else if (0 > strcmp(fileToWait, dirent.name))
                    {
                        // older than previus one
                        fileToWait = (char *)dirent.name;
//                        DEBUG_RLOG(r, "1ftw='%s'", fileToWait)
                    }
                    filecount++;
                }
            }
        }
        if (0 != chkFileCount)
        {
            chkFileCount = 0;
            if (0 != config->quelen && filecount > config->quelen)
            {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Queue full when waiting '%s'", r->uri);
                DEBUG_RLOG(r, "Queue has '%d', max='%ld''", filecount, config->quelen)
                ret = 2;
                break;
            }
        }
        if (NULL != fileToWait)
        {
            fileToWait = apr_psprintf(r->pool, "%s/%s", config->lockdir, fileToWait);
#ifdef DEBUG
            DEBUG_RLOG(r, "ftw='%s', filecount='%d', t='%ld',ff='%s'", fileToWait, filecount, apr_time_now() - tFirst, fFirst)
#endif
        }else
        {
            DEBUG_RLOG(r, "No ftw")
            break;
        }
    }
    if (NULL != dir)
    {
        apr_dir_close(dir);
    }
    DEBUG_RLOG(r, "ret=%d",ret)
    return ret;
}

/*
 =======================================================================================================================
    Wait for others to finnish before continuing
 =======================================================================================================================
*/
static int serializer_first(request_rec *r)
{
    apr_pool_t *p = r->pool;
    serializer_module_config_t *config = (serializer_module_config_t *)ap_get_module_config(r->per_dir_config, &serializer_module);
    // return if not enabled
    if (0 == config->enabled)
    {
        return (DECLINED);
    }

    // return if sub reg
    // return if internal redirect reg
    if (0 == config->enabled || r->main || r->prev || r->next)
    {
        DEBUG_RLOG(r, "DECLINED: sub_rec='%s', int_redirect='%s', ext_redirect='%s'",
                   (r->main) ? "Yes" : "No",
                   (r->prev) ? "Yes" : "No",
                   (r->next) ? "Yes" : "No")
        PRINT_SERIALIZER_CONFIG(config, r, "decline")
        return (DECLINED);
    }

    DEBUG_RLOG(r, "serializer_first: h='%s', uri='%s'", r->handler, r->uri)
    PRINT_SERIALIZER_CONFIG(config, r, "first")
    // return if ignore r->method
    char *chk_str = apr_psprintf(p, " %s ", r->method);
    if (NULL != strstr(config->skip_methods, chk_str))
    {
        DEBUG_RLOG(r, "DECLINED: '%s' in '%s'", chk_str, config->skip_methods)
        return (DECLINED);
    }

    // return if lock file already defined
    char *lockfile_with_path = (char *)apr_table_get(r->notes, "serializer_lockfile_with_path");
    if( NULL!=lockfile_with_path )
    {
        DEBUG_RLOG(r, "DECLINED: lf='%s'", lockfile_with_path)
        return (DECLINED);
    }

    apr_status_t rv;
    apr_time_t now = apr_time_now();
    apr_time_t timeout = apr_time_now() + ((apr_time_t)config->timeout * 1000000);
    char *lockfile = apr_psprintf(p, "%s%020ld%03d%08d%s", config->prefix, now, r->connection->client_addr->family, r->connection->client_addr->port, r->useragent_ip);
    lockfile_with_path = apr_psprintf(p, "%s/%s", config->lockdir, lockfile);

    //create lockfile
    apr_file_t *lock_file;
    rv = apr_file_open(&lock_file,
                       (const char *)lockfile_with_path,
                       APR_FOPEN_CREATE |  // create file
                       APR_FOPEN_EXCL |    // error if file was there already
                       APR_FOPEN_WRITE |   // open for writing
                       APR_FOPEN_APPEND |  // move to end of file on open
                       APR_FOPEN_XTHREAD | // allow multiple threads to use file
                       0, // flags
                       APR_OS_DEFAULT |
                       0, // permissions
                       p);
    if (APR_SUCCESS != rv)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to create lockfile '%s'", lockfile_with_path);
        apr_file_remove((const char *)lockfile_with_path, r->pool);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_file_close(lock_file);
    //set the file name to be deleted in 'serializer_last'
    apr_table_set(r->notes, "serializer_lockfile_with_path", lockfile_with_path);

    DEBUG_RLOG(r, "lf='%s'", lockfile_with_path)
    switch (wait_in_que(r, config, lockfile, timeout))
    {
    case 0: //OK
        break;
    case 1: // timeout
    case 2: // que full
        apr_file_remove(lockfile_with_path, r->pool);
        apr_table_unset(r->notes, "serializer_lockfile_with_path");
        if (1 < strlen(config->mime) && 1 < strlen(config->resp))
        {
            ap_set_content_type(r, config->mime);
            ap_rprintf(r, "%s", config->resp);
            r->status = config->errorCode;
            return DONE;
        }
        return config->errorCode;
        break;
    case 4: //File for this same client exists, remove lock file and continue
        apr_file_remove(lockfile_with_path, r->pool);
        apr_table_unset(r->notes, "serializer_lockfile_with_path");
        break;
    default: // error
        apr_file_remove(lockfile_with_path, r->pool);
        apr_table_unset(r->notes, "serializer_lockfile_with_path");
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "unknown error");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    return DECLINED;
}

/*
 =======================================================================================================================
    Remove the lockfile
 =======================================================================================================================
 */
static int serializer_last(request_rec *r)
{
    //remove the lockfile
    const char *lockfile_with_path=apr_table_get (r->notes, "serializer_lockfile_with_path");
    if( NULL!=lockfile_with_path ){
        apr_file_remove(lockfile_with_path, r->pool);
        apr_table_unset(r->notes, "serializer_lockfile_with_path");
#ifdef DEBUG
        DEBUG_RLOG(r, "serializer_last, remove '%s'", lockfile_with_path)
        DEBUG_RLOG(r, "serializer_last: '%s'", r->handler)
        serializer_module_config_t *config = (serializer_module_config_t *)ap_get_module_config(r->per_dir_config, &serializer_module);
        PRINT_SERIALIZER_CONFIG(config, r, "last")
        DEBUG_RLOG(r, "serializer_last: bytes_sent='%ld'", r->bytes_sent)
#endif
    }
    return DECLINED;
}

/*
 =======================================================================================================================
    Handler for the "Serializer" directive
 =======================================================================================================================
 */
const char *serializer_on(cmd_parms *cmd, void *cfg, const char *arg)
{
    serializer_module_config_t    *conf = (serializer_module_config_t *) cfg;
    if (!strcasecmp(arg, "on") || !strcasecmp(arg, "yes") || !strcasecmp(arg, "1"))
        conf->enabled = 1;
    else
        conf->enabled = 0;
    DEBUG_LOG("conf->enabled='%d'", conf->enabled);
    conf->setmap |= SERIALIZER_ENABLED;
    return NULL;
}

/*
 =======================================================================================================================
    Handler for the "SerializerTimeout" directive
 =======================================================================================================================
 */
const char *serializer_set_timeout(cmd_parms *cmd, void *cfg, const char *arg)
{
    serializer_module_config_t *conf = (serializer_module_config_t *)cfg;
    conf->timeout = apr_atoi64(arg);
    conf->setmap |= SERIALIZER_TIMEOUT;
    DEBUG_LOG("conf->timeout='%ld'", conf->timeout)
    return NULL;
}

/*
 =======================================================================================================================
    Handler for the "SerializerQueLen" directive
 =======================================================================================================================
 */
const char *serializer_set_que_len(cmd_parms *cmd, void *cfg, const char *arg)
{
    serializer_module_config_t    *conf = (serializer_module_config_t *) cfg;
    conf->quelen = apr_atoi64(arg);
    conf->setmap |= SERIALIZER_QUELEN;
    DEBUG_LOG("conf->quelen='%ld'", conf->quelen)
    return NULL;
}

/*
 =======================================================================================================================
    Handler for the "SerializerPath" directive
 =======================================================================================================================
 */
const char *serializer_set_path(cmd_parms *cmd, void *cfg, const char *arg)
{
    serializer_module_config_t    *conf = (serializer_module_config_t *) cfg;
    conf->lockdir = apr_psprintf(serializer_conf_pool, "%s", arg);
    conf->setmap |= SERIALIZER_LOCKDIR;
    DEBUG_LOG("conf->lockdir='%s'", conf->lockdir)
    return NULL;
}
/*
 =======================================================================================================================
    Handler for the "SerializerSkipMethods" directive
 =======================================================================================================================
 */
const char *serializer_set_skip_methods(cmd_parms *cmd, void *cfg, const char *arg)
{
    serializer_module_config_t    *conf = (serializer_module_config_t *) cfg;
    conf->skip_methods=apr_psprintf(serializer_conf_pool, " %s ", arg);
    conf->setmap |= SERIALIZER_SKIP_METHODS;
    //to uppercase and remove all non alphas
    for(int i=0;i<(strlen(arg)+1);i++){
        if( conf->skip_methods[i]>='a' &&  conf->skip_methods[i]<='z' ){
            conf->skip_methods[i]-=('a'-'A');
        }else if ( !(conf->skip_methods[i]>='A' &&  conf->skip_methods[i]<='Z') ){
            conf->skip_methods[i]=' ';
        }
    }
    DEBUG_LOG("conf->skip_methods='%s'", conf->skip_methods)
    // Now conf->skip_methods is a string with capital letter http methods separated by spaces, with pre and leading space
    return NULL;
}
/*
 =======================================================================================================================
    Handler for the "SerializerPrefix" directive
 =======================================================================================================================
 */
const char *serializer_set_prefix(cmd_parms *cmd, void *cfg, const char *arg)
{
    serializer_module_config_t    *conf = (serializer_module_config_t *) cfg;
    conf->prefix = apr_psprintf(serializer_conf_pool, "%s", arg);
    conf->setmap |= SERIALIZER_PREFIX;
    DEBUG_LOG("conf->prefix='%s'", conf->prefix)
    return NULL;
}

/*
 =======================================================================================================================
    Handler for the "SerializerErrorCode" directive ;
 =======================================================================================================================
 */
const char *serializer_set_error_code(cmd_parms *cmd, void *cfg, const char *arg)
{
    serializer_module_config_t    *conf = (serializer_module_config_t *) cfg;
    conf->errorCode = apr_atoi64(arg);
    conf->setmap |= SERIALIZER_ERRORCODE;
    DEBUG_LOG("conf->errorCode='%ld'", conf->errorCode)
    return NULL;
}

/*
 =======================================================================================================================
    Handler for the "SerializerErrorResp" directive
 =======================================================================================================================
 */
const char *serializer_set_error_resp(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2)
{
    serializer_module_config_t *conf = (serializer_module_config_t *)cfg;
    conf->mime = apr_psprintf(serializer_conf_pool, "%s", arg1);
    conf->resp = apr_psprintf(serializer_conf_pool, "%s", arg2);
    conf->setmap |= SERIALIZER_MIME + SERIALIZER_RESP;
    DEBUG_LOG("conf->mime='%s'", conf->mime)
    DEBUG_LOG("conf->resp='%s'",conf->resp)
    return NULL;
}

/*
 =======================================================================================================================
    Function for creating new configurations for per-directory/location contexts
 =======================================================================================================================
 */
serializer_module_config_t *serializer_create_dir_conf_ini(apr_pool_t *p, int set)
{

    serializer_module_config_t *cfg = apr_pcalloc(p, sizeof(serializer_module_config_t));
    if (set)
    {
        /* Set some default values */
        cfg->prefix = apr_psprintf(p, "serializer_");
        cfg->timeout = 60;
        cfg->quelen = 0;
        cfg->skip_methods = apr_psprintf(p, " ");
        apr_temp_dir_get((const char **)&cfg->lockdir, p);
        cfg->errorCode = HTTP_INTERNAL_SERVER_ERROR;
        cfg->mime = apr_pcalloc(p, 1);
        cfg->resp = apr_pcalloc(p, 1);
    }

    return cfg;
}
/*
 =======================================================================================================================
    Function for creating new configurations for per-directory/location contexts
 =======================================================================================================================
 */
void *serializer_create_dir_conf(apr_pool_t *p, char *c)
{
    serializer_conf_pool = p;
    return serializer_create_dir_conf_ini(p,1);
}

/*
 =======================================================================================================================
    Merging function for configurations
 =======================================================================================================================
 */
void *serializer_merge_dir_conf(apr_pool_t *pool, void *b, void *a)
{
    serializer_module_config_t *add  = (serializer_module_config_t *)a;
    serializer_module_config_t *base = (serializer_module_config_t *)b;
    serializer_module_config_t *conf = serializer_create_dir_conf_ini(pool, 0);

    conf->enabled      = (0 != (SERIALIZER_ENABLED      & add->setmap))  ? add->enabled      : base->enabled;
    conf->skip_methods = (0 != (SERIALIZER_SKIP_METHODS & add->setmap))  ? add->skip_methods : base->skip_methods;
    conf->lockdir      = (0 != (SERIALIZER_LOCKDIR      & add->setmap))  ? add->lockdir      : base->lockdir;
    conf->prefix       = (0 != (SERIALIZER_PREFIX       & add->setmap))  ? add->prefix       : base->prefix;
    conf->mime         = (0 != (SERIALIZER_MIME         & add->setmap))  ? add->mime         : base->mime;
    conf->resp         = (0 != (SERIALIZER_RESP         & add->setmap))  ? add->resp         : base->resp;
    conf->errorCode    = (0 != (SERIALIZER_ERRORCODE    & add->setmap))  ? add->errorCode    : base->errorCode;
    conf->timeout      = (0 != (SERIALIZER_TIMEOUT      & add->setmap))  ? add->timeout      : base->timeout;
    conf->quelen       = (0 != (SERIALIZER_QUELEN       & add->setmap))  ? add->quelen       : base->quelen;
    conf->setmap = add->setmap | base->setmap;

    return conf;
}


/*
 =======================================================================================================================
    Hook registration function
 =======================================================================================================================
 */
static void serializer_register_hooks(apr_pool_t *pool)
{
    
    ap_hook_fixups(          serializer_first, NULL, NULL, APR_HOOK_FIRST );
    ap_hook_log_transaction( serializer_last,  NULL, NULL, APR_HOOK_FIRST );
}

/*
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Configuration directives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

static const command_rec serializer_directives[] = {
    AP_INIT_TAKE1("Serializer", serializer_on, NULL, ACCESS_CONF, "Enanble mod_serializer for this location. Values can be 'on' or 'yes' or '1'. Default='No'"),
    AP_INIT_TAKE1("SerializerPath", serializer_set_path, NULL, ACCESS_CONF, "Path for lock files. Default system temp dir."),
    AP_INIT_TAKE1("SerializerPrefix", serializer_set_prefix, NULL, ACCESS_CONF, "Prefix for lock file. Default='serializer'"),
    AP_INIT_TAKE1("SerializerSkipMethods", serializer_set_skip_methods, NULL, ACCESS_CONF, "Comma separeated list of HTTP Methosds to skip. Default=GET"),
    AP_INIT_TAKE1("SerializerTimeout", serializer_set_timeout, NULL, ACCESS_CONF, "Max time in seconds to wait in queue. Default=60"),
    AP_INIT_TAKE1("SerializerQueLen", serializer_set_que_len, NULL, ACCESS_CONF, "Max reguest amount in wait queue. Default=0 (==no limit)"),
    AP_INIT_TAKE1("SerializerErrorCode", serializer_set_error_code, NULL, ACCESS_CONF, "HTTP error code to use, when timeout. Default=500"),
    AP_INIT_TAKE2("SerializerErrorResp", serializer_set_error_resp, NULL, ACCESS_CONF, "Mime type and string to send as HTTP body for error code. Default=' ' ' '"),
    {NULL}};

typedef struct
{
    server_rec *s;
} serializer_server_config_t;

// not a real configuration, just for storing the server_rec
static void *serializer_create_server_config(apr_pool_t *p, server_rec *s)
{
    serializer_server_config_t *cfg = apr_pcalloc(p, sizeof(serializer_server_config_t));
    sr = s;
    cfg->s=s;
    DEBUG_LOG("in ='%s'", "serializer_create_server_config")
    return cfg;
}

// need to be declared like this, otherwise the module name is not shown in log
AP_DECLARE_MODULE(serializer) = {
    STANDARD20_MODULE_STUFF,
    serializer_create_dir_conf,      // Per-directory configuration handler
    serializer_merge_dir_conf,       // Merge handler for per-directory configurations
    serializer_create_server_config, // Per-server configuration handler
    NULL,                            // Merge handler for per-server configurations
    serializer_directives,           // Directives for httpd
    serializer_register_hooks,       // Hook registering function
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};
