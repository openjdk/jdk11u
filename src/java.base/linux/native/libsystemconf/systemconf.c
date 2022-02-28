/*
 * Copyright (c) 2021, Red Hat, Inc.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

#include <jni.h>
#include <jni_util.h>
#include "jvm_md.h"
#include <stdio.h>

#ifdef SYSCONF_NSS
#include <nss3/pk11pub.h>
#else
#include <dlfcn.h>
#endif //SYSCONF_NSS

#include "java_security_SystemConfigurator.h"

#define MSG_MAX_SIZE 256
#define FIPS_ENABLED_PATH "/proc/sys/crypto/fips_enabled"

typedef int (SECMOD_GET_SYSTEM_FIPS_ENABLED_TYPE)(void);

static SECMOD_GET_SYSTEM_FIPS_ENABLED_TYPE *getSystemFIPSEnabled;
static jmethodID debugPrintlnMethodID = NULL;
static jobject debugObj = NULL;

static void dbgPrint(JNIEnv *env, const char* msg)
{
    jstring jMsg;
    if (debugObj != NULL) {
        jMsg = (*env)->NewStringUTF(env, msg);
        CHECK_NULL(jMsg);
        (*env)->CallVoidMethod(env, debugObj, debugPrintlnMethodID, jMsg);
    }
}

static void throwIOException(JNIEnv *env, const char *msg)
{
    jclass cls = (*env)->FindClass(env, "java/io/IOException");
    if (cls != 0)
        (*env)->ThrowNew(env, cls, msg);
}

static void handle_msg(JNIEnv *env, const char* msg, int msg_bytes)
{
  if (msg_bytes > 0 && msg_bytes < MSG_MAX_SIZE) {
    dbgPrint(env, msg);
  } else {
    dbgPrint(env, "systemconf: cannot render message");
  }
}

// Only used when NSS is not linked at build time
#ifndef SYSCONF_NSS

static void *nss_handle;

static jboolean loadNSS(JNIEnv *env)
{
  char msg[MSG_MAX_SIZE];
  int msg_bytes;
  const char* errmsg;

  nss_handle = dlopen(JNI_LIB_NAME("nss3"), RTLD_LAZY);
  if (nss_handle == NULL) {
    errmsg = dlerror();
    msg_bytes = snprintf(msg, MSG_MAX_SIZE, "loadNSS: dlopen: %s\n",
                         errmsg);
    handle_msg(env, msg, msg_bytes);
    return JNI_FALSE;
  }
  dlerror(); /* Clear errors */
  getSystemFIPSEnabled = (SECMOD_GET_SYSTEM_FIPS_ENABLED_TYPE*)dlsym(nss_handle, "SECMOD_GetSystemFIPSEnabled");
  if ((errmsg = dlerror()) != NULL) {
    msg_bytes = snprintf(msg, MSG_MAX_SIZE, "loadNSS: dlsym: %s\n",
                         errmsg);
    handle_msg(env, msg, msg_bytes);
    return JNI_FALSE;
  }
  return JNI_TRUE;
}

static void closeNSS(JNIEnv *env)
{
  char msg[MSG_MAX_SIZE];
  int msg_bytes;
  const char* errmsg;

  if (dlclose(nss_handle) != 0) {
    errmsg = dlerror();
    msg_bytes = snprintf(msg, MSG_MAX_SIZE, "closeNSS: dlclose: %s\n",
                         errmsg);
    handle_msg(env, msg, msg_bytes);
  }
}

#endif

/*
 * Class:     java_security_SystemConfigurator
 * Method:    JNI_OnLoad
 */
JNIEXPORT jint JNICALL DEF_JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env;
    jclass sysConfCls, debugCls;
    jfieldID sdebugFld;

    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_2) != JNI_OK) {
        return JNI_EVERSION; /* JNI version not supported */
    }

    sysConfCls = (*env)->FindClass(env,"java/security/SystemConfigurator");
    if (sysConfCls == NULL) {
        printf("libsystemconf: SystemConfigurator class not found\n");
        return JNI_ERR;
    }
    sdebugFld = (*env)->GetStaticFieldID(env, sysConfCls,
            "sdebug", "Lsun/security/util/Debug;");
    if (sdebugFld == NULL) {
        printf("libsystemconf: SystemConfigurator::sdebug field not found\n");
        return JNI_ERR;
    }
    debugObj = (*env)->GetStaticObjectField(env, sysConfCls, sdebugFld);
    if (debugObj != NULL) {
        debugCls = (*env)->FindClass(env,"sun/security/util/Debug");
        if (debugCls == NULL) {
            printf("libsystemconf: Debug class not found\n");
            return JNI_ERR;
        }
        debugPrintlnMethodID = (*env)->GetMethodID(env, debugCls,
                "println", "(Ljava/lang/String;)V");
        if (debugPrintlnMethodID == NULL) {
            printf("libsystemconf: Debug::println(String) method not found\n");
            return JNI_ERR;
        }
        debugObj = (*env)->NewGlobalRef(env, debugObj);
    }

#ifdef SYSCONF_NSS
    getSystemFIPSEnabled = *SECMOD_GetSystemFIPSEnabled;
#else
    if (loadNSS(env) == JNI_FALSE) {
      dbgPrint(env, "libsystemconf: Failed to load NSS library.");
    }
#endif

    return (*env)->GetVersion(env);
}

/*
 * Class:     java_security_SystemConfigurator
 * Method:    JNI_OnUnload
 */
JNIEXPORT void JNICALL DEF_JNI_OnUnload(JavaVM *vm, void *reserved)
{
    JNIEnv *env;

    if (debugObj != NULL) {
        if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_2) != JNI_OK) {
            return; /* Should not happen */
        }
#ifndef SYSCONF_NSS
        closeNSS(env);
#endif
        (*env)->DeleteGlobalRef(env, debugObj);
    }
}

JNIEXPORT jboolean JNICALL Java_java_security_SystemConfigurator_getSystemFIPSEnabled
  (JNIEnv *env, jclass cls)
{
    int fips_enabled;
    char msg[MSG_MAX_SIZE];
    int msg_bytes;

    if (getSystemFIPSEnabled != NULL) {
      dbgPrint(env, "getSystemFIPSEnabled: calling SECMOD_GetSystemFIPSEnabled");
      fips_enabled = (*getSystemFIPSEnabled)();
      msg_bytes = snprintf(msg, MSG_MAX_SIZE, "getSystemFIPSEnabled:"   \
                           " SECMOD_GetSystemFIPSEnabled returned 0x%x", fips_enabled);
      handle_msg(env, msg, msg_bytes);
      return (fips_enabled == 1 ? JNI_TRUE : JNI_FALSE);
    } else {
      FILE *fe;

      dbgPrint(env, "getSystemFIPSEnabled: reading " FIPS_ENABLED_PATH);
      if ((fe = fopen(FIPS_ENABLED_PATH, "r")) == NULL) {
        throwIOException(env, "Cannot open " FIPS_ENABLED_PATH);
        return JNI_FALSE;
      }
      fips_enabled = fgetc(fe);
      fclose(fe);
      if (fips_enabled == EOF) {
        throwIOException(env, "Cannot read " FIPS_ENABLED_PATH);
        return JNI_FALSE;
      }
      msg_bytes = snprintf(msg, MSG_MAX_SIZE, "getSystemFIPSEnabled:"   \
                           " read character is '%c'", fips_enabled);
      handle_msg(env, msg, msg_bytes);
      return (fips_enabled == '1' ? JNI_TRUE : JNI_FALSE);
    }
}
