#include "fastp2p.h"
#include "../../src/rule_update.h"
#include "bootstrap.h"
#include <jni.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    JavaVM *vm;
    jobject listener;
    jmethodID callback;
    jmethodID config_callback;
    fastp2p_client *client;
    fp_rule_update *rule_update;
    int receiving_config;
    int callback_failed;
    int restart_requested;
} binding;

enum { STEP_RESTART_REQUESTED = 1 };

static void request_restart(void *user) {
    binding *b = user;
    b->restart_requested = 1;
}

static int receive_config(const char *fields, uint64_t revision, void *user) {
    binding *b = user;
    JNIEnv *env = NULL;
    size_t size = strlen(fields);
    if (size > 65536 || (*b->vm)->GetEnv(b->vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
        return FASTP2P_EINVAL;
    jbyteArray json = (*env)->NewByteArray(env, (jsize)size);
    if (json)
        (*env)->SetByteArrayRegion(env, json, 0, (jsize)size, (const jbyte *)fields);
    int result = FASTP2P_EIO;
    if (json && !(*env)->ExceptionCheck(env)) {
        b->receiving_config = 1;
        result = (*env)->CallIntMethod(env, b->listener, b->config_callback,
                                      (jlong)(intptr_t)b, json, (jlong)revision);
        b->receiving_config = 0;
    }
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        result = FASTP2P_EIO;
    }
    if (b->rule_update) {
        if (result == FASTP2P_OK)
            fp_client_rules_commit(b->rule_update);
        else
            fp_client_rules_abort(b->rule_update);
        b->rule_update = NULL;
    }
    if (json)
        (*env)->DeleteLocalRef(env, json);
    return result;
}

static void notify(fastp2p_client *client, const fastp2p_event *event, void *user) {
    (void)client;
    binding *b = user;
    JNIEnv *env = NULL;
    if ((*b->vm)->GetEnv(b->vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        b->callback_failed = 1;
        return;
    }
    char id[32];
    snprintf(id, sizeof(id), "%" PRIu64, event->id);
    jstring jid = (*env)->NewStringUTF(env, id);
    jstring message = (*env)->NewStringUTF(env, event->message ? event->message : "");
    if (jid && message)
        (*env)->CallVoidMethod(env, b->listener, b->callback, (jint)event->type, (jint)event->state,
                               (jint)event->code, jid, message);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        b->callback_failed = 1;
    }
    if (jid)
        (*env)->DeleteLocalRef(env, jid);
    if (message)
        (*env)->DeleteLocalRef(env, message);
}

JNIEXPORT jlong JNICALL Java_top_fastp2p_cclient_NativeClient_create(JNIEnv *env, jclass type,
                                                                        jbyteArray json,
                                                                        jstring token, jstring ca,
                                                                        jobject listener) {
    (void)type;
    if (!json || !token || !listener)
        return 0;
    jsize length = (*env)->GetArrayLength(env, json);
    if (length <= 0 || length > 1024 * 1024)
        return 0;
    binding *b = calloc(1, sizeof(*b));
    char *text = malloc((size_t)length + 1);
    if (!b || !text) {
        free(b);
        free(text);
        return 0;
    }
    (*env)->GetByteArrayRegion(env, json, 0, length, (jbyte *)text);
    text[length] = 0;
    if ((*env)->ExceptionCheck(env) || memchr(text, 0, (size_t)length)) {
        free(text);
        free(b);
        return 0;
    }
    (*env)->GetJavaVM(env, &b->vm);
    b->listener = (*env)->NewGlobalRef(env, listener);
    jclass cls = (*env)->GetObjectClass(env, listener);
    b->callback = (*env)->GetMethodID(env, cls, "onNativeEvent",
                                      "(IIILjava/lang/String;Ljava/lang/String;)V");
    (*env)->DeleteLocalRef(env, cls);
    const char *secret = (*env)->GetStringUTFChars(env, token, NULL);
    const char *certificate = ca ? (*env)->GetStringUTFChars(env, ca, NULL) : NULL;
    int result = FASTP2P_EINVAL;
    if (b->listener && b->callback && secret && (!ca || certificate))
        result = fastp2p_client_create_json(text, secret, certificate, notify, b, &b->client);
    if (secret)
        (*env)->ReleaseStringUTFChars(env, token, secret);
    if (certificate)
        (*env)->ReleaseStringUTFChars(env, ca, certificate);
    free(text);
    if (result) {
        if (b->listener)
            (*env)->DeleteGlobalRef(env, b->listener);
        free(b);
        return 0;
    }
    fastp2p_client_set_restart_handler(b->client, request_restart, b);
    return (jlong)(intptr_t)b;
}

JNIEXPORT jint JNICALL Java_top_fastp2p_cclient_NativeClient_start(JNIEnv *env, jclass cls,
                                                                      jlong handle) {
    (void)env;
    (void)cls;
    binding *b = (binding *)(intptr_t)handle;
    return b ? fastp2p_client_start(b->client) : FASTP2P_EINVAL;
}

JNIEXPORT jint JNICALL Java_top_fastp2p_cclient_NativeClient_attachSdwanTun(
    JNIEnv *env, jclass cls, jlong handle, jint fd) {
    (void)env;
    (void)cls;
    binding *b = (binding *)(intptr_t)handle;
    return b ? fastp2p_client_attach_sdwan_tun(b->client, fd) : FASTP2P_EINVAL;
}

JNIEXPORT jint JNICALL Java_top_fastp2p_cclient_NativeClient_enableConfigPush(
    JNIEnv *env, jclass cls, jlong handle) {
    (void)cls;
    binding *b = (binding *)(intptr_t)handle;
    if (!b)
        return FASTP2P_EINVAL;
    jclass listener = (*env)->GetObjectClass(env, b->listener);
    b->config_callback = (*env)->GetMethodID(env, listener, "onGatewayConfig", "(J[BJ)I");
    (*env)->DeleteLocalRef(env, listener);
    return b->config_callback ? fastp2p_client_set_config_handler(b->client, receive_config, b)
                              : FASTP2P_EINVAL;
}
JNIEXPORT jint JNICALL Java_top_fastp2p_cclient_NativeClient_prepareGatewayRules(
    JNIEnv *env, jclass cls, jlong handle, jbyteArray json) {
    (void)cls;
    binding *b = (binding *)(intptr_t)handle;
    if (!b || !b->receiving_config || b->rule_update || !json)
        return FASTP2P_ESTATE;
    jsize length = (*env)->GetArrayLength(env, json);
    if (length <= 0 || length > 1024 * 1024)
        return FASTP2P_EINVAL;
    char *text = malloc((size_t)length + 1);
    if (!text)
        return FASTP2P_ENOMEM;
    (*env)->GetByteArrayRegion(env, json, 0, length, (jbyte *)text);
    text[length] = 0;
    int result = FASTP2P_EINVAL;
    if (!(*env)->ExceptionCheck(env) && !memchr(text, 0, (size_t)length))
        result = fp_client_rules_prepare(b->client, text, &b->rule_update);
    free(text);
    return result;
}
JNIEXPORT jint JNICALL Java_top_fastp2p_cclient_NativeClient_step(JNIEnv *env, jclass cls,
                                                                     jlong handle) {
    (void)env;
    (void)cls;
    binding *b = (binding *)(intptr_t)handle;
    if (!b)
        return FASTP2P_EINVAL;
    int rv = fastp2p_client_step(b->client, 10);
    if (b->callback_failed)
        return FASTP2P_EIO;
    return !rv && b->restart_requested ? STEP_RESTART_REQUESTED : rv;
}
JNIEXPORT jint JNICALL Java_top_fastp2p_cclient_NativeClient_publicPort(JNIEnv *env, jclass cls,
                                                                          jlong handle) {
    (void)env;
    (void)cls;
    binding *b = (binding *)(intptr_t)handle;
    return b ? fastp2p_client_public_port(b->client) : 0;
}
JNIEXPORT void JNICALL Java_top_fastp2p_cclient_NativeClient_destroy(JNIEnv *env, jclass cls,
                                                                        jlong handle) {
    (void)cls;
    binding *b = (binding *)(intptr_t)handle;
    if (!b)
        return;
    fastp2p_client_stop(b->client);
    fastp2p_client_destroy(b->client);
    (*env)->DeleteGlobalRef(env, b->listener);
    free(b);
}
JNIEXPORT jstring JNICALL Java_top_fastp2p_cclient_NativeClient_version(JNIEnv *env,
                                                                           jclass cls) {
    (void)cls;
    return (*env)->NewStringUTF(env, fastp2p_version());
}
JNIEXPORT jstring JNICALL Java_top_fastp2p_cclient_NativeClient_bootstrap(JNIEnv *env, jclass cls) {
    (void)cls;
    return (*env)->NewStringUTF(env, fastp2p_default_gateway());
}
