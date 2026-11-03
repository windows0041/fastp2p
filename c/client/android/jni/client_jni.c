#include "fastp2p.h"
#include "bootstrap.h"
#include "update.h"
#include <jni.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    JavaVM *vm;
    jobject listener;
    jmethodID callback;
    fastp2p_client *client;
    int callback_failed;
} binding;

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
    return (jlong)(intptr_t)b;
}

JNIEXPORT jint JNICALL Java_top_fastp2p_cclient_NativeClient_start(JNIEnv *env, jclass cls,
                                                                      jlong handle) {
    (void)env;
    (void)cls;
    binding *b = (binding *)(intptr_t)handle;
    return b ? fastp2p_client_start(b->client) : FASTP2P_EINVAL;
}
JNIEXPORT jint JNICALL Java_top_fastp2p_cclient_NativeClient_step(JNIEnv *env, jclass cls,
                                                                     jlong handle) {
    (void)env;
    (void)cls;
    binding *b = (binding *)(intptr_t)handle;
    if (!b)
        return FASTP2P_EINVAL;
    int rv = fastp2p_client_step(b->client, 10);
    return b->callback_failed ? FASTP2P_EIO : rv;
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
JNIEXPORT void JNICALL Java_top_fastp2p_cclient_NativeClient_setUpdateDir(JNIEnv *env, jclass cls,
                                                                         jstring directory) {
    (void)cls;
    if (!directory)
        return;
    const char *text = (*env)->GetStringUTFChars(env, directory, NULL);
    if (!text)
        return;
    /* Android cannot replace its own package, so the app supplies a writable
     * directory for the library to stage a verified download. */
    fp_update_set_dir(text);
    (*env)->ReleaseStringUTFChars(env, directory, text);
}
