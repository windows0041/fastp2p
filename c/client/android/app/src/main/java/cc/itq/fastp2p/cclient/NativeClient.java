package cc.itq.fastp2p.cclient;

final class NativeClient {
    static { System.loadLibrary("fastp2p_jni"); }
    private NativeClient() {}
    static native long create(byte[] jsonUtf8, String decimalToken, String caPath, Object listener);
    static native int start(long handle);
    static native int step(long handle);
    static native void destroy(long handle);
    static native String version();
    static native String bootstrap();
}
