#include <fcntl.h>
#include <jni.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

JNIEXPORT jint JNICALL Java_top_fastp2p_cclient_RootTunBridge_openTun(JNIEnv *env, jclass cls) {
    (void)env;
    (void)cls;
    if (geteuid())
        return -1;
    int fd = open("/dev/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct ifreq request = {.ifr_name = "fastp2p0"};
    request.ifr_flags = (short)(IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
    if (!ioctl(fd, TUNSETIFF, &request))
        return fd;
    close(fd);
    return -1;
}
