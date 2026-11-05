#include "linux_installer.h"
#include "linux_installer_assets.h"
#include "enrollment.h"
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

const char *const gw_linux_arches[GW_LINUX_ARCH_COUNT]={
    "x86_64","aarch64","armv7","i686","riscv64","s390x","ppc64le","mips64el"
};
const char *gw_linux_payload_arch(const char *path) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return NULL;
    struct stat metadata;unsigned char h[64];
    ssize_t length=fstat(fd,&metadata) || !S_ISREG(metadata.st_mode)?-1:read(fd,h,sizeof(h));
    close(fd);
    if(length<52 || memcmp(h,"\177ELF",4) || (h[5]!=1 && h[5]!=2))return NULL;
    unsigned machine=h[5]==1?h[18]+256u*h[19]:256u*h[18]+h[19];
    if(h[4]==2 && length==64){
        if(h[5]==2)return machine==22?"s390x":NULL;
        switch(machine){
        case 62:return "x86_64"; case 183:return "aarch64"; case 243:return "riscv64";
        case 21:return "ppc64le"; case 8:return "mips64el"; default:return NULL;
        }
    }
    if(h[4]==1 && h[5]==1){
        if(machine==3)return "i686";
        if(machine==40 && (h[37]&4))return "armv7";
    }
    return NULL;
}
static int package_valid(const struct gw_linux_package *p) {
    int supported=0;
    for(size_t i=0;i<GW_LINUX_ARCH_COUNT;i++)if(p->arch && !strcmp(p->arch,gw_linux_arches[i]))supported=1;
    char platform[24];snprintf(platform,sizeof(platform),"linux-%s",p->arch?p->arch:"");
    return supported && (!strcmp(p->platform,"linux") || !strcmp(p->platform,platform)) &&
        *p->version && strspn(p->version,"0123456789.")==strlen(p->version) &&
        strlen(p->sha)==64 && strspn(p->sha,"0123456789abcdef")==64 &&
        p->size && p->size<=128u*1024u*1024u;
}
static int cached_valid(const char *path,const char *script,size_t length) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return 0;
    struct stat metadata;int ok=!fstat(fd,&metadata) && S_ISREG(metadata.st_mode) && (uint64_t)metadata.st_size==length;
    char buffer[65536];size_t offset=0;
    while(ok && offset<length){
        size_t count=length-offset;if(count>sizeof(buffer))count=sizeof(buffer);
        ssize_t used=read(fd,buffer,count);
        if(used<=0 || memcmp(buffer,script+offset,(size_t)used))ok=0;
        else offset+=(size_t)used;
    }
    close(fd);return ok;
}
int gw_linux_installer(const char *directory,const char *host,unsigned port,const char *ca,
                       const struct gw_linux_package *packages,size_t count,char path[700]) {
    if(!fastp2p_enrollment_host_valid(host) || !port || port>65535 || !ca ||
       strstr(ca,"FASTP2P_DOWNLOAD_CA_EOF") || !count || count>GW_LINUX_ARCH_COUNT)return -1;
    for(size_t i=0;i<count;i++)if(!package_valid(packages+i))return -1;
    const char controller[]="@@FASTP2P_CONTROLLER@@\n",download[]="@@FASTP2P_DOWNLOAD@@\n";
    const char *a=strstr(linux_install_script,controller),*b=strstr(linux_install_script,download);
    if(!a || !b || b<a)return -1;
    char *script=NULL;size_t length=0;
    FILE *memory=open_memstream(&script,&length);if(!memory)return -1;
    fwrite(linux_install_script,1,(size_t)(a-linux_install_script),memory);
    fputs("cat > \"$work/fastp2p-service\" <<'FASTP2P_SERVICE_EOF'\n",memory);
    fputs(linux_service_script,memory);fputs("\nFASTP2P_SERVICE_EOF\n",memory);
    a+=sizeof(controller)-1;fwrite(a,1,(size_t)(b-a),memory);
    fprintf(memory,"gateway_url='https://%s:%u'\ndownload_ca=%u\ncase \"$arch\" in\n",host,port,*ca?1:0);
    for(size_t i=0;i<count;i++){
        const struct gw_linux_package *p=packages+i;
        fprintf(memory,"    %s) package_platform='%s'; expected_version='%s'; expected_sha='%s'; expected_size=%" PRIu64 " ;;\n",
                p->arch,p->platform,p->version,p->sha,p->size);
    }
    fputs("    *) fail \"网关尚无 $arch 的安装包，请先同步对应架构的 Release。\" ;;\nesac\n",memory);
    fputs("cat > \"$work/gateway-ca.pem\" <<'FASTP2P_DOWNLOAD_CA_EOF'\n",memory);
    fputs(ca,memory);fputs("\nFASTP2P_DOWNLOAD_CA_EOF\n",memory);
    fputs(b+sizeof(download)-1,memory);
    if(fclose(memory)){free(script);return -1;}
    unsigned char digest[32];unsigned bytes=0;char template_sha[65];
    if(!EVP_Digest(script,length,digest,&bytes,EVP_sha256(),NULL) || bytes!=32){free(script);return -1;}
    for(unsigned i=0;i<32;i++)snprintf(template_sha+2*i,3,"%02x",digest[i]);
    if(snprintf(path,700,"%s/installer-%s-%s.sh",directory,template_sha,packages[0].sha)>=700){free(script);return -1;}
    char lock_path[700];snprintf(lock_path,sizeof(lock_path),"%s/.release.lock",directory);
    int lock=open(lock_path,O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if(lock<0 || flock(lock,LOCK_EX|LOCK_NB)){if(lock>=0)close(lock);free(script);return -1;}
    if(cached_valid(path,script,length)){close(lock);free(script);return 0;}
    char temporary[700];
    if(snprintf(temporary,sizeof(temporary),"%s/.installer-XXXXXX",directory)>=(int)sizeof(temporary)){
        close(lock);free(script);return -1;
    }
    int fd=mkstemp(temporary);FILE *output=fd>=0?fdopen(fd,"wb"):NULL;int ok=0;
    if(output){
        ok=fwrite(script,1,length,output)==length && !fflush(output) && !fsync(fd);
        if(fclose(output))ok=0;
    }else if(fd>=0)close(fd);
    if(ok && rename(temporary,path))ok=0;
    if(!ok)unlink(temporary);
    close(lock);free(script);return ok?0:-1;
}
