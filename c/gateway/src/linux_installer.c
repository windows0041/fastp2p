#include "linux_installer.h"
#include "linux_installer_assets.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static void hex(const unsigned char digest[32], char output[65]) {
    static const char digits[]="0123456789abcdef";
    for (unsigned i=0;i<32;i++) { output[2*i]=digits[digest[i]>>4];output[2*i+1]=digits[digest[i]&15]; }
    output[64]=0;
}
int gw_linux_installer(const char *directory, const char *payload, const char *sha,
                       uint64_t size, char path[700]) {
    if (!sha || strlen(sha)!=64 || strspn(sha,"0123456789abcdef")!=64 || !size || size>128u*1024u*1024u)
        return -1;
    char *prefix=NULL; size_t length=0;
    FILE *memory=open_memstream(&prefix,&length);
    if (!memory) return -1;
    const char marker[]="@@FASTP2P_CONTROLLER@@\n";
    const char *position=strstr(linux_install_script,marker);
    if (!position) { fclose(memory);free(prefix);return -1; }
    fprintf(memory,"#!/bin/sh\nexpected_sha='%s'\nexpected_size=%" PRIu64 "\n",sha,size);
    fwrite(linux_install_script,1,(size_t)(position-linux_install_script),memory);
    fputs("cat > \"$work/fastp2p-service\" <<'FASTP2P_SERVICE_EOF'\n",memory);
    fputs(linux_service_script,memory);
    fputs("\nFASTP2P_SERVICE_EOF\n",memory);
    fputs(position+sizeof(marker)-1,memory);
    if (fclose(memory)) { free(prefix);return -1; }
    unsigned char digest[32];unsigned count=0;char template_sha[65];
    if (!EVP_Digest(prefix,length,digest,&count,EVP_sha256(),NULL) || count!=32) { free(prefix);return -1; }
    hex(digest,template_sha);
    if (snprintf(path,700,"%s/installer-%s-%s.sh",directory,template_sha,sha)>=700) { free(prefix);return -1; }
    char lock_path[700];snprintf(lock_path,sizeof(lock_path),"%s/.release.lock",directory);
    int lock=open(lock_path,O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if (lock<0 || flock(lock,LOCK_EX|LOCK_NB)) { if(lock>=0)close(lock);free(prefix);return -1; }
    struct stat metadata;
    if (!lstat(path,&metadata) && S_ISREG(metadata.st_mode) && (uint64_t)metadata.st_size==length+size) {
        close(lock);free(prefix);return 0;
    }
    int input=open(payload,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (input<0 || fstat(input,&metadata) || !S_ISREG(metadata.st_mode) || (uint64_t)metadata.st_size!=size) {
        if(input>=0)close(input);close(lock);free(prefix);return -1;
    }
    char temporary[700];
    if (snprintf(temporary,sizeof(temporary),"%s/.installer-XXXXXX",directory)>=(int)sizeof(temporary)) {
        close(input);close(lock);free(prefix);return -1;
    }
    int output=mkstemp(temporary);
    FILE *source=fdopen(input,"rb"),*destination=output>=0?fdopen(output,"wb"):NULL;
    EVP_MD_CTX *hash=EVP_MD_CTX_new();int ok=0;
    if (!source || !destination || !hash || EVP_DigestInit_ex(hash,EVP_sha256(),NULL)!=1) goto done;
    if (fwrite(prefix,1,length,destination)!=length) goto done;
    char buffer[65536];size_t used;uint64_t total=0;
    while ((used=fread(buffer,1,sizeof(buffer),source))) {
        total+=used;
        if (total>size || fwrite(buffer,1,used,destination)!=used || EVP_DigestUpdate(hash,buffer,used)!=1) goto done;
    }
    if (ferror(source) || total!=size || EVP_DigestFinal_ex(hash,digest,&count)!=1 || count!=32) goto done;
    char actual[65];hex(digest,actual);
    if (strcmp(actual,sha) || fflush(destination) || fsync(output)) goto done;
    ok=1;
done:
    if(hash)EVP_MD_CTX_free(hash);
    if(source)fclose(source);else close(input);
    if(destination) { if(fclose(destination))ok=0; } else if(output>=0)close(output);
    if (ok && rename(temporary,path)) ok=0;
    if(!ok)unlink(temporary);
    close(lock);free(prefix);return ok?0:-1;
}
