#ifndef FASTP2P_UTF8_H
#define FASTP2P_UTF8_H
#include <stddef.h>
#include <stdint.h>
/* Unicode scalar UTF-8, excluding overlong encodings and surrogate codepoints. */
static inline int fp_utf8_valid(const unsigned char *data,size_t len) {
    for(size_t i=0;i<len;) {
        unsigned lead=data[i++],remaining;uint32_t value,minimum;
        if(lead<0x80)continue;
        if(lead>=0xc2&&lead<=0xdf) {remaining=1;value=lead&0x1f;minimum=0x80;}
        else if(lead>=0xe0&&lead<=0xef) {remaining=2;value=lead&0x0f;minimum=0x800;}
        else if(lead>=0xf0&&lead<=0xf4) {remaining=3;value=lead&7;minimum=0x10000;}
        else return 0;
        if(remaining>len-i)return 0;
        while(remaining--) {unsigned next=data[i++];if((next&0xc0)!=0x80)return 0;value=(value<<6)|(next&0x3f);}
        if(value<minimum||value>0x10ffff||(value>=0xd800&&value<=0xdfff))return 0;
    }
    return 1;
}
#endif
