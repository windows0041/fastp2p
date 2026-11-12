/* Optional microbenchmark of the actual private QUIC callback and frame encoder.
 * Include their implementations so accounting sees only these buffers, without
 * interposing on OpenSSL/ngtcp2 allocations or changing production interfaces.
 * This measures buffer work, not end-to-end network throughput. */
#include "platform.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t shifted, copied, allocations, reallocations;
static void *bench_move(void *out,const void *in,size_t n) { shifted+=n;return memmove(out,in,n); }
static void *bench_copy(void *out,const void *in,size_t n) { copied+=n;return memcpy(out,in,n); }
static void *bench_alloc(size_t n) { ++allocations;return malloc(n); }
static void *bench_realloc(void *p,size_t n) { ++reallocations;return realloc(p,n); }
#define memmove bench_move
#define memcpy bench_copy
#define malloc bench_alloc
#define realloc bench_realloc
#include "../src/quic.c"
#include "../src/wire.c"
#undef memmove
#undef memcpy
#undef malloc
#undef realloc

int main(int argc,char **argv) {
    if(argc>2 || (argc==2 && strcmp(argv[1],"--typical"))){
        fputs("usage: bench-buffers [--typical]\n",stderr);return 2;
    }
    size_t total=argc==2?65536:QLIMIT,read_chunk=argc==2?16384:1024;
    size_t batches=argc==2?1000:1;
    uint8_t *input=malloc(QLIMIT),out[16384];assert(input);
    for(size_t i=0;i<QLIMIT;i++)input[i]=(uint8_t)(i*17u+3u);
    opq q={0};
    shifted=copied=allocations=reallocations=0;
    uint64_t drain_ns=0;
    for(size_t batch=0;batch<batches;batch++){
        for(size_t offset=0;offset<total;){
            size_t length=total-offset;if(length>1200)length=1200;
            assert(!receive_stream(NULL,0,0,offset,input+offset,length,&q,NULL));offset+=length;
        }
        uint64_t begin=op_monotonic_ns();size_t used=0,n;
        while((n=opq_read(&q,out,read_chunk))){
            assert(!memcmp(out,input+used,n));used+=n;
        }
        drain_ns+=op_monotonic_ns()-begin;
        assert(used==total);
    }
    printf("{\"quic_bytes\":%zu,\"quic_read_chunk\":%zu,\"quic_batches\":%zu,\"quic_reallocations\":%llu,\"quic_shifted_bytes\":%llu,\"quic_drain_ns\":%llu,",
           total,read_chunk,batches,(unsigned long long)reallocations,(unsigned long long)shifted,(unsigned long long)drain_ns);
    free(q.rx);

    op_buffer b={0};const size_t count=100000,length=4096;
    shifted=copied=allocations=reallocations=0;uint64_t begin=op_monotonic_ns();
    for(size_t i=0;i<count;i++){
        assert(!op_frame_add(&b,4,9,input,length));
        const uint8_t *frame=b.data+b.offset;
        assert(op_u32(frame)==length && op_u16(frame+4)==4 && op_u16(frame+6)==9);
        assert(!memcmp(frame+8,input,length));op_buffer_consume(&b,length+8);
    }
    uint64_t frame_ns=op_monotonic_ns()-begin;
    printf("\"frame_count\":%zu,\"frame_payload\":%zu,\"frame_allocations\":%llu,\"frame_copied_bytes\":%llu,\"frame_encode_ns\":%llu}\n",
           count,length,(unsigned long long)allocations,(unsigned long long)copied,(unsigned long long)frame_ns);
    op_buffer_clear(&b);free(input);return 0;
}
