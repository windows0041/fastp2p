/* Exercise ngtcp2's actual receive callback without requiring a live connection.
 * Real QUIC/TCP/SOCKS integration tests cover the transport and flow-control API. */
#include <assert.h>
#include <stdlib.h>
static int fail_allocation;
static void *receive_malloc(size_t n) {
    if(fail_allocation){fail_allocation=0;return NULL;}
    return malloc(n);
}
static void *receive_realloc(void *p,size_t n) {
    if(fail_allocation){fail_allocation=0;return NULL;}
    return realloc(p,n);
}
#define malloc receive_malloc
#define realloc receive_realloc
#include "../src/quic.c"
#undef malloc
#undef realloc

static uint8_t value(size_t offset) { return (uint8_t)(offset ^ (offset >> 8)); }
static void append(opq *q,size_t *produced,size_t n) {
    uint8_t input[8192];assert(n<=sizeof(input));
    for(size_t i=0;i<n;i++)input[i]=value(*produced+i);
    assert(!receive_stream(NULL,0,0,*produced,input,n,q,NULL));
    *produced+=n;
    assert(q->rxlen<=QLIMIT && q->rxcap<=QLIMIT);
}
static void consume(opq *q,size_t *consumed,size_t n) {
    uint8_t output[8192];assert(n<=sizeof(output));
    size_t got=opq_read(q,output,n);
    for(size_t i=0;i<got;i++)assert(output[i]==value(*consumed+i));
    *consumed+=got;
}
int main(void) {
    opq q={0};size_t produced=0,consumed=0;
    uint8_t first[4096]={0};fail_allocation=1;
    assert(receive_stream(NULL,0,0,0,first,sizeof(first),&q,NULL)==NGTCP2_ERR_CALLBACK_FAILURE);
    assert(!q.rx && !q.rxlen && !q.rxcap);
    /* Invalid stream/0-RTT checks must not be masked by a full receive window. */
    assert(receive_stream(NULL,0,4,0,first,1,&q,NULL)==NGTCP2_ERR_CALLBACK_FAILURE);
    assert(receive_stream(NULL,NGTCP2_STREAM_DATA_FLAG_0RTT,0,0,first,1,&q,NULL)==NGTCP2_ERR_CALLBACK_FAILURE);
    assert(!q.rx && !q.rxlen && !q.rxcap);
    assert(!opq_read(&q,NULL,0));
    assert(!receive_stream(NULL,0,0,0,NULL,0,&q,NULL));
    /* Fill, partially drain, wrap the tail, then grow with unread wrapped data. */
    append(&q,&produced,3000);consume(&q,&consumed,2500);
    append(&q,&produced,2000);
    fail_allocation=1;
    assert(receive_stream(NULL,0,0,produced,first,sizeof(first),&q,NULL)==NGTCP2_ERR_CALLBACK_FAILURE);
    assert(q.rxlen==2500);
    append(&q,&produced,4096);
    while(q.rxlen)consume(&q,&consumed,113);
    assert(consumed==produced);
    /* Reuse the same storage after draining; vary reads/writes over many wraps. */
    uint32_t random=12345;
    for(unsigned i=0;i<10000;i++){
        random=random*1664525u+1013904223u;
        append(&q,&produced,random%4097);
        random=random*1664525u+1013904223u;
        consume(&q,&consumed,random%8193);
        if(q.rxlen>65536)while(q.rxlen)consume(&q,&consumed,8192);
    }
    while(q.rxlen)consume(&q,&consumed,8192);
    assert(consumed==produced);
    /* A full receive window rejects extra bytes without corrupting queued data. */
    for(size_t i=0;i<QLIMIT/8192;i++)append(&q,&produced,8192);
    uint8_t extra=0;
    assert(receive_stream(NULL,0,0,produced,&extra,1,&q,NULL)==NGTCP2_ERR_CALLBACK_FAILURE);
    assert(receive_stream(NULL,0,4,produced,&extra,1,&q,NULL)==NGTCP2_ERR_CALLBACK_FAILURE);
    assert(receive_stream(NULL,NGTCP2_STREAM_DATA_FLAG_0RTT,0,produced,&extra,1,&q,NULL)==NGTCP2_ERR_CALLBACK_FAILURE);
    while(q.rxlen)consume(&q,&consumed,257);
    assert(consumed==produced && !opq_read(&q,NULL,0));
    free(q.rx);
    puts("QUIC receive order, wraparound, wrapped growth, allocation failure, reuse and receive-window limits passed");
    return 0;
}
