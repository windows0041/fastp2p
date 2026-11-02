/* The punch cadence and mapping classification are pure decisions, so they can
 * be checked without a socket. */
#include "../src/client.c"
#include <assert.h>

int main(void) {
    /* Dense start: the first half second decides a cone-to-cone punch. */
    assert(punch_interval(0) == 50 * MS);
    assert(punch_interval(100 * MS) == 50 * MS);
    assert(punch_interval(499 * MS) == 50 * MS);
    /* Then the steady cadence keeps both mappings alive. */
    assert(punch_interval(500 * MS) == 200 * MS);
    assert(punch_interval(9 * NS) == 200 * MS);

    /* Mapping classification. */
    assert(nat_classify(40000, 40000, 0) == NAT_CONE);
    assert(nat_classify(40000, 40001, 0) == NAT_HARD_SYM);
    assert(nat_classify(40000, 40001, 40000) == NAT_CONE);
    assert(nat_classify(40000, 41000, 40005) == NAT_EASY_SYM_INC);
    assert(nat_classify(40000, 41000, 39995) == NAT_EASY_SYM_DEC);
    assert(nat_classify(40000, 41000, 40101) == NAT_HARD_SYM);
    assert(nat_classify(40000, 41000, 39899) == NAT_HARD_SYM);

    /* Only the hard symmetric value feeds the relay decision. */
    assert(nat_is_hard_sym(NAT_HARD_SYM));
    assert(!nat_is_hard_sym(NAT_CONE));
    assert(!nat_is_hard_sym(NAT_EASY_SYM_INC));
    assert(!nat_is_hard_sym(NAT_EASY_SYM_DEC));
    assert(!nat_is_hard_sym(NAT_UNKNOWN));
    return 0;
}
