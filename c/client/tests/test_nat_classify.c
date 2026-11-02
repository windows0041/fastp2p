/* Cover the NAT mapping classification used by the punch ladder.
 * Including the translation unit keeps the production ABI unchanged. */
#include "../src/client.c"
#include <assert.h>

int main(void) {
    /* Endpoint-independent mapping: the same port answers for any destination,
     * which is what makes a punch from an arbitrary address arrive. */
    assert(nat_classify(40000, 40000, 0) == NAT_CONE);
    /* Symmetric probe that failed must not be mistaken for a predictable NAT. */
    assert(nat_classify(40000, 40001, 0) == NAT_HARD_SYM);
    /* A second local port that maps back to the first one is still cone-like. */
    assert(nat_classify(40000, 40001, 40000) == NAT_CONE);
    /* Predictable symmetric: the next mapping steps forward or backward by a
     * small amount, so a peer can spray a narrow window. */
    assert(nat_classify(40000, 41000, 40005) == NAT_EASY_SYM_INC);
    assert(nat_classify(40000, 41000, 39995) == NAT_EASY_SYM_DEC);
    assert(nat_classify(40000, 41000, 40100) == NAT_EASY_SYM_INC);
    assert(nat_classify(40000, 41000, 39900) == NAT_EASY_SYM_DEC);
    /* Random mapping: a step wider than the prediction window. */
    assert(nat_classify(40000, 41000, 40101) == NAT_HARD_SYM);
    assert(nat_classify(40000, 41000, 39899) == NAT_HARD_SYM);
    assert(nat_classify(40000, 41000, 65500) == NAT_HARD_SYM);
    /* Only the hard symmetric value feeds the relay decision. */
    assert(nat_is_hard_sym(NAT_HARD_SYM));
    assert(!nat_is_hard_sym(NAT_CONE));
    assert(!nat_is_hard_sym(NAT_EASY_SYM_INC));
    assert(!nat_is_hard_sym(NAT_EASY_SYM_DEC));
    assert(!nat_is_hard_sym(NAT_UNKNOWN));
    return 0;
}
