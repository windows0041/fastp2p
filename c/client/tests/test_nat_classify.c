/* The punch cadence, mapping classification and symmetric window are pure
 * decisions, so they can be checked without a socket. */
#include "../src/client.c"
#include <assert.h>

int main(void) {
    /* Dense start: the first half second decides a cone-to-cone punch. */
    assert(punch_interval(0) == 50 * MS);
    assert(punch_interval(499 * MS) == 50 * MS);
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

    /* A peer with no window leaves only its observed port worth a packet. */
    assert(sym_window_cap(0) == 0);
    assert(sym_window_base(40000, 0, 0) == 40000);

    /* Window cap keeps a peer from asking for an unbounded burst. */
    assert(sym_window_cap(200) == SYM_WINDOW_MAX);
    assert(sym_window_cap(SYM_WINDOW_MAX) == SYM_WINDOW_MAX);

    /* Incrementing window starts just above the observed port, and stops at
     * the end of the range instead of wrapping onto unrelated ports. */
    assert(sym_window_span(65530, 1, 50) == 5);
    assert(sym_window_base(65530, 1, 50) == 65531);
    /* Decrementing never reaches port 0. */
    assert(sym_window_span(1, 0, 50) == 0);
    assert(sym_window_base(1, 0, 50) == 1);
    assert(sym_window_span(20, 0, 50) == 19);
    /* Downward window starts at observed-1 and walks down, so it covers the
     * ports nearest the observed mapping rather than a span below it. */
    assert(sym_window_base(20, 0, 50) == 19);
    assert(sym_window_base(40000, 0, 50) == 39999);
    /* Decrementing window starts count ports below it, never below 1. */
    assert(sym_window_base(40000, 1, 50) == 40001);

    /* Punch ladder budget: a hard symmetric side wastes the second round. */
    assert(direct_rounds_allowed(0, 0) == 2);
    assert(direct_rounds_allowed(1, 0) == 1);
    assert(direct_rounds_allowed(0, 1) == 1);
    assert(direct_rounds_allowed(1, 1) == 1);
    assert(direct_rounds_allowed(nat_is_hard_sym(NAT_CONE),
                                 nat_is_hard_sym(NAT_EASY_SYM_INC)) == 2);
    assert(direct_rounds_allowed(nat_is_hard_sym(NAT_EASY_SYM_DEC),
                                 nat_is_hard_sym(NAT_HARD_SYM)) == 1);

    /* Only the hard symmetric value feeds the relay decision. */
    assert(nat_is_hard_sym(NAT_HARD_SYM));
    assert(!nat_is_hard_sym(NAT_CONE));
    assert(!nat_is_hard_sym(NAT_EASY_SYM_INC));
    assert(!nat_is_hard_sym(NAT_EASY_SYM_DEC));
    assert(!nat_is_hard_sym(NAT_UNKNOWN));
    return 0;
}
