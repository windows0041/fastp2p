/* The host firewall commands are the part of the opener that breaks silently: a rule
 * named for one port while opening another, a missing family, or an interface rule that
 * forgot the interface. Render them and check each platform's shape. */

#include "firewall.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    char out[4096];
    assert(!fp_firewall_commands(1179, 1, "fastp2p0", out, sizeof(out)));
#if defined(_WIN32)
    assert(strstr(out, "FastP2P TCP 1179"));
    assert(strstr(out, "FastP2P UDP 1179"));
    assert(strstr(out, "New-NetFirewallRule"));
    /* Only what is missing gets created, so a restart does not churn the policy. */
    assert(strstr(out, "-notcontains"));
    assert(strstr(out, "FastP2P overlay (fastp2p0)"));
    assert(strstr(out, "InterfaceAlias 'fastp2p0'"));
    assert(strstr(out, "Remove-NetFirewallRule"));
#elif defined(__APPLE__)
    assert(strstr(out, "socketfilterfw --add"));
    assert(strstr(out, "socketfilterfw --unblockapp"));
#elif defined(__ANDROID__)
    assert(strstr(out, "su -c 'iptables"));
    assert(strstr(out, "--dport 1179"));
    assert(strstr(out, "-i fastp2p0"));
#else
    assert(strstr(out, "-p tcp --dport 1179 -j ACCEPT"));
    assert(strstr(out, "-p udp --dport 1179 -j ACCEPT"));
    assert(strstr(out, "-i fastp2p0 -j ACCEPT"));
    assert(strstr(out, "ip6tables"));
    /* -C before -I keeps a restart from stacking a rule per start. */
    assert(strstr(out, "-C INPUT"));
#endif

    /* TCP only: requested without UDP, the rendering must not open UDP. */
    assert(!fp_firewall_commands(1179, 0, NULL, out, sizeof(out)));
#if !defined(_WIN32) && !defined(__APPLE__)
    assert(!strstr(out, "-p udp"));
#endif
#if !defined(__APPLE__)
    assert(!strstr(out, "fastp2p0"));
#endif

    /* No port means no rule at all. */
    char detail[64];
    assert(fp_firewall_open(0, 1, NULL, detail, sizeof(detail)) == FP_FIREWALL_ABSENT);
    puts("firewall command rendering");
    return 0;
}
