/* The host firewall commands are the part of the opener that breaks silently: a rule
 * named for one port while opening another, a missing family, or an interface rule that
 * forgot the interface. Render them and check each platform's shape. */

#include "firewall.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__) && !defined(__ANDROID__)
/* The same kernel has two front ends and a host may ship only one of them. The nftables
 * rendering owns a private table so it never rewrites the distribution's ruleset, and it
 * flushes that table on every start so a changed port cannot pile up rules. */
static void nftables_rendering(void) {
    char out[4096];
    assert(!fp_firewall_commands("nft", 1179, 1, "fastp2p0", out, sizeof(out)));
    assert(strstr(out, "add table inet fastp2p"));
    assert(strstr(out, "flush chain inet fastp2p input"));
    assert(strstr(out, "nft add rule inet fastp2p input tcp dport 1179 accept"));
    assert(strstr(out, "nft add rule inet fastp2p input udp dport 1179 accept"));
    assert(strstr(out, "iifname \"fastp2p0\" accept"));
    /* One inet table covers both families, so there is no ip6tables equivalent. */
    assert(!strstr(out, "ip6tables"));
    /* The accept verdict has to run before the host policy. */
    assert(strstr(out, "priority -10"));
    /* TCP only: the rendering must not open UDP or the overlay. */
    assert(!fp_firewall_commands("nft", 1179, 0, NULL, out, sizeof(out)));
    assert(!strstr(out, "udp dport") && !strstr(out, "fastp2p0"));
    /* An unknown front end is a programming error, not a reason to run something else. */
    assert(fp_firewall_commands("pf", 1179, 1, NULL, out, sizeof(out)) == -1);
    /* The iptables rendering is still available when it is asked for by name. */
    assert(!fp_firewall_commands("iptables", 1179, 1, NULL, out, sizeof(out)));
    assert(strstr(out, "iptables -C INPUT"));
}
#endif

int main(void) {
    char out[4096];
    assert(!fp_firewall_commands(NULL, 1179, 1, "fastp2p0", out, sizeof(out)));
#if defined(_WIN32)
    assert(strstr(out, "FastP2P TCP 1179"));
    assert(strstr(out, "FastP2P UDP 1179"));
    assert(strstr(out, "New-NetFirewallRule"));
    /* Only what is missing gets created, so a restart does not churn the policy. */
    assert(strstr(out, "-notcontains"));
    assert(strstr(out, "FastP2P overlay (fastp2p0)"));
    assert(strstr(out, "InterfaceAlias 'fastp2p0'"));
    /* The punch dials and listens on ephemeral ports, so the program itself has to be
     * allowed: a rule that only names the service port blocks every punch packet. */
    assert(strstr(out, "FastP2P program"));
    assert(strstr(out, "-Program '"));
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
    assert(!strstr(out, "inet fastp2p"));
#endif

    /* TCP only: requested without UDP, the rendering must not open UDP. */
    assert(!fp_firewall_commands(NULL, 1179, 0, NULL, out, sizeof(out)));
#if !defined(_WIN32) && !defined(__APPLE__)
    assert(!strstr(out, "-p udp"));
#endif
#if !defined(__APPLE__)
    assert(!strstr(out, "fastp2p0"));
#endif

#if defined(__linux__) && !defined(__ANDROID__)
    nftables_rendering();
#endif
    /* No port means no rule at all. */
    char detail[64];
    assert(fp_firewall_open(0, 1, NULL, detail, sizeof(detail)) == FP_FIREWALL_ABSENT);
    puts("firewall command rendering");
    return 0;
}
