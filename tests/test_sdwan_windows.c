#include "platform.h"
#include "sdwan.h"

#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
#include <string.h>

#define LOCAL "198.18.1.129"
#define PEER "198.18.1.130"
#define PEER_PORT 45391
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "Wintun test failed: %s\n", #expr); goto done; } } while (0)

static int address_exists(uint32_t address) {
    PMIB_UNICASTIPADDRESS_TABLE table;
    if (GetUnicastIpAddressTable(AF_INET, &table))
        return -1;
    int found = 0;
    for (ULONG i = 0; i < table->NumEntries; ++i)
        if (table->Table[i].Address.Ipv4.sin_addr.s_addr == htonl(address))
            found = 1;
    FreeMibTable(table);
    return found;
}

static int route_exists(uint32_t address, unsigned width) {
    PMIB_IPFORWARD_TABLE2 table;
    if (GetIpForwardTable2(AF_INET, &table))
        return -1;
    int found = 0;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const IP_ADDRESS_PREFIX *prefix = &table->Table[i].DestinationPrefix;
        if (prefix->PrefixLength == width && prefix->Prefix.Ipv4.sin_addr.s_addr == htonl(address))
            found = 1;
    }
    FreeMibTable(table);
    return found;
}

static uint16_t ip_checksum(const uint8_t *packet) {
    unsigned sum = 0;
    for (size_t i = 0; i < 20; i += 2)
        sum += (unsigned)packet[i] << 8 | packet[i + 1];
    sum = (sum & 65535) + (sum >> 16);
    return (uint16_t)~((sum & 65535) + (sum >> 16));
}

static void swap_fields(uint8_t *a, uint8_t *b, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        uint8_t value = a[i];
        a[i] = b[i];
        b[i] = value;
    }
}

int main(void) {
    const char text[] =
        "{\"Subnet\":\"198.18.1.0/24\",\"Address\":\"" LOCAL "\","
        "\"Peers\":[{\"Node\":\"wintun-test-peer\",\"Address\":\"" PEER "\",\"Routes\":[\"203.0.113.0/24\"]}]}";
    WSADATA winsock;
    if (WSAStartup(MAKEWORD(2, 2), &winsock))
        return 1;
    int success = 0;
    SOCKET socket_handle = INVALID_SOCKET;
    fp_sdwan state = {0};
    json_object *config = json_tokener_parse(text);
    const uint32_t remote = UINT32_C(0xc6120182);
    const uint32_t subnet = UINT32_C(0xcb007100);
    CHECK(config && !fp_sdwan_parse(&state, config));
    CHECK(address_exists(state.address) == 0);
    CHECK(route_exists(remote, 32) == 0 && route_exists(subnet, 24) == 0);
    const char *error = fp_sdwan_start(&state);
    if (error)
        fprintf(stderr, "%s\n", error);
    CHECK(!error && fp_sdwan_active(&state));
    CHECK(address_exists(state.address) == 1);
    CHECK(route_exists(remote, 32) == 1 && route_exists(subnet, 24) == 1);

    socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(socket_handle != INVALID_SOCKET);
    struct sockaddr_in local = {0}, peer = {0};
    local.sin_family = peer.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(state.address);
    peer.sin_addr.s_addr = htonl(remote);
    peer.sin_port = htons(PEER_PORT);
    int bound = 0;
    for (int i = 0; !bound && i < 100; ++i) {
        bound = bind(socket_handle, (const struct sockaddr *)&local, sizeof(local)) == 0;
        if (!bound) Sleep(50);
    }
    CHECK(bound);
    DWORD timeout = 3000;
    CHECK(!setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)));
    const char marker[] = "FastP2P Wintun IPv4 test";
    const int marker_length = (int)sizeof(marker);
    CHECK(sendto(socket_handle, marker, marker_length, 0,
                 (const struct sockaddr *)&peer, sizeof(peer)) == marker_length);
    uint8_t packet[FP_SDWAN_MTU];
    int length = 0;
    for (int i = 0; i < 100; ++i) {
        uint32_t from, to;
        length = fp_sdwan_read(&state, packet);
        if (length > 0 && !fp_sdwan_ipv4(packet, (size_t)length, &from, &to) &&
            from == state.address && to == remote && packet[9] == IPPROTO_UDP)
            break;
        length = 0;
        Sleep(30);
    }
    CHECK(length == 28 + marker_length && packet[0] == 0x45);
    CHECK(!memcmp(packet + 28, marker, sizeof(marker)));
    swap_fields(packet + 12, packet + 16, 4);
    swap_fields(packet + 20, packet + 22, 2);
    packet[10] = packet[11] = packet[26] = packet[27] = 0;
    uint16_t checksum = ip_checksum(packet);
    packet[10] = (uint8_t)(checksum >> 8);
    packet[11] = (uint8_t)checksum;
    fp_sdwan_write(&state, packet, (size_t)length);
    char received[sizeof(marker)];
    CHECK(recv(socket_handle, received, marker_length, 0) == marker_length);
    CHECK(!memcmp(received, marker, sizeof(marker)));
    success = 1;
done:
    if (socket_handle != INVALID_SOCKET)
        closesocket(socket_handle);
    if (fp_sdwan_active(&state)) {
        fp_sdwan_stop(&state);
        if (address_exists(state.address) || route_exists(remote, 32) || route_exists(subnet, 24)) {
            fputs("Wintun test left a configured address or route\n", stderr);
            success = 0;
        }
    }
    if (config) json_object_put(config);
    WSACleanup();
    if (success)
        puts("Wintun IPv4 packet I/O, peer and subnet routes, and cleanup passed");
    return !success;
}
