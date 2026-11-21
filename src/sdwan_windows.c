#include "platform.h"
#include "sdwan.h"

#include <iphlpapi.h>
#include <netioapi.h>
#include <openssl/rand.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wintun.h>

#define WINTUN_RESOURCE 101
#define WINTUN_RING_CAPACITY (256 * 1024)

typedef struct fp_sdwan_windows {
    HMODULE library;
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    WCHAR directory[MAX_PATH];
    WCHAR dll[MAX_PATH];
    NET_LUID luid;
    unsigned routes_installed;
    int address_installed;
    WINTUN_CREATE_ADAPTER_FUNC *create_adapter;
    WINTUN_CLOSE_ADAPTER_FUNC *close_adapter;
    WINTUN_GET_ADAPTER_LUID_FUNC *get_luid;
    WINTUN_START_SESSION_FUNC *start_session;
    WINTUN_END_SESSION_FUNC *end_session;
    WINTUN_RECEIVE_PACKET_FUNC *receive_packet;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC *release_packet;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC *allocate_packet;
    WINTUN_SEND_PACKET_FUNC *send_packet;
} fp_sdwan_windows;

static const BYTE *driver_image(DWORD *size) {
    static const BYTE marker;
    HMODULE module;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)(const void *)&marker, &module))
        return NULL;
    HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(WINTUN_RESOURCE), MAKEINTRESOURCEW(10));
    if (!resource)
        return NULL;
    *size = SizeofResource(module, resource);
    HGLOBAL data = LoadResource(module, resource);
    return *size && data ? LockResource(data) : NULL;
}

static int has_admin_rights(void) {
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(sid);
    BOOL member = FALSE;
    return CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sid, &size) &&
           CheckTokenMembership(NULL, sid, &member) && member;
}

const char *fp_sdwan_check(void) {
    DWORD size;
    if (!driver_image(&size))
        return "SD-WAN requires the Windows build bundled with Wintun";
    if (!has_admin_rights())
        return "SD-WAN requires the FastP2P Windows service or an administrator terminal";
    return NULL;
}

static DWORD create_private_directory(fp_sdwan_windows *win) {
    WCHAR root[MAX_PATH], path[MAX_PATH];
    UINT length = GetSystemWindowsDirectoryW(root, MAX_PATH);
    uint32_t nonce[3];
    if (!length || length >= MAX_PATH)
        return ERROR_PATH_NOT_FOUND;
    if (RAND_bytes((unsigned char *)nonce, sizeof(nonce)) != 1)
        return ERROR_GEN_FAILURE;
    int n = swprintf(path, MAX_PATH, L"%ls\\Temp\\fastp2p-wintun-%08lx%08lx%08lx", root,
                     (unsigned long)nonce[0], (unsigned long)nonce[1], (unsigned long)nonce[2]);
    if (n < 0 || (size_t)n + sizeof(L"\\wintun.dll") / sizeof(WCHAR) > MAX_PATH)
        return ERROR_BUFFER_OVERFLOW;
    PSECURITY_DESCRIPTOR descriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, NULL))
        return GetLastError();
    SECURITY_ATTRIBUTES permissions = {sizeof(permissions), descriptor, FALSE};
    BOOL created = CreateDirectoryW(path, &permissions);
    DWORD error = created ? ERROR_SUCCESS : GetLastError();
    LocalFree(descriptor);
    if (created)
        wcscpy(win->directory, path);
    return error;
}

static DWORD load_driver(fp_sdwan_windows *win) {
    DWORD size, written = 0;
    const BYTE *image = driver_image(&size);
    if (!image)
        return ERROR_RESOURCE_DATA_NOT_FOUND;
    DWORD error = create_private_directory(win);
    if (error)
        return error;
    WCHAR path[MAX_PATH];
    int n = swprintf(path, MAX_PATH, L"%ls\\wintun.dll", win->directory);
    if (n < 0 || n >= MAX_PATH)
        return ERROR_BUFFER_OVERFLOW;
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError();
    wcscpy(win->dll, path);
    if (!WriteFile(file, image, size, &written, NULL))
        error = GetLastError();
    else if (written != size)
        error = ERROR_WRITE_FAULT;
    if (!CloseHandle(file) && !error)
        error = GetLastError();
    if (error)
        return error;
    win->library = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!win->library)
        return GetLastError();
#define BIND(member, name) do { \
    FARPROC address = GetProcAddress(win->library, "Wintun" #name); \
    if (!address) return GetLastError(); \
    memcpy(&win->member, &address, sizeof(address)); \
} while (0)
    BIND(create_adapter, CreateAdapter);
    BIND(close_adapter, CloseAdapter);
    BIND(get_luid, GetAdapterLUID);
    BIND(start_session, StartSession);
    BIND(end_session, EndSession);
    BIND(receive_packet, ReceivePacket);
    BIND(release_packet, ReleaseReceivePacket);
    BIND(allocate_packet, AllocateSendPacket);
    BIND(send_packet, SendPacket);
#undef BIND
    return ERROR_SUCCESS;
}

static MIB_UNICASTIPADDRESS_ROW address_row(const fp_sdwan *state) {
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = state->windows->luid;
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr.s_addr = htonl(state->address);
    row.OnLinkPrefixLength = 32;
    return row;
}

static MIB_IPFORWARD_ROW2 route_row(const fp_sdwan *state, const fp_sdwan_route *route) {
    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    row.InterfaceLuid = state->windows->luid;
    row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = htonl(route->network);
    row.DestinationPrefix.PrefixLength = (UINT8)route->bits;
    row.NextHop.Ipv4.sin_family = AF_INET;
    row.NextHop.Ipv4.sin_addr.s_addr = INADDR_ANY;
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    return row;
}

static DWORD configure_link(fp_sdwan *state) {
    MIB_IPINTERFACE_ROW row;
    InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET;
    row.InterfaceLuid = state->windows->luid;
    DWORD error = GetIpInterfaceEntry(&row);
    for (unsigned i = 0; i < 20 && (error == ERROR_NOT_FOUND || error == ERROR_FILE_NOT_FOUND); ++i) {
        Sleep(50);
        error = GetIpInterfaceEntry(&row);
    }
    if (error)
        return error;
    row.NlMtu = FP_SDWAN_MTU;
    /* Forward through the virtual interface when this node exports a subnet. */
    for (unsigned i = 0; i < state->route_count; ++i)
        if (state->routes[i].owner == FP_SDWAN_LOCAL && state->routes[i].network != state->address)
            row.ForwardingEnabled = TRUE;
    row.SitePrefixLength = 0;
    return SetIpInterfaceEntry(&row);
}

static DWORD assign_address(fp_sdwan *state) {
    PMIB_UNICASTIPADDRESS_TABLE table;
    DWORD error = GetUnicastIpAddressTable(AF_INET, &table);
    if (error)
        return error;
    MIB_UNICASTIPADDRESS_ROW address = address_row(state);
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        if (table->Table[i].Address.Ipv4.sin_addr.s_addr == address.Address.Ipv4.sin_addr.s_addr) {
            error = ERROR_OBJECT_ALREADY_EXISTS;
            break;
        }
    }
    FreeMibTable(table);
    return error ? error : CreateUnicastIpAddressEntry(&address);
}

static DWORD add_routes(fp_sdwan *state) {
    PMIB_IPFORWARD_TABLE2 table;
    DWORD error = GetIpForwardTable2(AF_INET, &table);
    if (error)
        return error;
    for (unsigned i = 0; !error && i < state->route_count; ++i) {
        const fp_sdwan_route *route = &state->routes[i];
        if (route->owner >= 0) {
            MIB_IPFORWARD_ROW2 row = route_row(state, route);
            for (ULONG j = 0; j < table->NumEntries; ++j) {
                const MIB_IPFORWARD_ROW2 *existing = &table->Table[j];
                if (existing->DestinationPrefix.PrefixLength == route->bits &&
                    existing->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr ==
                        row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr &&
                    existing->InterfaceLuid.Value != row.InterfaceLuid.Value) {
                    error = ERROR_OBJECT_ALREADY_EXISTS;
                    break;
                }
            }
            if (!error)
                error = CreateIpForwardEntry2(&row);
        }
        if (!error)
            state->windows->routes_installed = i + 1;
    }
    FreeMibTable(table);
    return error;
}

static const char *failure(fp_sdwan *state, const char *action, DWORD code) {
    fp_sdwan_stop(state);
    snprintf(state->error, sizeof(state->error), "SD-WAN %s (Windows error %lu)", action, (unsigned long)code);
    return state->error;
}

const char *fp_sdwan_start(fp_sdwan *state) {
    if (state->windows)
        return "SD-WAN Wintun is already active";
    const char *unsupported = fp_sdwan_check();
    if (unsupported)
        return unsupported;
    fp_sdwan_windows *win = calloc(1, sizeof(*win));
    if (!win)
        return "SD-WAN cannot allocate the Windows adapter state";
    state->windows = win;
    DWORD error = load_driver(win);
    if (error)
        return failure(state, "cannot load the bundled Wintun DLL", error);
    /* Keep Windows' network profile identity stable across service restarts. */
    static const GUID adapter_id = {0x2e865e8a, 0xe84b, 0x4c4b,
                                    {0x8c, 0xe5, 0x2a, 0x0f, 0x78, 0xe9, 0xbf, 0x31}};
    win->adapter = win->create_adapter(L"fastp2p0", L"FastP2P", &adapter_id);
    if (!win->adapter)
        return failure(state, "cannot create the Wintun adapter", GetLastError());
    win->get_luid(win->adapter, &win->luid);
    win->session = win->start_session(win->adapter, WINTUN_RING_CAPACITY);
    if (!win->session)
        return failure(state, "cannot start the Wintun packet session", GetLastError());
    error = configure_link(state);
    if (error)
        return failure(state, "cannot configure the Wintun interface", error);
    error = assign_address(state);
    if (error == ERROR_OBJECT_ALREADY_EXISTS)
        return failure(state, "virtual IPv4 address is already in use", error);
    if (error)
        return failure(state, "cannot assign the virtual IPv4 address", error);
    win->address_installed = 1;
    error = add_routes(state);
    if (error == ERROR_OBJECT_ALREADY_EXISTS)
        return failure(state, "route conflicts with an existing Windows route", error);
    if (error)
        return failure(state, "cannot install the Windows routes", error);
    return NULL;
}

void fp_sdwan_stop(fp_sdwan *state) {
    fp_sdwan_windows *win = state->windows;
    if (!win)
        return;
    for (unsigned i = 0; i < win->routes_installed; ++i) {
        if (state->routes[i].owner < 0)
            continue;
        MIB_IPFORWARD_ROW2 row = route_row(state, &state->routes[i]);
        (void)DeleteIpForwardEntry2(&row);
    }
    if (win->address_installed) {
        MIB_UNICASTIPADDRESS_ROW row = address_row(state);
        (void)DeleteUnicastIpAddressEntry(&row);
    }
    if (win->session)
        win->end_session(win->session);
    if (win->adapter)
        win->close_adapter(win->adapter);
    if (win->library)
        FreeLibrary(win->library);
    if (*win->dll)
        DeleteFileW(win->dll);
    if (*win->directory)
        RemoveDirectoryW(win->directory);
    free(win);
    state->windows = NULL;
}

int fp_sdwan_read(fp_sdwan *state, uint8_t packet[FP_SDWAN_MTU]) {
    fp_sdwan_windows *win = state->windows;
    if (!win || !win->session)
        return -1;
    DWORD size;
    BYTE *data = win->receive_packet(win->session, &size);
    if (!data)
        return -1;
    int length = 1; /* Let the caller skip an oversized packet and drain the next one. */
    if (size >= 20 && size <= FP_SDWAN_MTU) {
        memcpy(packet, data, size);
        length = (int)size;
    }
    win->release_packet(win->session, data);
    return length;
}

void fp_sdwan_write(fp_sdwan *state, const uint8_t *packet, size_t length) {
    fp_sdwan_windows *win = state->windows;
    if (!win || !win->session || length < 20 || length > FP_SDWAN_MTU)
        return;
    BYTE *data = win->allocate_packet(win->session, (DWORD)length);
    if (data) {
        memcpy(data, packet, length);
        win->send_packet(win->session, data);
    }
}
