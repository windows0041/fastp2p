/* A small terminal + message-box experience for the double-clicked installer.
 *
 * Explorer starts the GUI subsystem exe with no console, so the elevated copy
 * allocates one, prints its progress in UTF-8, and finishes with a native result
 * dialog. Pressing OK returns from the dialog and the process exits, which closes
 * the console automatically: no "press any key" prompt is needed.
 */
#include "install.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>

static int console_owned;

static int stream_missing(FILE *stream) {
    int descriptor = _fileno(stream);
    if (descriptor < 0) return 1;
    intptr_t handle = _get_osfhandle(descriptor);
    return handle == -1 || handle == -2;
}

void fastp2p_console_prepare(int argc, char **argv) {
    if (argc > 1 && (!strcmp(argv[1], "service") || !strcmp(argv[1], "--apply-update")))
        return;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--")) break;
        if (!strcmp(argv[i], "--background") || !strcmp(argv[i], "-background") || !strcmp(argv[i], "-b"))
            return;
    }
    /* Capture CRT state before attaching: AttachConsole may replace Win32
     * standard handles. Preserve inherited pipes/files used by CLI automation. */
    int input_missing = stream_missing(stdin);
    int output_missing = stream_missing(stdout);
    int error_missing = stream_missing(stderr);
    if (!GetConsoleWindow() && !AttachConsole(ATTACH_PARENT_PROCESS))
        return;
    if (input_missing) (void)freopen("CONIN$", "r", stdin);
    if (output_missing) (void)freopen("CONOUT$", "w", stdout);
    if (error_missing) (void)freopen("CONOUT$", "w", stderr);
}

static WCHAR *utf8_to_wide(const char *text, WCHAR *buffer, size_t count) {
    if (!MultiByteToWideChar(CP_UTF8, 0, text, -1, buffer, (int)count))
        buffer[0] = 0;
    return buffer;
}

void fastp2p_installer_ui_begin(void) {
    /* Reuse a console when launched from a shell; otherwise create one. */
    if (!GetConsoleWindow()) {
        if (AllocConsole())
            console_owned = 1;
    }
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitleW(L"fastp2p installer");
    /* freopen keeps the standard handles working for mingw and MSVC alike. */
    if (freopen("CONOUT$", "w", stdout))
        setvbuf(stdout, NULL, _IONBF, 0);
    if (freopen("CONOUT$", "w", stderr))
        setvbuf(stderr, NULL, _IONBF, 0);
    fputs("============================================\n"
          "  fastp2p Windows installer\n"
          "============================================\n", stdout);
}

void fastp2p_install_step(const char *text) {
    if (text) {
        fputs(text, stdout);
        fputc('\n', stdout);
        fflush(stdout);
    }
    fastp2p_install_note(text ? text : "");
}

int fastp2p_installer_ui_result(int ok, const char *title, const char *detail) {
    WCHAR wide_title[256], wide_text[1024];
    utf8_to_wide(title ? title : "fastp2p", wide_title, 256);
    utf8_to_wide(detail ? detail : "", wide_text, 1024);
    MessageBoxW(NULL, wide_text, wide_title,
                MB_OK | MB_SETFOREGROUND | (ok ? MB_ICONINFORMATION : MB_ICONERROR));
    if (console_owned)
        FreeConsole();
    return 0;
}

#else

void fastp2p_console_prepare(int argc, char **argv) { (void)argc; (void)argv; }
void fastp2p_installer_ui_begin(void) {}
void fastp2p_install_step(const char *text) { fastp2p_install_note(text ? text : ""); }
int fastp2p_installer_ui_result(int ok, const char *title, const char *detail) {
    (void)ok; (void)title; (void)detail;
    return 0;
}

#endif
