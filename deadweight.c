#include <windows.h>
#include <commctrl.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <shlwapi.h>
#include <time.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <pdh.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "comctl32.lib")

#define MAX_LOG_LENGTH 1024
#define MAX_PATH_LENGTH 32768
// --- GUI/Modern additions declarations ---
#define ID_BTN_CLEAN 1001
#define ID_BTN_SCANAPPS 1002
#define ID_LIST_APPS    1003
#define ID_BTN_CLEANSEL 1004

typedef struct {
    TCHAR path[MAX_PATH_LENGTH];
    TCHAR name[MAX_PATH];
    FILETIME lastAccess;
    BOOL unused;
} AppEntry;

AppEntry* g_appEntries = NULL;
int g_appCount = 0;
// --- GUI/Modern additions declarations ---
void purge_system(void);
void log_purge_action(const char* msg);
void scan_applications(HWND hWnd);
void purge_applications(HWND hWnd);
BOOL is_system_folder(const TCHAR* name);
LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int);
// --- log_purge_action: logs to deadweight_purge.log ---
void log_purge_action(const char* msg) {
    FILE* f = fopen("deadweight_purge.log", "a");
    if (!f) return;
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
            t->tm_year+1900, t->tm_mon+1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec, msg);
    fclose(f);
}

// --- Helper: delete all contents of a folder (recursive, no prompt) ---
void delete_folder_contents(const TCHAR* folder) {
    WIN32_FIND_DATA fd;
    TCHAR search[MAX_PATH_LENGTH];
    _stprintf(search, _T("%s\\*"), folder);
    HANDLE hFind = FindFirstFile(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (_tcscmp(fd.cFileName, _T(".")) == 0 || _tcscmp(fd.cFileName, _T("..")) == 0) continue;
        TCHAR full[MAX_PATH_LENGTH];
        _stprintf(full, _T("%s\\%s"), folder, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            delete_folder_contents(full);
            RemoveDirectory(full);
        } else {
            DeleteFile(full);
        }
    } while (FindNextFile(hFind, &fd));
    FindClose(hFind);
}

// --- purge_system: performs all cleaning steps ---
void purge_system(void) {
    // 0. Remove RunOnce entries
    HKEY runonce_keys[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const TCHAR* runonce_subkeys[] = {
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
    };
    for (int i = 0; i < 2; ++i) {
        HKEY hKey;
        if (RegOpenKeyEx(runonce_keys[i], runonce_subkeys[i], 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD count, maxName;
            RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &count, &maxName, NULL, NULL, NULL);
            TCHAR* name = (TCHAR*)malloc((maxName+2)*sizeof(TCHAR));
            for (DWORD j = 0; j < count; ++j) {
                DWORD n = maxName+1, type;
                if (RegEnumValue(hKey, 0, name, &n, NULL, &type, NULL, NULL) == ERROR_SUCCESS) {
                    RegDeleteValue(hKey, name);
                }
            }
            free(name);
            RegCloseKey(hKey);
            TCHAR msg[256];
            _stprintf(msg, _T("Cleared RunOnce: %s"), runonce_subkeys[i]);
            log_purge_action(msg);
        }
    }

    // 0b. Remove AppInit_DLLs
    HKEY hWinNT;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), 0, KEY_ALL_ACCESS, &hWinNT) == ERROR_SUCCESS) {
        RegSetValueEx(hWinNT, _T("AppInit_DLLs"), 0, REG_SZ, (const BYTE*)_T(""), sizeof(TCHAR));
        RegCloseKey(hWinNT);
        log_purge_action("Cleared AppInit_DLLs");
    }

    // 0c. Remove IFEO debuggers
    HKEY hIFEO;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), 0, KEY_ALL_ACCESS, &hIFEO) == ERROR_SUCCESS) {
        DWORD idx = 0;
        TCHAR subkey[256];
        while (RegEnumKey(hIFEO, idx, subkey, 256) == ERROR_SUCCESS) {
            HKEY hSub;
            if (RegOpenKeyEx(hIFEO, subkey, 0, KEY_ALL_ACCESS, &hSub) == ERROR_SUCCESS) {
                RegDeleteValue(hSub, _T("Debugger"));
                RegCloseKey(hSub);
            }
            ++idx;
        }
        RegCloseKey(hIFEO);
        log_purge_action("Cleared IFEO debuggers");
    }

    // 0d. Clean Winlogon Shell
    HKEY hWinlogon;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_ALL_ACCESS, &hWinlogon) == ERROR_SUCCESS) {
        RegSetValueEx(hWinlogon, _T("Shell"), 0, REG_SZ, (const BYTE*)_T("explorer.exe"), (lstrlen(_T("explorer.exe"))+1)*sizeof(TCHAR));
        RegCloseKey(hWinlogon);
        log_purge_action("Set Winlogon Shell to explorer.exe");
    }

    // 0e. Remove drivers (vgk.sys, nvlddmkm.sys, rz*.sys, *.inf)
    const TCHAR* driver_dirs[] = {
        _T("C:\\Windows\\System32\\drivers"),
        _T("C:\\Windows\\System32\\DriverStore\\FileRepository")
    };
    const TCHAR* patterns[] = { _T("vgk.sys"), _T("nvlddmkm.sys"), _T("rz*.sys"), _T("*.inf") };
    for (int d = 0; d < 2; ++d) {
        for (int p = 0; p < 4; ++p) {
            TCHAR search[MAX_PATH];
            _stprintf(search, _T("%s\\%s"), driver_dirs[d], patterns[p]);
            WIN32_FIND_DATA fd;
            HANDLE hFind = FindFirstFile(search, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    TCHAR full[MAX_PATH];
                    _stprintf(full, _T("%s\\%s"), driver_dirs[d], fd.cFileName);
                    DeleteFile(full);
                    TCHAR msg[256];
                    _stprintf(msg, _T("Deleted driver: %s"), full);
                    log_purge_action(msg);
                } while (FindNextFile(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    // 0f. Remove services with names containing razer/nvidia/proton/vgk
    SC_HANDLE scm2 = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm2) {
        DWORD needed = 0, count = 0;
        EnumServicesStatusEx(scm2, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &needed, &count, NULL, NULL);
        LPENUM_SERVICE_STATUS_PROCESS p = (LPENUM_SERVICE_STATUS_PROCESS)malloc(needed);
        if (EnumServicesStatusEx(scm2, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)p, needed, &needed, &count, NULL, NULL)) {
            for (DWORD i = 0; i < count; ++i) {
                TCHAR* sname = p[i].lpServiceName;
                if (_tcsstr(sname, _T("razer")) || _tcsstr(sname, _T("nvidia")) || _tcsstr(sname, _T("proton")) || _tcsstr(sname, _T("vgk"))) {
                    SC_HANDLE svc = OpenService(scm2, sname, DELETE|SERVICE_STOP);
                    if (svc) {
                        SERVICE_STATUS s;
                        ControlService(svc, SERVICE_CONTROL_STOP, &s);
                        DeleteService(svc);
                        CloseServiceHandle(svc);
                        TCHAR msg[256];
                        _stprintf(msg, _T("Deleted service: %s"), sname);
                        log_purge_action(msg);
                    }
                }
            }
        }
        free(p);
        CloseServiceHandle(scm2);
    }

    // 0g. Remove WMI persistence (delete all event filters/consumers/bindings)
    // NOTE: This is a best-effort, as full WMI COM code is verbose. We'll use system call.
    _tsystem(_T("wmic /namespace:\\root\\subscription PATH __EventFilter DELETE"));
    _tsystem(_T("wmic /namespace:\\root\\subscription PATH CommandLineEventConsumer DELETE"));
    _tsystem(_T("wmic /namespace:\\root\\subscription PATH FilterToConsumerBinding DELETE"));
    log_purge_action("WMI persistence removed");
    TCHAR temp[MAX_PATH], msg[512];
    // 1. %TEMP%
    GetTempPath(MAX_PATH, temp);
    delete_folder_contents(temp);
    log_purge_action("Cleared %TEMP%");

    // 2. C:\\Windows\\Temp
    GetWindowsDirectory(temp, MAX_PATH);
    _tcscat(temp, _T("\\Temp"));
    delete_folder_contents(temp);
    log_purge_action("Cleared C:\\Windows\\Temp");

    // 3. C:\\Users\\<user>\\AppData\\Local\\Temp
#ifdef _MSC_VER
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, temp))) {
        _tcscat(temp, _T("\\Temp"));
        delete_folder_contents(temp);
        log_purge_action("Cleared AppData Local Temp");
    }
#else
    TCHAR* appdata = _tgetenv(_T("LOCALAPPDATA"));
    if (appdata) {
        _stprintf(temp, _T("%s\\Temp"), appdata);
        delete_folder_contents(temp);
        log_purge_action("Cleared AppData Local Temp");
    }
#endif

    // 4. C:\\Windows\\Prefetch
    GetWindowsDirectory(temp, MAX_PATH);
    _tcscat(temp, _T("\\Prefetch"));
    delete_folder_contents(temp);
    log_purge_action("Cleared Prefetch");

    // 5. C:\\Windows\\SoftwareDistribution\\Download
    GetWindowsDirectory(temp, MAX_PATH);
    _tcscat(temp, _T("\\SoftwareDistribution\\Download"));
    delete_folder_contents(temp);
    log_purge_action("Cleared SoftwareDistribution Download");

    // 6. Clean registry autoruns and RunOnce
    HKEY keys[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const TCHAR* subkeys[] = {
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        _T("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
    };
    for (int i = 0; i < 5; ++i) {
        HKEY hKey;
        if (RegOpenKeyEx(keys[i], subkeys[i], 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD count, maxName;
            RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &count, &maxName, NULL, NULL, NULL);
            TCHAR* name = (TCHAR*)malloc((maxName+2)*sizeof(TCHAR));
            for (DWORD j = 0; j < count; ++j) {
                DWORD n = maxName+1, type;
                if (RegEnumValue(hKey, 0, name, &n, NULL, &type, NULL, NULL) == ERROR_SUCCESS) {
                    RegDeleteValue(hKey, name);
                }
            }
            free(name);
            RegCloseKey(hKey);
            _stprintf(msg, _T("Cleared autoruns: %s"), subkeys[i]);
            log_purge_action(msg);
        }
    }

    // 6b. Remove AppInit_DLLs
    // 6b. Remove AppInit_DLLs
    HKEY hWinKey2;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), 0, KEY_ALL_ACCESS, &hWinKey2) == ERROR_SUCCESS) {
        RegSetValueEx(hWinKey2, _T("AppInit_DLLs"), 0, REG_SZ, (const BYTE*)_T(""), sizeof(TCHAR));
        RegCloseKey(hWinKey2);
        log_purge_action("Cleared AppInit_DLLs");
    }

    // 6c. Remove IFEO debuggers
    HKEY hIFEO2;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), 0, KEY_ALL_ACCESS, &hIFEO2) == ERROR_SUCCESS) {
        DWORD idx2 = 0;
        TCHAR subkey2[256];
        while (RegEnumKey(hIFEO2, idx2, subkey2, 256) == ERROR_SUCCESS) {
            HKEY hSub2;
            if (RegOpenKeyEx(hIFEO2, subkey2, 0, KEY_ALL_ACCESS, &hSub2) == ERROR_SUCCESS) {
                RegDeleteValue(hSub2, _T("Debugger"));
                RegCloseKey(hSub2);
            }
            idx2++;
        }
        RegCloseKey(hIFEO2);
        log_purge_action("Cleared IFEO debuggers");
    }

    // 6d. Clean Winlogon Shell
    HKEY hLogon2;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_ALL_ACCESS, &hLogon2) == ERROR_SUCCESS) {
        RegSetValueEx(hLogon2, _T("Shell"), 0, REG_SZ, (const BYTE*)_T("explorer.exe"), (DWORD)((_tcslen(_T("explorer.exe"))+1)*sizeof(TCHAR)));
        RegCloseKey(hLogon2);
        log_purge_action("Reset Winlogon Shell to explorer.exe");
    }

    // 6e. Remove services with names containing razer/nvidia/proton/vgk
    SC_HANDLE scm2a = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm2a) {
        DWORD needed2a = 0, count2a = 0;
        EnumServicesStatusEx(scm2a, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &needed2a, &count2a, NULL, NULL);
        LPENUM_SERVICE_STATUS_PROCESS p2a = (LPENUM_SERVICE_STATUS_PROCESS)malloc(needed2a);
        if (EnumServicesStatusEx(scm2a, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)p2a, needed2a, &needed2a, &count2a, NULL, NULL)) {
            for (DWORD i = 0; i < count2a; ++i) {
                TCHAR* svcName = p2a[i].lpServiceName;
                TCHAR svcNameLower[256];
                _tcscpy(svcNameLower, svcName);
                _tcslwr(svcNameLower);
                if (_tcsstr(svcNameLower, _T("razer")) || _tcsstr(svcNameLower, _T("nvidia")) || _tcsstr(svcNameLower, _T("proton")) || _tcsstr(svcNameLower, _T("vgk"))) {
                    SC_HANDLE svc = OpenService(scm2a, svcName, DELETE|SERVICE_STOP);
                    if (svc) {
                        SERVICE_STATUS s;
                        ControlService(svc, SERVICE_CONTROL_STOP, &s);
                        DeleteService(svc);
                        CloseServiceHandle(svc);
                        _stprintf(msg, _T("Deleted service: %s"), svcName);
                        log_purge_action(msg);
                    }
                }
            }
        }
        free(p2a);
        CloseServiceHandle(scm2a);
    }

    // 6f. Delete drivers (vgk.sys, nvlddmkm.sys, rz*.sys, *.inf)
    const TCHAR* driverDirs2[] = { _T("C:\\Windows\\System32\\drivers"), _T("C:\\Windows\\System32\\DriverStore\\FileRepository") };
    const TCHAR* patterns2[] = { _T("vgk.sys"), _T("nvlddmkm.sys"), _T("rz*.sys"), _T("*.inf") };
    for (int d = 0; d < 2; ++d) {
        for (int p = 0; p < 4; ++p) {
            TCHAR search[MAX_PATH];
            _stprintf(search, _T("%s\\%s"), driverDirs2[d], patterns2[p]);
            WIN32_FIND_DATA fd;
            HANDLE hFind = FindFirstFile(search, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    TCHAR full[MAX_PATH];
                    _stprintf(full, _T("%s\\%s"), driverDirs2[d], fd.cFileName);
                    DeleteFile(full);
                    _stprintf(msg, _T("Deleted driver: %s"), full);
                    log_purge_action(msg);
                } while (FindNextFile(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    // 6g. Remove WMI persistence (delete __EventFilter, CommandLineEventConsumer, FilterToConsumerBinding)
    // Use wmic for simplicity
    system("wmic /namespace:\\root\\subscription PATH __EventFilter DELETE");
    log_purge_action("Deleted WMI __EventFilter");
    system("wmic /namespace:\\root\\subscription PATH CommandLineEventConsumer DELETE");
    log_purge_action("Deleted WMI CommandLineEventConsumer");
    system("wmic /namespace:\\root\\subscription PATH FilterToConsumerBinding DELETE");
    log_purge_action("Deleted WMI FilterToConsumerBinding");

    // 6h. Optionally block re-creation by creating dummy folders (example: C:\\Program Files\\Razer)
    CreateDirectory(_T("C:\\Program Files\\Razer"), NULL);
    SetFileAttributes(_T("C:\\Program Files\\Razer"), FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN);
    log_purge_action("Created dummy folder: C:Program Files\\Razer (read-only)");

    // 7. Delete scheduled tasks (non-system)
    TCHAR cmd[] = _T("schtasks /query /fo LIST /v");
    FILE* fp = _tpopen(cmd, _T("r"));
    TCHAR buf[32768] = {0};
    if (fp) {
        while (_fgetts(buf, 32768, fp)) {
            if (_tcsstr(buf, _T("TaskName:"))) {
                TCHAR* tn = buf + _tcslen(_T("TaskName:   "));
                while (*tn == ' ' || *tn == '\t') ++tn;
                if (_tcsncmp(tn, _T("\\Microsoft"), 10) != 0 && _tcsncmp(tn, _T("\\Windows"), 9) != 0) {
                    TCHAR delcmd[512];
                    _stprintf(delcmd, _T("schtasks /delete /f /tn \"%s\""), tn);
                    _tsystem(delcmd);
                    _stprintf(msg, _T("Deleted scheduled task: %s"), tn);
                    log_purge_action(msg);
                }
            }
        }
        _pclose(fp);
    }

    // 8. Remove WMI persistence
    GetWindowsDirectory(temp, MAX_PATH);
    _tcscat(temp, _T("\\System32\\wbem\\Repository"));
    delete_folder_contents(temp);
    log_purge_action("Cleared WMI Repository");

    // 9. Stop & disable non-system services
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        DWORD needed = 0, count = 0;
        EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &needed, &count, NULL, NULL);
        LPENUM_SERVICE_STATUS_PROCESS p = (LPENUM_SERVICE_STATUS_PROCESS)malloc(needed);
        if (EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)p, needed, &needed, &count, NULL, NULL)) {
            for (DWORD i = 0; i < count; ++i) {
                SC_HANDLE svc = OpenService(scm, p[i].lpServiceName, SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
                if (svc) {
                    QUERY_SERVICE_CONFIG* cfg = (QUERY_SERVICE_CONFIG*)malloc(8192);
                    DWORD sz;
                    if (QueryServiceConfig(svc, cfg, 8192, &sz)) {
                        if (!_tcsstr(cfg->lpBinaryPathName, _T("System32"))) {
                            SERVICE_STATUS s;
                            ControlService(svc, SERVICE_CONTROL_STOP, &s);
                            ChangeServiceConfig(svc, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
                            _stprintf(msg, _T("Stopped & disabled: %s"), p[i].lpServiceName);
                            log_purge_action(msg);
                        }
                    }
                    free(cfg);
                    CloseServiceHandle(svc);
                }
            }
        }
        free(p);
        CloseServiceHandle(scm);
    }

    // 10. Kill non-essential processes
    const TCHAR* keep[] = { _T("explorer.exe"), _T("svchost.exe"), _T("services.exe"), _T("lsass.exe"), _T("winlogon.exe") };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                BOOL skip = FALSE;
                for (int i = 0; i < 5; ++i)
                    if (_tcsicmp(pe.szExeFile, keep[i]) == 0) skip = TRUE;
                if (!skip && pe.th32ProcessID > 4) {
                    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (h) {
                        TerminateProcess(h, 0);
                        CloseHandle(h);
                        _stprintf(msg, _T("Killed process: %s"), pe.szExeFile);
                        log_purge_action(msg);
                    }
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
}

// --- GUI Window Procedure ---
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        CreateWindowEx(0, WC_BUTTON, _T("CLEAN"), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       30, 30, 120, 40, hWnd, (HMENU)ID_BTN_CLEAN, GetModuleHandle(NULL), NULL);
        CreateWindowEx(0, WC_BUTTON, _T("SCAN APPS"), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       170, 30, 120, 40, hWnd, (HMENU)ID_BTN_SCANAPPS, GetModuleHandle(NULL), NULL);
        CreateWindowEx(0, WC_LISTBOX, NULL, WS_CHILD | LBS_MULTIPLESEL | WS_BORDER | WS_VSCROLL,
                       30, 80, 260, 200, hWnd, (HMENU)ID_LIST_APPS, GetModuleHandle(NULL), NULL);
        CreateWindowEx(0, WC_BUTTON, _T("CLEAN SELECTED"), WS_CHILD | BS_PUSHBUTTON,
                       80, 290, 160, 40, hWnd, (HMENU)ID_BTN_CLEANSEL, GetModuleHandle(NULL), NULL);
        ShowWindow(GetDlgItem(hWnd, ID_LIST_APPS), SW_HIDE);
        ShowWindow(GetDlgItem(hWnd, ID_BTN_CLEANSEL), SW_HIDE);
        break;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_CLEAN:
            purge_system();
            MessageBox(hWnd, _T("System cleaned"), _T("DEADWEIGHT"), MB_OK | MB_ICONINFORMATION);
            break;
        case ID_BTN_SCANAPPS:
            scan_applications(hWnd);
            break;
        case ID_BTN_CLEANSEL:
            purge_applications(hWnd);
            break;
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}
// --- Helper: check if folder is system/critical ---
BOOL is_system_folder(const TCHAR* name) {
    const TCHAR* sys[] = { _T("Windows"), _T("System32"), _T("Microsoft"), _T("Defender"), _T("NVIDIA"), _T("Intel"), _T("AMD"), _T("Razer"), _T("Visual Studio"), _T("Microsoft Office") };
    for (int i = 0; i < sizeof(sys)/sizeof(sys[0]); ++i)
        if (_tcsicmp(name, sys[i]) == 0) return TRUE;
    return FALSE;
}

// --- Application scan: find unused app folders ---
void scan_applications(HWND hWnd) {
    HWND hList = GetDlgItem(hWnd, ID_LIST_APPS);
    HWND hCleanSel = GetDlgItem(hWnd, ID_BTN_CLEANSEL);
    SendMessage(hList, LB_RESETCONTENT, 0, 0);
    if (g_appEntries) { free(g_appEntries); g_appEntries = NULL; g_appCount = 0; }
    // Folders to scan
    const TCHAR* roots[4];
    roots[0] = _T("C:\\Program Files");
    roots[1] = _T("C:\\Program Files (x86)");
    TCHAR userLocal[MAX_PATH], userRoam[MAX_PATH];
    #ifndef CSIDL_LOCAL_APPDATA
    #define CSIDL_LOCAL_APPDATA 0x001c
    #endif
    #ifndef CSIDL_APPDATA
    #define CSIDL_APPDATA 0x001a
    #endif
    #ifndef SHGetFolderPath
    /* SHGetFolderPath is declared in shlobj.h, but if not available, declare prototype for MinGW */
    #ifdef __MINGW32__
    #ifdef __cplusplus
    extern "C" {
    #endif
    HRESULT __stdcall SHGetFolderPathA(HWND, int, HANDLE, DWORD, LPSTR);
    HRESULT __stdcall SHGetFolderPathW(HWND, int, HANDLE, DWORD, LPWSTR);
    #ifdef UNICODE
    #define SHGetFolderPath  SHGetFolderPathW
    #else
    #define SHGetFolderPath  SHGetFolderPathA
    #endif
    #ifdef __cplusplus
    }
    #endif
    #endif
    #endif
    SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, userLocal);
    SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, userRoam);
    roots[2] = userLocal;
    roots[3] = userRoam;
    // For each root, enumerate subfolders
    for (int r = 0; r < 4; ++r) {
        TCHAR search[MAX_PATH];
        _stprintf(search, _T("%s\\*"), roots[r]);
        WIN32_FIND_DATA fd;
        HANDLE hFind = FindFirstFile(search, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    _tcscmp(fd.cFileName, _T(".")) && _tcscmp(fd.cFileName, _T("..")) && !is_system_folder(fd.cFileName)) {
                    // Compose full path
                    TCHAR full[MAX_PATH_LENGTH];
                    _stprintf(full, _T("%s\\%s"), roots[r], fd.cFileName);
                    // Check last access time
                    FILETIME lastAccess = fd.ftLastAccessTime;
                    SYSTEMTIME st;
                    FileTimeToSystemTime(&lastAccess, &st);
                    // Check if unused (30+ days)
                    FILETIME nowFT; GetSystemTimeAsFileTime(&nowFT);
                    ULARGE_INTEGER ulNow, ulAccess;
                    ulNow.LowPart = nowFT.dwLowDateTime; ulNow.HighPart = nowFT.dwHighDateTime;
                    ulAccess.LowPart = lastAccess.dwLowDateTime; ulAccess.HighPart = lastAccess.dwHighDateTime;
                    ULONGLONG diff = (ulNow.QuadPart - ulAccess.QuadPart) / 10000000ULL;
                    ULONGLONG daysDiff = diff / (60 * 60 * 24);
                    BOOL unused = daysDiff > 30;
                    // Check for prefetch file (simple heuristic)
                    BOOL hasPrefetch = FALSE;
                    TCHAR pfdir[MAX_PATH];
                    GetWindowsDirectory(pfdir, MAX_PATH);
                    _tcscat(pfdir, _T("\\Prefetch\\"));
                    WIN32_FIND_DATA pfdata;
                    TCHAR pfsearch[MAX_PATH];
                    _stprintf(pfsearch, _T("%s%s*.pf"), pfdir, fd.cFileName);
                    HANDLE hpf = FindFirstFile(pfsearch, &pfdata);
                    if (hpf != INVALID_HANDLE_VALUE) { hasPrefetch = TRUE; FindClose(hpf); }
                    if (!hasPrefetch && unused) {
                        g_appEntries = realloc(g_appEntries, (g_appCount+1)*sizeof(AppEntry));
                        _tcscpy(g_appEntries[g_appCount].path, full);
                        _tcscpy(g_appEntries[g_appCount].name, fd.cFileName);
                        g_appEntries[g_appCount].lastAccess = lastAccess;
                        g_appEntries[g_appCount].unused = TRUE;
                        TCHAR entry[512];
                        _stprintf(entry, _T("%s | Last: %04d-%02d-%02d"), fd.cFileName, st.wYear, st.wMonth, st.wDay);
                        SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)entry);
                        ++g_appCount;
                    }
                }
            } while (FindNextFile(hFind, &fd));
            FindClose(hFind);
        }
    }
    ShowWindow(hList, SW_SHOW);
    ShowWindow(hCleanSel, SW_SHOW);
}

// --- Application purge: delete selected apps ---
void purge_applications(HWND hWnd) {
    HWND hList = GetDlgItem(hWnd, ID_LIST_APPS);
    int selCount = SendMessage(hList, LB_GETSELCOUNT, 0, 0);
    if (selCount <= 0) {
        MessageBox(hWnd, _T("No applications selected."), _T("DEADWEIGHT"), MB_OK | MB_ICONINFORMATION);
        return;
    }
    int* sel = malloc(selCount * sizeof(int));
    SendMessage(hList, LB_GETSELITEMS, selCount, (LPARAM)sel);
    int deleted = 0;
    for (int i = 0; i < selCount; ++i) {
        AppEntry* app = &g_appEntries[sel[i]];
        delete_folder_contents(app->path);
        // Remove RunOnce entries for each app
        HKEY runonce_keys[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
        const TCHAR* runonce_subkeys[] = {
            _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
        };
        for (int i_r = 0; i_r < 2; ++i_r) {
            HKEY hKey;
            if (RegOpenKeyEx(runonce_keys[i_r], runonce_subkeys[i_r], 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                RegDeleteValue(hKey, app->name);
                RegCloseKey(hKey);
            }
        }
        // Remove AppInit_DLLs
        HKEY hWinNT;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), 0, KEY_ALL_ACCESS, &hWinNT) == ERROR_SUCCESS) {
            RegSetValueEx(hWinNT, _T("AppInit_DLLs"), 0, REG_SZ, (const BYTE*)_T(""), sizeof(TCHAR));
            RegCloseKey(hWinNT);
        }
        // Remove IFEO debuggers for this app
        HKEY hIFEO;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), 0, KEY_ALL_ACCESS, &hIFEO) == ERROR_SUCCESS) {
            HKEY hSub;
            if (RegOpenKeyEx(hIFEO, app->name, 0, KEY_ALL_ACCESS, &hSub) == ERROR_SUCCESS) {
                RegDeleteValue(hSub, _T("Debugger"));
                RegCloseKey(hSub);
            }
            RegCloseKey(hIFEO);
        }
        // Clean Winlogon Shell
        HKEY hWinlogon;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 0, KEY_ALL_ACCESS, &hWinlogon) == ERROR_SUCCESS) {
            RegSetValueEx(hWinlogon, _T("Shell"), 0, REG_SZ, (const BYTE*)_T("explorer.exe"), (lstrlen(_T("explorer.exe"))+1)*sizeof(TCHAR));
            RegCloseKey(hWinlogon);
        }
        // Remove drivers for this app (heuristic: rz*.sys, *.inf, appname*.sys)
        const TCHAR* driver_dirs[] = {
            _T("C:\\Windows\\System32\\drivers"),
            _T("C:\\Windows\\System32\\DriverStore\\FileRepository")
        };
        TCHAR pattern1[MAX_PATH];
        _stprintf(pattern1, _T("%s*.sys"), app->name);
        const TCHAR* patterns[] = { pattern1, _T("rz*.sys"), _T("*.inf") };
        for (int d = 0; d < 2; ++d) {
            for (int p = 0; p < 3; ++p) {
                TCHAR search[MAX_PATH];
                _stprintf(search, _T("%s\\%s"), driver_dirs[d], patterns[p]);
                WIN32_FIND_DATA fd;
                HANDLE hFind = FindFirstFile(search, &fd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        TCHAR full[MAX_PATH];
                        _stprintf(full, _T("%s\\%s"), driver_dirs[d], fd.cFileName);
                        DeleteFile(full);
                        TCHAR msg[256];
                        _stprintf(msg, _T("Deleted driver: %s"), full);
                        log_purge_action(msg);
                    } while (FindNextFile(hFind, &fd));
                    FindClose(hFind);
                }
            }
        }
        // Remove services with app name or razer/nvidia/proton/vgk
        SC_HANDLE scm2 = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (scm2) {
            DWORD needed = 0, count = 0;
            EnumServicesStatusEx(scm2, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &needed, &count, NULL, NULL);
            LPENUM_SERVICE_STATUS_PROCESS p = (LPENUM_SERVICE_STATUS_PROCESS)malloc(needed);
            if (EnumServicesStatusEx(scm2, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)p, needed, &needed, &count, NULL, NULL)) {
                for (DWORD i = 0; i < count; ++i) {
                    TCHAR* sname = p[i].lpServiceName;
                    if (_tcsicmp(sname, app->name) == 0 || _tcsstr(sname, _T("razer")) || _tcsstr(sname, _T("nvidia")) || _tcsstr(sname, _T("proton")) || _tcsstr(sname, _T("vgk"))) {
                        SC_HANDLE svc = OpenService(scm2, sname, DELETE|SERVICE_STOP);
                        if (svc) {
                            SERVICE_STATUS s;
                            ControlService(svc, SERVICE_CONTROL_STOP, &s);
                            DeleteService(svc);
                            CloseServiceHandle(svc);
                            TCHAR msg[256];
                            _stprintf(msg, _T("Deleted service: %s"), sname);
                            log_purge_action(msg);
                        }
                    }
                }
            }
            free(p);
            CloseServiceHandle(scm2);
        }
        // Remove WMI persistence for this app (best effort)
        TCHAR wmiCmd[512];
        _stprintf(wmiCmd, _T("wmic /namespace:\\root\\subscription PATH __EventFilter WHERE \"Name LIKE '%%%s%%'\" DELETE"), app->name);
        _tsystem(wmiCmd);
        _stprintf(wmiCmd, _T("wmic /namespace:\\root\\subscription PATH CommandLineEventConsumer WHERE \"Name LIKE '%%%s%%'\" DELETE"), app->name);
        _tsystem(wmiCmd);
        _stprintf(wmiCmd, _T("wmic /namespace:\\root\\subscription PATH FilterToConsumerBinding WHERE \"Filter LIKE '%%%s%%'\" DELETE"), app->name);
        _tsystem(wmiCmd);
        // Optionally: block re-creation by creating dummy folder (best effort)
        CreateDirectory(app->path, NULL);
        SetFileAttributes(app->path, FILE_ATTRIBUTE_READONLY);
        // Log aggressive actions
        TCHAR msg2[256];
        _stprintf(msg2, _T("Aggressive purge for: %s"), app->name);
        log_purge_action(msg2);
        ++deleted;
    }
    free(sel);
    TCHAR summary[128];
    _stprintf(summary, _T("Deleted %d applications. See deadweight_purge.log for details."), deleted);
    MessageBox(hWnd, summary, _T("DEADWEIGHT"), MB_OK | MB_ICONINFORMATION);
}

// --- WinMain: GUI entry point ---
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    WNDCLASS wc = {0};
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = _T("DeadweightMainWnd");
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);

    HWND hWnd = CreateWindowEx(0, _T("DeadweightMainWnd"), _T("DEADWEIGHT Cleaner"),
                              WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                              CW_USEDEFAULT, CW_USEDEFAULT, 320, 200, NULL, NULL, hInstance, NULL);
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

typedef struct {
    FILETIME creationTime;
    FILETIME lastAccessTime;
    FILETIME lastWriteTime;
    LARGE_INTEGER fileSize;
    TCHAR fileName[MAX_PATH_LENGTH];
    TCHAR filePath[MAX_PATH_LENGTH];
} FileInfo;

typedef struct {
    DWORD pid;
    DWORD ppid;
    TCHAR name[MAX_PATH];
    TCHAR path[MAX_PATH_LENGTH];
    DWORD memoryUsage;
    DWORD cpuUsage;
} ProcessInfo;

typedef struct {
    TCHAR keyPath[MAX_PATH];
    TCHAR valueName[MAX_PATH];
    TCHAR valueData[MAX_PATH_LENGTH];
    TCHAR filePath[MAX_PATH_LENGTH];
    BOOL fileExists;
} RegistryEntry;

void dump_log(const TCHAR* module, const TCHAR* message) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    TCHAR logFileName[MAX_PATH];
    GetModuleFileName(NULL, logFileName, MAX_PATH);
    PathRemoveFileSpec(logFileName);
    PathAppend(logFileName, _T("deadweight.log"));
    
    FILE* logFile = _tfopen(logFileName, _T("a"));
    if (logFile) {
        _ftprintf(logFile, _T("[%04d-%02d-%02d %02d:%02d:%02d] | [%s] | %s\n"), 
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                 module, message);
        fclose(logFile);
    }
}

void print_header(const TCHAR* title) {
    _tprintf(_T("\n=== DEADWEIGHT - %s ===\n"), title);
}

void scan_directory_recursive(const TCHAR* path, int daysThreshold, int* fileCount, LARGE_INTEGER* totalSize) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    TCHAR searchPath[MAX_PATH_LENGTH];

    _stprintf(searchPath, _T("%s\\*"), path);

    hFind = FindFirstFile(searchPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        dump_log(_T("scan_directory"), _T("FindFirstFile failed"));
        return;
    }

    do {
        if (_tcscmp(findFileData.cFileName, _T(".")) == 0 || _tcscmp(findFileData.cFileName, _T("..")) == 0) {
            continue;
        }

        TCHAR fullPath[MAX_PATH_LENGTH];
        _stprintf(fullPath, _T("%s\\%s"), path, findFileData.cFileName);

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_directory_recursive(fullPath, daysThreshold, fileCount, totalSize);
        } else {
            FILETIME ftNow;
            GetSystemTimeAsFileTime(&ftNow);
            
            ULARGE_INTEGER ulNow, ulAccess;
            ulNow.LowPart = ftNow.dwLowDateTime;
            ulNow.HighPart = ftNow.dwHighDateTime;
            ulAccess.LowPart = findFileData.ftLastAccessTime.dwLowDateTime;
            ulAccess.HighPart = findFileData.ftLastAccessTime.dwHighDateTime;
            
            ULONGLONG diff = (ulNow.QuadPart - ulAccess.QuadPart) / 10000000ULL; // convert to seconds
            ULONGLONG daysDiff = diff / (60 * 60 * 24);
            
            if (daysDiff > (ULONGLONG)daysThreshold) {
                LARGE_INTEGER fileSize;
                fileSize.LowPart = findFileData.nFileSizeLow;
                fileSize.HighPart = findFileData.nFileSizeHigh;
                
                totalSize->QuadPart += fileSize.QuadPart;
                (*fileCount)++;
                
                SYSTEMTIME stAccess;
                FileTimeToSystemTime(&findFileData.ftLastAccessTime, &stAccess);
                
                _tprintf(_T("[%d] %s - Last used: %04d-%02d-%02d - Size: %.2f MB\n"), 
                         *fileCount, fullPath, 
                         stAccess.wYear, stAccess.wMonth, stAccess.wDay,
                         (double)fileSize.QuadPart / (1024 * 1024));
                
                TCHAR logMsg[MAX_LOG_LENGTH];
                _stprintf(logMsg, _T("Found old file: %s, Last used: %04d-%02d-%02d, Size: %lld bytes"), 
                          fullPath, stAccess.wYear, stAccess.wMonth, stAccess.wDay, fileSize.QuadPart);
                dump_log(_T("scan_directory"), logMsg);
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

void scan_directory(const TCHAR* path, int daysThreshold) {
    print_header(_T("DIRECTORY SCAN REPORT"));
    
    int fileCount = 0;
    LARGE_INTEGER totalSize = {0};
    
    _tprintf(_T("Scanning directory: %s\n"), path);
    _tprintf(_T("Looking for files not used in last %d days...\n\n"), daysThreshold);
    
    scan_directory_recursive(path, daysThreshold, &fileCount, &totalSize);
    
    _tprintf(_T("\n-- Total: %d files, %.2f GB\n"), 
             fileCount, (double)totalSize.QuadPart / (1024 * 1024 * 1024));
    
    TCHAR logMsg[MAX_LOG_LENGTH];
    _stprintf(logMsg, _T("Scan completed. Found %d old files, total size: %.2f GB"), 
              fileCount, (double)totalSize.QuadPart / (1024 * 1024 * 1024));
    dump_log(_T("scan_directory"), logMsg);
}

void analyze_prefetch() {
    print_header(_T("PREFETCH ANALYSIS"));
    
    TCHAR prefetchPath[MAX_PATH];
    GetWindowsDirectory(prefetchPath, MAX_PATH);
    PathAppend(prefetchPath, _T("Prefetch"));
    
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    TCHAR searchPath[MAX_PATH];
    
    _stprintf(searchPath, _T("%s\\*.pf"), prefetchPath);
    
    hFind = FindFirstFile(searchPath, &findFileData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        _tprintf(_T("No prefetch files found or access denied.\n"));
        dump_log(_T("analyze_prefetch"), _T("No prefetch files found or access denied"));
        return;
    }
    
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    
    _tprintf(_T("%-40s %-20s %s\n"), _T("Application"), _T("Last Run"), _T("Days Since Run"));
    _tprintf(_T("--------------------------------------------------------------------------------\n"));
    
    do {
        TCHAR appName[MAX_PATH];
        _tcscpy(appName, findFileData.cFileName);
        
        // Remove .pf extension
        TCHAR* dot = _tcsrchr(appName, _T('.'));
        if (dot) *dot = _T('\0');
        
        ULARGE_INTEGER ulNow, ulAccess;
        ulNow.LowPart = ftNow.dwLowDateTime;
        ulNow.HighPart = ftNow.dwHighDateTime;
        ulAccess.LowPart = findFileData.ftLastAccessTime.dwLowDateTime;
        ulAccess.HighPart = findFileData.ftLastAccessTime.dwHighDateTime;
        
        ULONGLONG diff = (ulNow.QuadPart - ulAccess.QuadPart) / 10000000ULL; // convert to seconds
        ULONGLONG daysDiff = diff / (60 * 60 * 24);
        
        SYSTEMTIME stAccess;
        FileTimeToSystemTime(&findFileData.ftLastAccessTime, &stAccess);
        
        _tprintf(_T("%-40s %04d-%02d-%02d %02d:%02d   %-3llu\n"), 
                appName, stAccess.wYear, stAccess.wMonth, stAccess.wDay,
                stAccess.wHour, stAccess.wMinute, daysDiff);
        
    } while (FindNextFile(hFind, &findFileData) != 0);
    
    FindClose(hFind);
    
    dump_log(_T("analyze_prefetch"), _T("Prefetch analysis completed"));
}

void analyze_registry_run() {
    print_header(_T("REGISTRY RUN ENTRIES"));
    
    HKEY hKey;
    const TCHAR* runKeys[] = {
        _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        _T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
        _T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
    };
    
    _tprintf(_T("%-50s %-50s %s\n"), _T("Key Path"), _T("Value Name"), _T("Value Data"));
    _tprintf(_T("--------------------------------------------------------------------------------------------------------------------\n"));
    
    for (int i = 0; i < sizeof(runKeys)/sizeof(runKeys[0]); i++) {
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, runKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            TCHAR valueName[256];
            DWORD valueNameSize, valueSize;
            DWORD type;
            BYTE valueData[1024];
            DWORD index = 0;
            
            while (1) {
                valueNameSize = 256;
                valueSize = sizeof(valueData);
                
                if (RegEnumValue(hKey, index, valueName, &valueNameSize, NULL, &type, valueData, &valueSize) != ERROR_SUCCESS) {
                    break;
                }
                
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                    _tprintf(_T("%-50s %-50s %s\n"), runKeys[i], valueName, (TCHAR*)valueData);
                    
                    TCHAR logMsg[MAX_LOG_LENGTH];
                    _stprintf(logMsg, _T("Found Run entry: %s\\%s = %s"), runKeys[i], valueName, (TCHAR*)valueData);
                    dump_log(_T("analyze_registry"), logMsg);
                }
                
                index++;
            }
            
            RegCloseKey(hKey);
        }
    }
    
    dump_log(_T("analyze_registry"), _T("Registry Run analysis completed"));
}

void monitor_processes(int duration_seconds) {
    print_header(_T("PROCESS MONITOR"));
    _tprintf(_T("Monitoring processes for %d seconds...\n"), duration_seconds);
    
    DWORD startTime = GetTickCount();
    DWORD endTime = startTime + (duration_seconds * 1000);
    
    ProcessInfo* initialProcesses = NULL;
    DWORD initialCount = 0;
    
    // Get initial process list
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                initialProcesses = (ProcessInfo*)realloc(initialProcesses, (initialCount + 1) * sizeof(ProcessInfo));
                initialProcesses[initialCount].pid = pe32.th32ProcessID;
                initialProcesses[initialCount].ppid = pe32.th32ParentProcessID;
                _tcscpy(initialProcesses[initialCount].name, pe32.szExeFile);
                
                // Get full path
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    GetModuleFileNameEx(hProcess, NULL, initialProcesses[initialCount].path, MAX_PATH);
                    CloseHandle(hProcess);
                } else {
                    _tcscpy(initialProcesses[initialCount].path, _T("Access Denied"));
                }
                
                initialCount++;
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    // Monitoring loop
    while (GetTickCount() < endTime) {
        Sleep(1000);
        
        // Compare with current processes
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    // Check if this is a new process
                    BOOL found = FALSE;
                    for (DWORD i = 0; i < initialCount; i++) {
                        if (initialProcesses[i].pid == pe32.th32ProcessID) {
                            found = TRUE;
                            break;
                        }
                    }
                    
                    if (!found) {
                        _tprintf(_T("[NEW] PID: %6d, Name: %s, Parent: %d\n"), 
                                pe32.th32ProcessID, pe32.szExeFile, pe32.th32ParentProcessID);
                        
                        TCHAR logMsg[MAX_LOG_LENGTH];
                        _stprintf(logMsg, _T("New process detected: PID: %d, Name: %s, Parent: %d"), 
                                  pe32.th32ProcessID, pe32.szExeFile, pe32.th32ParentProcessID);
                        dump_log(_T("monitor_processes"), logMsg);
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }
    
    // Check for terminated processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        DWORD currentCount = 0;
        ProcessInfo* currentProcesses = NULL;
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                currentProcesses = (ProcessInfo*)realloc(currentProcesses, (currentCount + 1) * sizeof(ProcessInfo));
                currentProcesses[currentCount].pid = pe32.th32ProcessID;
                currentCount++;
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        for (DWORD i = 0; i < initialCount; i++) {
            BOOL found = FALSE;
            for (DWORD j = 0; j < currentCount; j++) {
                if (initialProcesses[i].pid == currentProcesses[j].pid) {
                    found = TRUE;
                    break;
                }
            }
            
            if (!found) {
                _tprintf(_T("[TERMINATED] PID: %6d, Name: %s\n"), 
                        initialProcesses[i].pid, initialProcesses[i].name);
                
                TCHAR logMsg[MAX_LOG_LENGTH];
                _stprintf(logMsg, _T("Process terminated: PID: %d, Name: %s"), 
                          initialProcesses[i].pid, initialProcesses[i].name);
                dump_log(_T("monitor_processes"), logMsg);
            }
        }
        
        free(currentProcesses);
        CloseHandle(hSnapshot);
    }
    
    free(initialProcesses);
    
    dump_log(_T("monitor_processes"), _T("Process monitoring completed"));
}

void lupa_mode(const TCHAR* process_name) {
    print_header(_T("PROCESS DETAILS"));
    _tprintf(_T("Analyzing process: %s\n"), process_name);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Error creating process snapshot\n"));
        dump_log(_T("lupa_mode"), _T("Error creating process snapshot"));
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    DWORD targetPid = 0;
    DWORD parentPid = 0;
    TCHAR processPath[MAX_PATH] = _T("");
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_tcsicmp(pe32.szExeFile, process_name) == 0) {
                targetPid = pe32.th32ProcessID;
                parentPid = pe32.th32ParentProcessID;
                
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
                if (hProcess) {
                    GetModuleFileNameEx(hProcess, NULL, processPath, MAX_PATH);
                    CloseHandle(hProcess);
                } else {
                    _tcscpy(processPath, _T("Access Denied"));
                }
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    if (targetPid == 0) {
        _tprintf(_T("Process not found\n"));
        dump_log(_T("lupa_mode"), _T("Process not found"));
        CloseHandle(hSnapshot);
        return;
    }
    
    _tprintf(_T("\nBasic Information:\n"));
    _tprintf(_T("  PID:           %d\n"), targetPid);
    _tprintf(_T("  Parent PID:    %d\n"), parentPid);
    _tprintf(_T("  Path:          %s\n"), processPath);
    
    // Get memory usage
    PROCESS_MEMORY_COUNTERS pmc;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
    if (hProcess && GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        _tprintf(_T("  Memory Usage:  %.2f MB\n"), (float)pmc.WorkingSetSize / (1024 * 1024));
    }
    if (hProcess) CloseHandle(hProcess);
    
    // Get loaded modules
    _tprintf(_T("\nLoaded Modules:\n"));
    HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPid);
    if (hModuleSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        
        if (Module32First(hModuleSnapshot, &me32)) {
            do {
                _tprintf(_T("  %s\n"), me32.szModule);
            } while (Module32Next(hModuleSnapshot, &me32));
        }
        CloseHandle(hModuleSnapshot);
    }
    
    // Get parent process info
    if (parentPid != 0) {
        HANDLE hParentSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hParentSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 peParent;
            peParent.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hParentSnapshot, &peParent)) {
                do {
                    if (peParent.th32ProcessID == parentPid) {
                        _tprintf(_T("\nParent Process:\n"));
                        _tprintf(_T("  PID:   %d\n"), peParent.th32ProcessID);
                        _tprintf(_T("  Name:  %s\n"), peParent.szExeFile);
                        
                        HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, parentPid);
                        if (hParentProcess) {
                            TCHAR parentPath[MAX_PATH];
                            if (GetModuleFileNameEx(hParentProcess, NULL, parentPath, MAX_PATH)) {
                                _tprintf(_T("  Path:  %s\n"), parentPath);
                            }
                            CloseHandle(hParentProcess);
                        }
                        break;
                    }
                } while (Process32Next(hParentSnapshot, &peParent));
            }
            CloseHandle(hParentSnapshot);
        }
    }
    
    CloseHandle(hSnapshot);
    
    dump_log(_T("lupa_mode"), _T("Process analysis completed"));
}

BOOL delete_tree_helper(const TCHAR* path) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    TCHAR searchPath[MAX_PATH_LENGTH];
    
    _stprintf(searchPath, _T("%s\\*"), path);
    
    hFind = FindFirstFile(searchPath, &findFileData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    do {
        if (_tcscmp(findFileData.cFileName, _T(".")) == 0 || _tcscmp(findFileData.cFileName, _T("..")) == 0) {
            continue;
        }
        
        TCHAR fullPath[MAX_PATH_LENGTH];
        _stprintf(fullPath, _T("%s\\%s"), path, findFileData.cFileName);
        
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!delete_tree_helper(fullPath)) {
                FindClose(hFind);
                return FALSE;
            }
        } else {
            if (!DeleteFile(fullPath)) {
                FindClose(hFind);
                return FALSE;
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);
    
    FindClose(hFind);
    
    return RemoveDirectory(path);
}

void delete_tree(const TCHAR* folder_path) {
    print_header(_T("DELETE TREE OPERATION"));
    
    // First gather information about the folder
    int fileCount = 0;
    int folderCount = 0;
    LARGE_INTEGER totalSize = {0};
    
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    TCHAR searchPath[MAX_PATH_LENGTH];
    
    _stprintf(searchPath, _T("%s\\*"), folder_path);
    
    hFind = FindFirstFile(searchPath, &findFileData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (_tcscmp(findFileData.cFileName, _T(".")) == 0 || _tcscmp(findFileData.cFileName, _T("..")) == 0) {
                continue;
            }
            
            TCHAR fullPath[MAX_PATH_LENGTH];
            _stprintf(fullPath, _T("%s\\%s"), folder_path, findFileData.cFileName);
            
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                folderCount++;
            } else {
                fileCount++;
                LARGE_INTEGER fileSize;
                fileSize.LowPart = findFileData.nFileSizeLow;
                fileSize.HighPart = findFileData.nFileSizeHigh;
                totalSize.QuadPart += fileSize.QuadPart;
            }
        } while (FindNextFile(hFind, &findFileData) != 0);
        
        FindClose(hFind);
    }
    
    SYSTEMTIME stAccess;
    FileTimeToSystemTime(&findFileData.ftLastAccessTime, &stAccess);
    
    _tprintf(_T("Folder to delete: %s\n"), folder_path);
    _tprintf(_T("Last accessed: %04d-%02d-%02d\n"), stAccess.wYear, stAccess.wMonth, stAccess.wDay);
    _tprintf(_T("Contains: %d files, %d folders\n"), fileCount, folderCount);
    _tprintf(_T("Total size: %.2f MB\n\n"), (double)totalSize.QuadPart / (1024 * 1024));
    
    _tprintf(_T("Are you sure you want to delete this folder and all its contents? (y/n): "));
    TCHAR response[2];
    _fgetts(response, 2, stdin);
    
    if (_totlower(response[0]) == _T('y')) {
        if (delete_tree_helper(folder_path)) {
            _tprintf(_T("\nFolder successfully deleted.\n"));
            
            TCHAR logMsg[MAX_LOG_LENGTH];
            _stprintf(logMsg, _T("Deleted folder: %s, contained %d files, %d folders, size: %.2f MB"), 
                     folder_path, fileCount, folderCount, (double)totalSize.QuadPart / (1024 * 1024));
            dump_log(_T("delete_tree"), logMsg);
        } else {
            _tprintf(_T("\nError deleting folder. Some files may be in use or access was denied.\n"));
            dump_log(_T("delete_tree"), _T("Error deleting folder"));
        }
    } else {
        _tprintf(_T("\nOperation cancelled.\n"));
        dump_log(_T("delete_tree"), _T("Operation cancelled by user"));
    }
}

void analyze_services() {
    print_header(_T("SERVICES ANALYSIS"));
    
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        _tprintf(_T("Error opening Service Control Manager\n"));
        dump_log(_T("analyze_services"), _T("Error opening Service Control Manager"));
        return;
    }
    
    DWORD bytesNeeded = 0;
    DWORD numServices = 0;
    
    // First call to get buffer size
    EnumServicesStatus(scm, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &numServices, NULL);
    
    DWORD err = GetLastError();
    if (err != ERROR_MORE_DATA) {
        _tprintf(_T("Error enumerating services\n"));
        CloseServiceHandle(scm);
        dump_log(_T("analyze_services"), _T("Error enumerating services"));
        return;
    }
    
    LPENUM_SERVICE_STATUS services = (LPENUM_SERVICE_STATUS)malloc(bytesNeeded);
    if (!services) {
        _tprintf(_T("Memory allocation error\n"));
        CloseServiceHandle(scm);
        dump_log(_T("analyze_services"), _T("Memory allocation error"));
        return;
    }
    
    if (!EnumServicesStatus(scm, SERVICE_WIN32, SERVICE_STATE_ALL, services, bytesNeeded, &bytesNeeded, &numServices, NULL)) {
        _tprintf(_T("Error enumerating services\n"));
        free(services);
        CloseServiceHandle(scm);
        dump_log(_T("analyze_services"), _T("Error enumerating services"));
        return;
    }
    
    _tprintf(_T("%-40s %-20s %-40s\n"), _T("Service Name"), _T("Status"), _T("Display Name"));
    _tprintf(_T("--------------------------------------------------------------------------------------------------------\n"));
    
    for (DWORD i = 0; i < numServices; i++) {
        SC_HANDLE service = OpenService(scm, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (service) {
            LPQUERY_SERVICE_CONFIG config = NULL;
            DWORD configSize = 0;
            
            // First call to get buffer size
            QueryServiceConfig(service, NULL, 0, &configSize);
            config = (LPQUERY_SERVICE_CONFIG)malloc(configSize);
            
            if (QueryServiceConfig(service, config, configSize, &configSize)) {
                // Check if service is running from suspicious locations
                TCHAR* path = config->lpBinaryPathName;
                if (path) {
                    if (_tcsstr(path, _T("Temp\\")) || _tcsstr(path, _T("temp\\")) || 
                        _tcsstr(path, _T("AppData\\")) || _tcsstr(path, _T("Users\\"))) {
                        _tprintf(_T("%-40s %-20s %-40s\n"), 
                                services[i].lpServiceName, 
                                services[i].lpDisplayName, 
                                _T("SUSPICIOUS LOCATION"));
                        
                        TCHAR logMsg[MAX_LOG_LENGTH];
                        _stprintf(logMsg, _T("Suspicious service: %s (%s) - Path: %s"), 
                                 services[i].lpServiceName, services[i].lpDisplayName, path);
                        dump_log(_T("analyze_services"), logMsg);
                        continue;
                    }
                }
            }
            free(config);
            CloseServiceHandle(service);
        }
        
        _tprintf(_T("%-40s %-20s %-40s\n"),
                services[i].lpServiceName,
                services[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING ? _T("Running") : _T("Stopped"),
                services[i].lpDisplayName);
    }
    
    free(services);
    CloseServiceHandle(scm);
    
    dump_log(_T("analyze_services"), _T("Services analysis completed"));
}

void generate_report() {
    print_header(_T("SYSTEM REPORT"));
    
    // System information
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    _tprintf(_T("System Information:\n"));
    _tprintf(_T("  Processor Architecture: %d\n"), sysInfo.wProcessorArchitecture);
    _tprintf(_T("  Number of Processors: %d\n"), sysInfo.dwNumberOfProcessors);
    _tprintf(_T("  Memory: %.2f GB / %.2f GB (%.2f%% used)\n"), 
            (float)(memStatus.ullTotalPhys - memStatus.ullAvailPhys) / (1024 * 1024 * 1024),
            (float)memStatus.ullTotalPhys / (1024 * 1024 * 1024),
            memStatus.dwMemoryLoad);
    
    // Disk information
    DWORD drives = GetLogicalDrives();
    _tprintf(_T("\nDisk Information:\n"));
    
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            TCHAR rootPath[] = {_T('A') + i, _T(':'), _T('\\'), _T('\0')};
            TCHAR volumeName[MAX_PATH + 1] = {0};
            TCHAR fileSystemName[MAX_PATH + 1] = {0};
            DWORD serialNumber = 0, maxComponentLen = 0, fileSystemFlags = 0;
            
            if (GetVolumeInformation(rootPath, volumeName, MAX_PATH, &serialNumber, 
                                   &maxComponentLen, &fileSystemFlags, fileSystemName, MAX_PATH)) {
                ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
                
                if (GetDiskFreeSpaceEx(rootPath, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
                    _tprintf(_T("  %s: %s, %s, %.2f GB free of %.2f GB\n"), 
                            rootPath, volumeName, fileSystemName,
                            (float)freeBytesAvailable.QuadPart / (1024 * 1024 * 1024),
                            (float)totalNumberOfBytes.QuadPart / (1024 * 1024 * 1024));
                }
            }
        }
    }
    
    // Recent activities
    _tprintf(_T("\nRecent Activities:\n"));
    analyze_prefetch();
    analyze_registry_run();
    analyze_services();
    
    dump_log(_T("generate_report"), _T("System report generated"));
}

void print_usage() {
    _tprintf(_T("\nDEADWEIGHT - Windows System Analyzer and Cleaner\n"));
    _tprintf(_T("Usage: deadweight.exe [OPTION] [ARGUMENT]\n\n"));
    _tprintf(_T("Options:\n"));
    _tprintf(_T("  --scan PATH [DAYS]    Scan directory for old files (default: 30 days)\n"));
    _tprintf(_T("  --live SECONDS        Monitor processes for specified duration\n"));
    _tprintf(_T("  --clean PATH          Delete directory and all its contents\n"));
    _tprintf(_T("  --lupa PROCESS_NAME   Analyze specific process in detail\n"));
    _tprintf(_T("  --report              Generate full system report\n"));
    _tprintf(_T("  --persistence         Check for persistence mechanisms\n"));
    _tprintf(_T("  --help                Show this help message\n"));
}

int _tmain(int argc, TCHAR* argv[]) {
    if (argc < 2) {
        // No CLI args: launch GUI
        int ret = WinMain(GetModuleHandle(NULL), NULL, GetCommandLineA(), SW_SHOWNORMAL);
        return ret;
    }
    // ...existing CLI logic...
    if (_tcsicmp(argv[1], _T("--scan")) == 0) {
        if (argc < 3) {
            _tprintf(_T("Error: Missing directory path\n"));
            return 1;
        }
        int daysThreshold = 30; // default
        if (argc >= 4) {
            daysThreshold = _ttoi(argv[3]);
        }
        scan_directory(argv[2], daysThreshold);
    } 
    else if (_tcsicmp(argv[1], _T("--live")) == 0) {
        if (argc < 3) {
            _tprintf(_T("Error: Missing duration\n"));
            return 1;
        }
        int duration = _ttoi(argv[2]);
        if (duration <= 0) duration = 15; // default
        monitor_processes(duration);
    } 
    else if (_tcsicmp(argv[1], _T("--clean")) == 0) {
        if (argc < 3) {
            _tprintf(_T("Error: Missing directory path\n"));
            return 1;
        }
        delete_tree(argv[2]);
    } 
    else if (_tcsicmp(argv[1], _T("--lupa")) == 0) {
        if (argc < 3) {
            _tprintf(_T("Error: Missing process name\n"));
            return 1;
        }
        lupa_mode(argv[2]);
    } 
    else if (_tcsicmp(argv[1], _T("--report")) == 0) {
        generate_report();
    } 
    else if (_tcsicmp(argv[1], _T("--persistence")) == 0) {
        analyze_registry_run();
        analyze_services();
    } 
    else if (_tcsicmp(argv[1], _T("--help")) == 0) {
        print_usage();
    } 
    else {
        _tprintf(_T("Error: Unknown command\n"));
        print_usage();
        return 1;
    }
    return 0;
}