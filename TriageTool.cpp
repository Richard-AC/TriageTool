#include <windows.h>
#include <stdio.h>
#include <atlstr.h>
#include "filesystem_functions.h"

#define DBG 0

#define debug_print(...) \
            do { if (DBG) fwprintf(stderr, __VA_ARGS__); } while (0)

#define TIMEOUT_VALUE 4000 // Defines how long to wait before considering that the process did not crash.

UINT16 EnterDebugLoop(const LPDEBUG_EVENT DebugEv);

int wmain(int argc, wchar_t* wargv[]) {
    if (argc < 4 || argc > 5) {
        printf("Usage: TriageTool.exe <program path> <input dir> <output dir> [<extension>]\nUse absolute paths.\n");
        printf("Example: TriageTool.exe C:\\myapp.exe C:\\infolder C:\\outfolder .pdf\n");
        return 0;
    }
    const wchar_t* program_path = wargv[1];
    const wchar_t* initial_dir = wargv[2];
    const wchar_t* output_dir = wargv[3];
    wchar_t input_dir[200] = L"";
    const wchar_t input_dir_format[] = L"%s\\input_dir";
    swprintf_s(input_dir, 200, input_dir_format, output_dir);
    
    const wchar_t* extension = L"";
    if (argc == 5) {
        extension = wargv[4];
    }

    int err = _wmkdir(output_dir);
    if (err == -1) {
        printf("Failed to create output folder. The folder might already exist.\n");
        return 1;
    }

    UINT32 number_of_files = setup_input_dir(initial_dir, input_dir, extension);
    if (number_of_files == 0) {
        printf("Did not find any input\n");
        return 1;
    }
    printf("Found %d files.\n", number_of_files);
    UINT16* hashes_array = (UINT16*)malloc(number_of_files * sizeof(UINT16));
    if (hashes_array == NULL) {
        printf("Failed to allocates memory for hash array\n");
        return 1;
    }
    memset(hashes_array, 0, number_of_files * sizeof(UINT16));

    wchar_t input_path_format[] = L"%s %s\\input_%05d%s";
    wchar_t input_path[200] = L"";
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    for (UINT32 i = 0; i < number_of_files; i++) {
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        swprintf_s(input_path, 200, input_path_format, program_path, input_dir, i, extension);

        if (!CreateProcess(NULL,
            input_path,
            NULL,
            NULL,
            FALSE,
            DEBUG_ONLY_THIS_PROCESS,
            NULL,
            NULL,
            &si,
            &pi
        )) {
            printf("CreateProcess failed (%d).\n", GetLastError());
            return 1;
        }

        DEBUG_EVENT DebugEv = { 0 };
        DWORD dwContinueStatus = 0;
        // Debugger loop 
        UINT16 hash = EnterDebugLoop(&DebugEv);
        hashes_array[i] = hash;
        printf("%d. hash : 0x%04X\n", i, hash);
        DebugActiveProcessStop(pi.dwProcessId);
        TerminateProcess(pi.hProcess, 0);

        // Close process and thread handles. 
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    dispatch_input_files(hashes_array, number_of_files, input_dir, output_dir, extension);
    return 0;
}

UINT16 EnterDebugLoop(const LPDEBUG_EVENT DebugEv) {
    UINT32 nbr_of_exceptions = 0;
    // We sum (EIP & 0xffff) at each exception and use this value as a hash to identify a given input
    UINT16 hash = 0;
    DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 
    CONTEXT context = { 0 };
    CString strRegisters;
    HANDLE hThread;
    for (;;) {
        if (WaitForDebugEvent(DebugEv, TIMEOUT_VALUE) == 0) {
            // Process either did not crash or hangs for more than TIMEOUT_VALUE
            if (nbr_of_exceptions > 1) {
                return hash;
            }
            else {
                return 0;
            }
        }
        hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, DebugEv->dwThreadId);
        if (hThread == NULL) {
            printf("Failed to retreive thread handle from thread id. GetLastError: %d", GetLastError());
            return 0;
        }
        context.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hThread, &context);
        strRegisters.Format(
            L"EAX = %08X EBX = %08X ECX = %08X\n"
            L"EDX = %08X ESI = %08X EDI = %08X\n"
            L"EIP = %08X ESP = %08X EBP = %08X\n"
            L"EFL = %08X",
            context.Rax, context.Rbx, context.Rcx,
            context.Rdx, context.Rsi, context.Rdi,
            context.Rip, context.Rsp, context.Rbp,
            context.EFlags
        );

        switch (DebugEv->dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            // We count the number of exceptions. 
            // In a non-crashing run this number should be 1 (initial breakpoint) otherwise it is > 1.
            nbr_of_exceptions++;
            hash += (UINT16) (context.Rip * (context.Rip + 3));
            debug_print(L"EXCEPTION_DEBUG_EVENT Exception Code: ");

            switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode) {
            case EXCEPTION_ACCESS_VIOLATION:
                debug_print(L"EXCEPTION_ACCESS_VIOLATION\n");
                debug_print(L"%s\n", (LPCTSTR) strRegisters);
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;

            case EXCEPTION_BREAKPOINT:
                debug_print(L"EXCEPTION_BREAKPOINT\n");
                debug_print(L"%s\n", (LPCTSTR) strRegisters);
                dwContinueStatus = DBG_CONTINUE;
                break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
                debug_print(L"EXCEPTION_DATATYPE_MISALIGNMENT\n");
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;

            case EXCEPTION_SINGLE_STEP:
                debug_print(L"EXCEPTION_SINGLE_STEPT\n");
                dwContinueStatus = DBG_CONTINUE;
                break;

            case DBG_CONTROL_C:
                debug_print(L"EXCEPTION_DBG_CONTROL_C\n");
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;

            default:
                debug_print(L"OTHER EXCEPTION\n");
                debug_print(L"%s\n", (LPCTSTR) strRegisters);
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;
            }

            break;

        case CREATE_THREAD_DEBUG_EVENT:
            debug_print(L"CREATE_THREAD_DEBUG_EVENT\n");
            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            debug_print(L"CREATE_PROCESS_DEBUG_EVENT\n");
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            debug_print(L"EXIT_THREAD_DEBUG_EVENT\n");
            debug_print(L"Thread exited with code:  0x%x\n", DebugEv->u.ExitThread.dwExitCode);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            debug_print(L"EXIT_PROCESS_DEBUG_EVENT\n");
            debug_print(L"Process exited with code:  0x%x\n", DebugEv->u.ExitProcess.dwExitCode);
            if (nbr_of_exceptions > 1) {
                return hash;
            }
            else {
                return 0;
            }

            break;

        case LOAD_DLL_DEBUG_EVENT:
            //debug_print(L"LOAD_DLL_DEBUG_EVENT\n");
            CloseHandle(DebugEv->u.LoadDll.hFile);
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            //debug_print(L"UNLOAD_DLL_DEBUG_EVENT\n");
            //debug_print(L"Dll at %p has been unloaded\n", DebugEv->u.UnloadDll.lpBaseOfDll);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            debug_print(L"OUTPUT_DEBUG_STRING_DEBUG_EVENT\n");
            break;

        case RIP_EVENT:
            debug_print(L"RIP_EVENT\n");
            break;
        }
        CloseHandle(hThread);
        ContinueDebugEvent(DebugEv->dwProcessId,
            DebugEv->dwThreadId,
            dwContinueStatus);
    }

}

