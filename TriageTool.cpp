#include <windows.h>
#include <stdio.h>
#include <atlstr.h>

#define DBG 1

#define debug_print(...) \
            do { if (DBG) fwprintf(stderr, __VA_ARGS__); } while (0)


void EnterDebugLoop(const LPDEBUG_EVENT DebugEv);

int main(int argc, char* argv[]) {
    DWORD exit_code;
    wchar_t input_path[150] = L"";
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    int i = 0;
    swprintf_s(input_path, 150, L"C:\\Users\\Richard\\Documents\\winafl\\build32\\bin\\Release\\opentext_harness_5.exe E:\\Fuzz\\crash\\input_%d.dwg", i);

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
    EnterDebugLoop(&DebugEv);

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

void EnterDebugLoop(const LPDEBUG_EVENT DebugEv) {
    DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 
    CONTEXT context = { 0 };
    CString strRegisters;
    HANDLE hThread;
    for (;;) {
        WaitForDebugEvent(DebugEv, INFINITE);
        hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, DebugEv->dwThreadId);
        if (hThread == NULL) {
            printf("Failed to retreive thread handle from thread id. GetLastError: %d", GetLastError());
            return;
        }
        context.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hThread, &context);
        strRegisters.Format(
            L"EAX = %08X EBX = %08X ECX = %08X\n"
            L"EDX = %08X ESI = %08X EDI = %08X\n"
            L"EIP = %08X ESP = %08X EBP = %08X\n"
            L"EFL = %08X",
            context.Eax, context.Ebx, context.Ecx,
            context.Edx, context.Esi, context.Edi,
            context.Eip, context.Esp, context.Ebp,
            context.EFlags
        );

        switch (DebugEv->dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            debug_print(L"EXCEPTION_DEBUG_EVENT Exception Code: ");
            // Process the exception code. When handling 
            // exceptions, remember to set the continuation 
            // status parameter (dwContinueStatus). This value 
            // is used by the ContinueDebugEvent function. 

            switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode) {
            case EXCEPTION_ACCESS_VIOLATION:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                debug_print(L"EXCEPTION_ACCESS_VIOLATION\n");
                debug_print(L"%s\n", (LPCTSTR) strRegisters);
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;

            case EXCEPTION_BREAKPOINT:
                // First chance: Display the current 
                // instruction and register values. 
                debug_print(L"EXCEPTION_BREAKPOINT\n");
                debug_print(L"%s\n", (LPCTSTR) strRegisters);
                dwContinueStatus = DBG_CONTINUE;
                break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                debug_print(L"EXCEPTION_DATATYPE_MISALIGNMENT\n");
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;

            case EXCEPTION_SINGLE_STEP:
                // First chance: Update the display of the 
                // current instruction and register values. 
                debug_print(L"EXCEPTION_SINGLE_STEPT\n");
                dwContinueStatus = DBG_CONTINUE;
                break;

            case DBG_CONTROL_C:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                debug_print(L"EXCEPTION_DBG_CONTROL_C\n");
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;

            default:
                // Handle other exceptions. 
                debug_print(L"OTHER EXCEPTION\n");
                debug_print(L"%s\n", (LPCTSTR) strRegisters);
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;
            }

            break;

        case CREATE_THREAD_DEBUG_EVENT:
            // As needed, examine or change the thread's registers 
            // with the GetThreadContext and SetThreadContext functions; 
            // and suspend and resume thread execution with the 
            // SuspendThread and ResumeThread functions. 
            debug_print(L"CREATE_THREAD_DEBUG_EVENT\n");
            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            // As needed, examine or change the registers of the
            // process's initial thread with the GetThreadContext and
            // SetThreadContext functions; read from and write to the
            // process's virtual memory with the ReadProcessMemory and
            // WriteProcessMemory functions; and suspend and resume
            // thread execution with the SuspendThread and ResumeThread
            // functions. Be sure to close the handle to the process image
            // file with CloseHandle.
            debug_print(L"CREATE_PROCESS_DEBUG_EVENT\n");
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            // Display the thread's exit code. 
            debug_print(L"EXIT_THREAD_DEBUG_EVENT\n");

            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            // Display the process's exit code. 
            debug_print(L"EXIT_PROCESS_DEBUG_EVENT\n");
            debug_print(L"Process exited with code:  0x%x", DebugEv->u.ExitProcess.dwExitCode);
            return;

            break;

        case LOAD_DLL_DEBUG_EVENT:
            // Read the debugging information included in the newly 
            // loaded DLL. Be sure to close the handle to the loaded DLL 
            // with CloseHandle.

            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            // Display a message that the DLL has been unloaded. 

            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            // Display the output debugging string. 
            break;

        case RIP_EVENT:
            break;
        }
        CloseHandle(hThread);
        ContinueDebugEvent(DebugEv->dwProcessId,
            DebugEv->dwThreadId,
            dwContinueStatus);
    }

}

