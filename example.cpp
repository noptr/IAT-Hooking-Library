#include "IATHooker.h"

int __stdcall HookedMsgBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    std::cout << "MessageBoxaaA Called: " << lpText << std::endl;
    return 0;
}

void InitHook() {
    iat_hooker::SetExportHook("user32.dll", "MessageBoxA", (void*)HookedMsgBox);
}