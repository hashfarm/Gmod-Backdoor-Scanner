#include "ScanApplication.h"

#ifdef _WIN32
int wmain(int argc, wchar_t* argv[]) {
    return RunScanner(argc, const_cast<const wchar_t**>(argv));
}
#else
int main(int argc, char* argv[]) {
    return RunScanner(argc, const_cast<const char**>(argv));
}
#endif
