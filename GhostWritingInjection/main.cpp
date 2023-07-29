#include "GhostWritingInjection.h"
#include "../Common/PE.h"

int main(int argc, char** argv)
{
    DWORD threadId = atoi(argv[1]);
    PE dll = PE(argv[2]);

    GhostWritingInjection(threadId, dll);
    return 0;
}
