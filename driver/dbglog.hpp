#pragma once
#include "imports.hpp"

#define DBGPRINT 0

#if (DBGPRINT == 1)
#define LOG(x, ...) {CALL_NO_RET(DbgPrint, x "\n", __VA_ARGS__);}//DbgPrint(x "\n", __VA_ARGS__)
#else
#define LOG(x, ...)
#endif
