// W2's C++ part (docs/compat.md): an exception thrown through two frames with a destructor to
// run on the way, caught by type. Exercises the CRT's C++ exception machinery (_CxxThrowException,
// RaiseException, the frame handler and RtlUnwindEx) on D-CMPL's SEH dispatcher.

#include <stdexcept>

namespace {

int destroyed;

struct Guard {
    ~Guard() { destroyed++; }
};

struct Failure {
    int value;
};

__declspec(noinline) void deep(int v)
{
    Guard g;
    if (v > 0)
        throw Failure{v};
}

__declspec(noinline) void middle(int v)
{
    Guard g;
    deep(v);
}

} // namespace

extern "C" int cxx_throw_catch(void)
{
    int r = 0;
    try {
        middle(1234);
    } catch (const Failure &f) {
        r = f.value;
    }
    try {
        throw std::runtime_error("std exception");
    } catch (const std::exception &) {
        r = destroyed == 2 ? r : -destroyed;
    }
    return r;
}
