// W3's C++ /MD /EHsc check: exercises _CxxThrowException, __CxxFrameHandler4, RAII destructors,
// and std::runtime_error over D-CMPL's built-in vcruntime140 / vcruntime140_1 / ucrtbase.

#include <stdexcept>

namespace {

int w3_destroyed;

struct W3Guard {
    ~W3Guard() { w3_destroyed++; }
};

struct W3Err {
    int code;
};

__declspec(noinline) void w3_inner(int v)
{
    W3Guard g;
    if (v > 0)
        throw W3Err{v};
}

__declspec(noinline) void w3_outer(int v)
{
    W3Guard g;
    w3_inner(v);
}

} // namespace

extern "C" int w3_cxx_test(void)
{
    w3_destroyed = 0;
    int r = 0;
    try {
        w3_outer(5678);
    } catch (const W3Err &e) {
        r = e.code;
    }
    try {
        throw std::runtime_error("w3 dynamic crt exception");
    } catch (const std::exception &) {
        r = (w3_destroyed == 2) ? r : -w3_destroyed;
    }
    return r;
}
