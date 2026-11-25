#include <dosdrm/shim.h>

/* Freestanding C++20 runtime hooks for vendored C++ GPU stacks (e.g. NVIDIA nvkms, Mesa). */

void *operator new(size_t size) {
    return dosdrm_kzalloc(size);
}

void *operator new[](size_t size) {
    return dosdrm_kzalloc(size);
}

void operator delete(void *ptr) noexcept {
    dosdrm_kfree(ptr);
}

void operator delete[](void *ptr) noexcept {
    dosdrm_kfree(ptr);
}

void operator delete(void *ptr, size_t) noexcept {
    dosdrm_kfree(ptr);
}

void operator delete[](void *ptr, size_t) noexcept {
    dosdrm_kfree(ptr);
}

extern "C" void __cxa_pure_virtual(void) {
    for (;;) {
        __asm__ volatile("ud2");
    }
}

namespace {

class KmsProbeBase {
public:
    virtual ~KmsProbeBase() = default;
    virtual uint32_t tag(uint32_t seed) const noexcept = 0;
};

class KmsProbeImpl final : public KmsProbeBase {
public:
    explicit constexpr KmsProbeImpl(uint32_t salt) noexcept : salt_(salt) {}
    uint32_t tag(uint32_t seed) const noexcept override {
        return seed ^ salt_;
    }

private:
    uint32_t salt_;
};

} // namespace

extern "C" uint32_t dosdrm_cxx_probe(uint32_t seed) {
    KmsProbeBase *obj = new KmsProbeImpl(0x4B4D5331u);
    if (!obj) {
        return 0;
    }
    const uint32_t res = obj->tag(seed);
    delete obj;
    return res;
}
