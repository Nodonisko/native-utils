#ifndef SECP256K1_WRAPPER_H
#define SECP256K1_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "secp256k1/include/secp256k1.h"

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
namespace secp256k1_wrapper {
    // Convenience class for managing secp256k1 context
    class Context {
    private:
        secp256k1_context* ctx;
        
    public:
        Context(unsigned int flags = SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY) {
            ctx = secp256k1_context_create(flags);
        }
        
        ~Context() {
            if (ctx) {
                secp256k1_context_destroy(ctx);
            }
        }
        
        // Disable copy constructor and assignment
        Context(const Context&) = delete;
        Context& operator=(const Context&) = delete;
        
        // Allow move constructor and assignment
        Context(Context&& other) noexcept : ctx(other.ctx) {
            other.ctx = nullptr;
        }
        
        Context& operator=(Context&& other) noexcept {
            if (this != &other) {
                if (ctx) {
                    secp256k1_context_destroy(ctx);
                }
                ctx = other.ctx;
                other.ctx = nullptr;
            }
            return *this;
        }
        
        secp256k1_context* get() const {
            return ctx;
        }
        
        operator secp256k1_context*() const {
            return ctx;
        }
    };
}
#endif

#endif // SECP256K1_WRAPPER_H 