#include "HashEngine.h"

#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace core::acquisition {

    HashEngine::HashEngine() {
        ctx_ = EVP_MD_CTX_new();
        if (!ctx_) {
            throw std::runtime_error("HashEngine: failed to allocate EVP_MD_CTX");
        }

        if (EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx_);
            ctx_ = nullptr;
            throw std::runtime_error("HashEngine: EVP_DigestInit_ex failed");
        }
    }

    HashEngine::~HashEngine() {
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
        }
    }

    bool HashEngine::update(const void* data, size_t length) {
        if (finalized_ || !ctx_) return false;
        if (length == 0) return true; // nothing to hash, not an error

        return EVP_DigestUpdate(ctx_, data, length) == 1;
    }

    std::string HashEngine::finalize() {
        if (finalized_) {
            return cachedDigest_; // already finalized, return cached result
        }

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestLen = 0;

        if (!ctx_ || EVP_DigestFinal_ex(ctx_, digest, &digestLen) != 1) {
            finalized_ = true;
            cachedDigest_.clear();
            return cachedDigest_;
        }

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < digestLen; ++i) {
            oss << std::setw(2) << static_cast<int>(digest[i]);
        }

        cachedDigest_ = oss.str();
        finalized_ = true;
        return cachedDigest_;
    }

    void HashEngine::reset() {
        if (ctx_) {
            EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr);
        }
        finalized_ = false;
        cachedDigest_.clear();
    }

} // namespace core::acquisition
