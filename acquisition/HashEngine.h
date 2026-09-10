#pragma once

#include <cstddef>
#include <string>

// Forward-declared instead of #include <openssl/evp.h> here, so consumers
// of this header don't need OpenSSL's headers on their include path too.
typedef struct evp_md_ctx_st EVP_MD_CTX;

namespace core::acquisition {

    // Streaming SHA-256 hasher over OpenSSL's EVP API.
    //
    // Usage:
    //   HashEngine hasher;
    //   hasher.update(buffer, bytesRead);   // call once per chunk as data streams in
    //   ...
    //   std::string digest = hasher.finalize(); // lowercase hex digest, call once at the end
    //
    // Built so DiskImager can call update() on each O_DIRECT read buffer as it
    // streams the image to disk, instead of re-reading the whole image to hash
    // it afterwards.
    class HashEngine {
    public:
        HashEngine();
        ~HashEngine();

        // Owns an OpenSSL context; not safe to copy.
        HashEngine(const HashEngine&) = delete;
        HashEngine& operator=(const HashEngine&) = delete;

        // Feed the next chunk into the running hash.
        // Returns false on an OpenSSL error, or if called after finalize().
        bool update(const void* data, size_t length);

        // Finalize the hash and return the lowercase hex digest.
        // Idempotent: calling it again just returns the cached digest.
        std::string finalize();

        // Reset to a clean state so the same instance can be reused for a new stream.
        void reset();

    private:
        EVP_MD_CTX* ctx_ = nullptr;
        bool finalized_ = false;
        std::string cachedDigest_;
    };

} // namespace core::acquisition
