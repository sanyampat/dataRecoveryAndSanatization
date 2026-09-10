#pragma once

#include <cstdint>
#include <string>

namespace core::sanitization {

/// Assurance levels per NIST SP 800-88 Rev 2.
enum class AssuranceLevel {
    NONE,   ///< No sanitization was performed.
    CLEAR,  ///< Logical/block-level sanitization (known pattern overwrite).
    PURGE,  ///< Device-level sanitization intended to render previous data infeasible to recover according to the applicable device/storage implementation and standard.
};

inline const char* toString(AssuranceLevel level) {
    switch (level) {
        case AssuranceLevel::CLEAR: return "CLEAR";
        case AssuranceLevel::PURGE: return "PURGE";
        default:                    return "NONE";
    }
}

/// Full auditable result returned by any sanitizer.
struct SanitizationResult {

    bool success  = false;  ///< Overall success (wipe + verification both passed).
    bool blocked  = false;  ///< Safety block fired before any wipe was attempted.

    std::string devicePath;
    std::string mediaType;   ///< e.g. "NVMe SSD", "SATA SSD", "SATA HDD", "Virtual Block Device"
    std::string busType;
    std::string vendor;
    std::string model;
    std::string serialNumber;

    std::string methodApplied;   ///< e.g. "NVMe Sanitize — Crypto Erase"
    AssuranceLevel assuranceLevel = AssuranceLevel::NONE;

    uint64_t capacityBytes   = 0;
    uint64_t bytesProcessed  = 0;

    bool wipePassed               = false;
    
    // -----------------------------------------------------------------
    // Verification Telemetry
    // -----------------------------------------------------------------
    bool verificationAttempted    = false;
    bool verificationPassed       = false;
    std::string verificationMethod; ///< e.g. "Full Sequential Read-Back", "Command Status Validation"
    std::string verificationScope;  ///< e.g. "Full (100%)", "Sampled", "Command Status Only"
    uint32_t samplesChecked       = 0;
    uint64_t bytesVerified        = 0;
    std::string expectedPattern;    ///< e.g. "0x00"
    
    // -----------------------------------------------------------------
    // Error & Mismatch Tracking
    // -----------------------------------------------------------------
    uint64_t firstMismatchOffset  = 0;
    std::string observedByte;
    std::string expectedByte;

    double durationSeconds    = 0.0;
    std::string startedAtUtc;
    std::string completedAtUtc;

    std::string error;  ///< Non-empty only when success == false.
};

} // namespace core::sanitization