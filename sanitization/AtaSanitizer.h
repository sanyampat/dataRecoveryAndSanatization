#pragma once

#include "DeviceCapabilities.h"
#include "SanitizationResult.h"

namespace core::sanitization {

/// ATA / SATA sanitization commands:
///   1. ATA Sanitize — Crypto Scramble EXT  → PURGE
///   2. ATA Sanitize — Block Erase EXT      → PURGE
///   3. ATA Security Erase (Enhanced)        → PURGE
///   4. Fallback → GenericBlockSanitizer    → CLEAR (called by SanitizationEngine)
///
/// All commands sent via SCSI generic (SG_IO) ATA passthrough.
class AtaSanitizer {
public:
    AtaSanitizer()  = default;
    ~AtaSanitizer() = default;

    /// Execute the strongest available ATA Purge operation.
    SanitizationResult purge(const DeviceCapabilities& caps) const;

private:
    // ATA Sanitize commands
    SanitizationResult ataSanitizeCrypto(int fd, const DeviceCapabilities& caps) const;
    SanitizationResult ataSanitizeBlock (int fd, const DeviceCapabilities& caps) const;

    // ATA Security Erase
    SanitizationResult ataSecurityErase(int fd, const DeviceCapabilities& caps,
                                        bool enhanced) const;

    // Poll SANITIZE DEVICE STATUS EXT until done or timeout
    bool waitSanitizeComplete(int fd, unsigned timeoutSeconds = 600) const;

    // Build and send a SCSI generic ATA passthrough command
    bool sendAtaCommand(int fd, uint8_t cmd, uint8_t feature, uint16_t count,
                        uint64_t lba, uint8_t* buf, size_t bufLen,
                        bool dataIn, uint8_t* senseOut, size_t senseLen) const;
};

} // namespace core::sanitization
