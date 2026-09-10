#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace core::sanitization {

/// Capabilities discovered for a single storage device.
/// Populated by DeviceCapabilityProbe::probe() before any sanitization decision is made.
struct DeviceCapabilities {

    // -----------------------------------------------------------------
    // Identity & Classification
    // -----------------------------------------------------------------
    std::string devicePath;
    std::string vendor;
    std::string model;
    std::string firmwareRevision;
    std::string serialNumber;

    enum class BusType  { NVME, SATA, SCSI, USB, UNKNOWN } bus = BusType::UNKNOWN;
    enum class MediaType{ HDD, SSD, UNKNOWN }             media = MediaType::UNKNOWN;

    bool isRotational = false;
    bool isRemovable  = false;
    bool isVirtual    = false;   // VMware, VirtualBox, QEMU, KVM detected

    uint32_t logicalSectorSize  = 512;
    uint32_t physicalSectorSize = 512;
    uint64_t capacityBytes      = 0;

    // -----------------------------------------------------------------
    // Safety State
    // -----------------------------------------------------------------
    bool isMounted    = false;
    bool isSystemDisk = false;
    std::vector<std::string> mountPoints;

    // -----------------------------------------------------------------
    // NVMe Hardware Commands (from Identify Controller + SANICAP)
    // -----------------------------------------------------------------
    bool supportsNvmeSanitizeCrypto    = false;  // SANICAP bit 0 — Crypto Erase
    bool supportsNvmeSanitizeBlock     = false;  // SANICAP bit 1 — Block Erase
    bool supportsNvmeSanitizeOverwrite = false;  // SANICAP bit 2 — Overwrite
    bool supportsNvmeFormatCrypto      = false;  // OACS bit 1 + FNA bit 1 — Format NVM w/ Crypto Erase
    bool supportsNvmeFormatUser        = false;  // OACS bit 1 — Format NVM (user data erase)

    // -----------------------------------------------------------------
    // ATA / SATA Hardware Commands (from ATA IDENTIFY DEVICE via SG_IO)
    // -----------------------------------------------------------------
    bool supportsAtaSanitizeCrypto     = false;  // SANITIZE EXT, Crypto Scramble
    bool supportsAtaSanitizeBlock      = false;  // SANITIZE EXT, Block Erase
    bool supportsAtaSanitizeOverwrite  = false;  // SANITIZE EXT, Overwrite
    bool supportsAtaSecurityErase      = false;  // ATA Security Set Password + Erase Unit
    bool supportsAtaEnhSecurityErase   = false;  // Enhanced security erase
    bool ataSecurityFrozen             = false;  // Security state is frozen (erase blocked)

    // -----------------------------------------------------------------
    // SCSI Hardware Commands (from SCSI INQUIRY)
    // -----------------------------------------------------------------
    bool supportsScsiSanitize          = false;
    bool supportsScsiFormatUnit        = false;

    // -----------------------------------------------------------------
    // Derived Decision Helpers
    // -----------------------------------------------------------------

    /// True if any hardware-level Purge command is available.
    bool canAchievePurge() const {
        return supportsNvmeSanitizeCrypto
            || supportsNvmeSanitizeBlock
            || supportsNvmeFormatCrypto
            || supportsNvmeFormatUser
            || (supportsAtaSanitizeCrypto && !ataSecurityFrozen)
            || (supportsAtaSanitizeBlock   && !ataSecurityFrozen)
            || (supportsAtaSecurityErase   && !ataSecurityFrozen)
            || supportsScsiSanitize;
    }

    /// Human-readable summary of the strongest available Purge method.
    std::string bestMethod() const {
        if (supportsNvmeSanitizeCrypto)              return "NVMe Sanitize — Crypto Erase";
        if (supportsNvmeSanitizeBlock)               return "NVMe Sanitize — Block Erase";
        if (supportsNvmeFormatCrypto)                return "NVMe Format NVM — Crypto Erase";
        if (supportsNvmeFormatUser)                  return "NVMe Format NVM — User Data Erase";
        if (supportsAtaSanitizeCrypto && !ataSecurityFrozen) return "ATA Sanitize — Crypto Scramble";
        if (supportsAtaSanitizeBlock   && !ataSecurityFrozen) return "ATA Sanitize — Block Erase";
        if (supportsAtaEnhSecurityErase&& !ataSecurityFrozen) return "ATA Security Erase — Enhanced";
        if (supportsAtaSecurityErase   && !ataSecurityFrozen) return "ATA Security Erase";
        if (supportsScsiSanitize)                    return "SCSI Sanitize";
        return "Generic Block Overwrite";
    }
};

} // namespace core::sanitization
