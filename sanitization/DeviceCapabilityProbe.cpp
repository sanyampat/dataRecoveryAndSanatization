#include "DeviceCapabilityProbe.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/nvme_ioctl.h>
#include <scsi/sg.h>
#include <sys/stat.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;
namespace core::sanitization {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string DeviceCapabilityProbe::readSysfsValue(const std::string& path) const {
    std::ifstream f(path);
    std::string v;
    if (f.is_open()) {
        std::getline(f, v);
        auto last = v.find_last_not_of(" \n\r\t");
        if (last != std::string::npos) v.erase(last + 1);
        else v.clear();
    }
    return v;
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

DeviceCapabilities DeviceCapabilityProbe::probe(const core::drive::DriveInfo& drive) const {
    return probeByPath(drive.devicePath);
}

DeviceCapabilities DeviceCapabilityProbe::probeByPath(const std::string& devicePath) const {
    DeviceCapabilities caps;
    caps.devicePath = devicePath;

    // 1. Sysfs metadata
    const std::string devName = fs::path(devicePath).filename().string();
    probeSysfs(devName, caps);

    // 2. Mount state
    probeMounts(caps);

    // 3. Hardware protocol probing (requires open fd)
    int fd = open(devicePath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        std::cerr << "[DeviceCapabilityProbe] Cannot open " << devicePath << " for probing.\n";
        return caps;
    }

    probeVirtualDisk(fd, caps);

    // Choose hardware probe path based on device name / sysfs bus
    if (devName.rfind("nvme", 0) == 0) {
        caps.bus = DeviceCapabilities::BusType::NVME;
        probeNvme(fd, caps);
    } else {
        // Attempt ATA passthrough first; fall back to SCSI inquiry
        probeAta(fd, caps);
        if (!caps.supportsAtaSanitizeCrypto && !caps.supportsAtaSanitizeBlock &&
            !caps.supportsAtaSecurityErase) {
            probeScsi(fd, caps);
        }
    }

    close(fd);
    return caps;
}

// ---------------------------------------------------------------------------
// 1. Sysfs
// ---------------------------------------------------------------------------

void DeviceCapabilityProbe::probeSysfs(const std::string& devName, DeviceCapabilities& caps) const {
    const std::string base = "/sys/block/" + devName;

    caps.model  = readSysfsValue(base + "/device/model");
    caps.vendor = readSysfsValue(base + "/device/vendor");
    if (caps.model.empty())  caps.model  = readSysfsValue(base + "/device/device/model");
    if (caps.vendor.empty()) caps.vendor = readSysfsValue(base + "/device/device/vendor");
    caps.serialNumber    = readSysfsValue(base + "/device/serial");
    caps.firmwareRevision= readSysfsValue(base + "/device/firmware_rev");

    // Sector sizes
    auto parse32 = [](const std::string& s, uint32_t def) -> uint32_t {
        try { return static_cast<uint32_t>(std::stoul(s)); } catch (...) { return def; }
    };
    caps.logicalSectorSize  = parse32(readSysfsValue(base + "/queue/logical_block_size"),  512);
    caps.physicalSectorSize = parse32(readSysfsValue(base + "/queue/physical_block_size"), caps.logicalSectorSize);

    // Capacity (sysfs reports in 512-byte blocks)
    try {
        std::string sizeStr = readSysfsValue(base + "/size");
        if (!sizeStr.empty()) caps.capacityBytes = std::stoull(sizeStr) * 512ULL;
    } catch (...) {}

    // Rotational
    std::string rot = readSysfsValue(base + "/queue/rotational");
    caps.isRotational = (rot == "1");
    caps.media        = caps.isRotational ? DeviceCapabilities::MediaType::HDD
                                          : DeviceCapabilities::MediaType::SSD;

    // Removable
    caps.isRemovable = (readSysfsValue(base + "/removable") == "1");

    // Bus type from device name
    if (devName.rfind("nvme", 0) == 0) {
        caps.bus = DeviceCapabilities::BusType::NVME;
        caps.media = DeviceCapabilities::MediaType::SSD;
        caps.isRotational = false;
    } else if (devName.rfind("sd", 0) == 0) {
        // Could be SATA, SCSI, or USB — resolved further by probeAta/probeScsi
        caps.bus = DeviceCapabilities::BusType::SATA;
    }
    // USB bus heuristic via sysfs symlink
    std::error_code ec;
    std::string real = fs::weakly_canonical(fs::path(base), ec).string();
    if (!ec && (real.find("/usb") != std::string::npos)) {
        caps.bus = DeviceCapabilities::BusType::USB;
    }
}

// ---------------------------------------------------------------------------
// 2. Mount state
// ---------------------------------------------------------------------------

void DeviceCapabilityProbe::probeMounts(DeviceCapabilities& caps) const {
    std::ifstream f("/proc/mounts");
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string dev, mnt;
        if (!(iss >> dev >> mnt)) continue;
        if (dev == caps.devicePath || dev.rfind(caps.devicePath, 0) == 0) {
            caps.isMounted = true;
            caps.mountPoints.push_back(mnt);
            if (mnt == "/" || mnt == "/boot" || mnt == "/boot/efi" ||
                mnt == "/usr" || mnt == "/etc" || mnt == "/home") {
                caps.isSystemDisk = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. NVMe capability probing (Identify Controller — SANICAP, OACS, FNA)
// ---------------------------------------------------------------------------

void DeviceCapabilityProbe::probeNvme(int fd, DeviceCapabilities& caps) const {
    uint8_t id_ctrl[4096] = {};
    struct nvme_admin_cmd cmd = {};
    cmd.opcode   = 0x06;  // Identify
    cmd.nsid     = 0;
    cmd.addr     = reinterpret_cast<__u64>(id_ctrl);
    cmd.data_len = 4096;
    cmd.cdw10    = 1;     // CNS = 1 (Controller)

    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) != 0) {
        std::cerr << "[DeviceCapabilityProbe] NVMe Identify Controller failed.\n";
        return;
    }

    // Model (bytes 24–63, padded with spaces)
    {
        std::string m(reinterpret_cast<const char*>(id_ctrl + 24), 40);
        auto last = m.find_last_not_of(' ');
        caps.model = (last != std::string::npos) ? m.substr(0, last + 1) : m;
    }
    // Serial (bytes 4–23)
    {
        std::string s(reinterpret_cast<const char*>(id_ctrl + 4), 20);
        auto last = s.find_last_not_of(' ');
        caps.serialNumber = (last != std::string::npos) ? s.substr(0, last + 1) : s;
    }

    uint16_t oacs;   std::memcpy(&oacs,   id_ctrl + 256, 2);
    uint32_t sanicap; std::memcpy(&sanicap, id_ctrl + 328, 4);
    uint8_t  fna     = id_ctrl[524];

    caps.supportsNvmeSanitizeCrypto    = (sanicap & (1u << 0)) != 0;
    caps.supportsNvmeSanitizeBlock     = (sanicap & (1u << 1)) != 0;
    caps.supportsNvmeSanitizeOverwrite = (sanicap & (1u << 2)) != 0;
    caps.supportsNvmeFormatUser        = (oacs & (1u << 1)) != 0;
    caps.supportsNvmeFormatCrypto      = caps.supportsNvmeFormatUser && ((fna & (1u << 1)) != 0);

    caps.media = DeviceCapabilities::MediaType::SSD;
    caps.bus   = DeviceCapabilities::BusType::NVME;
}

// ---------------------------------------------------------------------------
// 4. ATA capability probing (IDENTIFY DEVICE via SG_IO ATA passthrough)
// ---------------------------------------------------------------------------

void DeviceCapabilityProbe::probeAta(int fd, DeviceCapabilities& caps) const {
    // ATA passthrough via SCSI Generic — 16-byte CDB
    // We send ATA IDENTIFY DEVICE (opcode 0xEC)
    constexpr int ATA_IDENTIFY_DEVICE = 0xEC;
    constexpr size_t ID_LEN = 512;

    uint8_t id_buf[ID_LEN] = {};
    uint8_t sense_buf[32]  = {};

    // 16-byte ATA passthrough CDB (see SAT-5)
    uint8_t cdb[16] = {};
    cdb[0]  = 0x85;        // ATA PASSTHROUGH (16)
    cdb[1]  = (4 << 1);    // PROTOCOL = 4 (PIO Data-In)
    cdb[2]  = 0x2E;        // CK_COND=1, T_DIR=1 (to host), BYT_BLOK=1, T_LENGTH=2 (sector count)
    cdb[6]  = 1;           // sector count = 1
    cdb[14] = ATA_IDENTIFY_DEVICE;

    sg_io_hdr_t io = {};
    io.interface_id    = 'S';
    io.cmd_len         = 16;
    io.cmdp            = cdb;
    io.dxfer_direction = SG_DXFER_FROM_DEV;
    io.dxfer_len       = ID_LEN;
    io.dxferp          = id_buf;
    io.sbp             = sense_buf;
    io.mx_sb_len       = sizeof(sense_buf);
    io.timeout         = 3000;  // ms

    if (ioctl(fd, SG_IO, &io) != 0) {
        return;  // Not an ATA device / no SG support — caller will try SCSI
    }
    if (io.status || (io.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
        return;
    }

    // ATA IDENTIFY DEVICE words are 16-bit little-endian
    auto word = [&id_buf](size_t w) -> uint16_t {
        return static_cast<uint16_t>(id_buf[w * 2] | (id_buf[w * 2 + 1] << 8));
    };

    // Model string — words 27–46 (big-endian per-word byte swap)
    if (caps.model.empty()) {
        std::string m;
        for (size_t w = 27; w <= 46; ++w) {
            uint16_t wv = word(w);
            m += static_cast<char>((wv >> 8) & 0xFF);
            m += static_cast<char>(wv & 0xFF);
        }
        auto last = m.find_last_not_of(' ');
        caps.model = (last != std::string::npos) ? m.substr(0, last + 1) : m;
    }

    // Confirm bus as SATA (sdX ATA device)
    caps.bus = DeviceCapabilities::BusType::SATA;

    // Word 76 — SATA capabilities (exists on SATA, absent on PATA = 0x0000/0xFFFF)
    uint16_t w76 = word(76);
    bool isSata = (w76 != 0x0000 && w76 != 0xFFFF);
    if (!isSata) return;  // PATA — skip ATA Sanitize (never supported on PATA)

    // Word 59 (byte 1) + Word 61: Sector count — rotational check
    // Word 82 bit 5: Security feature set supported
    uint16_t w82 = word(82);
    uint16_t w85 = word(85);  // current enabled features
    uint16_t w128 = word(128); // Security status

    caps.supportsAtaSecurityErase    = (w82 & (1u << 1)) != 0;
    caps.supportsAtaEnhSecurityErase = (w82 & (1u << 5)) != 0;
    caps.ataSecurityFrozen           = (w128 & (1u << 3)) != 0;

    // ATA Sanitize feature set — Word 59 bit 12, Word 255 (vendor specific differs)
    // Better detection: word 119 (supported features ext) + word 120 (enabled ext)
    uint16_t w119 = word(119);
    uint16_t w120 = word(120);
    (void)w85; (void)w120;
    // Word 59 bits 12–15 (ACS-3+): Sanitize feature set
    uint16_t w59  = word(59);
    bool sanitizeSetSupported = (w119 & (1u << 6)) != 0  // Word 119 bit 6 = SANITIZE
                             || (w59  & (1u << 12)) != 0;

    if (sanitizeSetSupported) {
        // Word 59 bits 13–15 report specific sanitize sub-commands
        caps.supportsAtaSanitizeCrypto    = (w59 & (1u << 14)) != 0;
        caps.supportsAtaSanitizeBlock     = (w59 & (1u << 15)) != 0;
        caps.supportsAtaSanitizeOverwrite = (w59 & (1u << 13)) != 0;
    }
}

// ---------------------------------------------------------------------------
// 5. SCSI INQUIRY + mode sense
// ---------------------------------------------------------------------------

void DeviceCapabilityProbe::probeScsi(int fd, DeviceCapabilities& caps) const {
    // Standard INQUIRY (response data page 0)
    uint8_t inq[96]    = {};
    uint8_t sense[32]  = {};
    uint8_t cdb[6]     = { 0x12, 0, 0, 0, sizeof(inq), 0 };

    sg_io_hdr_t io = {};
    io.interface_id    = 'S';
    io.cmd_len         = 6;
    io.cmdp            = cdb;
    io.dxfer_direction = SG_DXFER_FROM_DEV;
    io.dxfer_len       = sizeof(inq);
    io.dxferp          = inq;
    io.sbp             = sense;
    io.mx_sb_len       = sizeof(sense);
    io.timeout         = 3000;

    if (ioctl(fd, SG_IO, &io) != 0) return;
    if (io.status || (io.info & SG_INFO_OK_MASK) != SG_INFO_OK) return;

    // Vendor (bytes 8–15) + Product (bytes 16–31)
    if (caps.vendor.empty()) {
        std::string v(reinterpret_cast<const char*>(inq + 8), 8);
        auto last = v.find_last_not_of(' ');
        caps.vendor = (last != std::string::npos) ? v.substr(0, last + 1) : v;
    }
    if (caps.model.empty()) {
        std::string m(reinterpret_cast<const char*>(inq + 16), 16);
        auto last = m.find_last_not_of(' ');
        caps.model = (last != std::string::npos) ? m.substr(0, last + 1) : m;
    }

    // Peripheral device type (byte 0 bits 0–4): 0=disk, others = not a direct-access device
    uint8_t devType = inq[0] & 0x1F;
    if (devType != 0x00) return;  // Not a direct-access block device — no sanitize

    // SCSI Sanitize is identified via Supported VPD Pages (page 0x00) and
    // Block Device Characteristics VPD page, but reliably is in the
    // "Sanitize" command opcode presence. We use the INQUIRY byte 5 bit 0 (third-party copy)
    // as a coarse heuristic; actual sanitize discovery requires VPD page 0x1C.
    // For now: mark SCSI bus and enable format unit as fallback.
    caps.bus = DeviceCapabilities::BusType::SCSI;
    caps.supportsScsiFormatUnit = true;

    // Attempt VPD page 0x1C — Block Device Characteristics
    // byte 0x00B (offset 11) — SANITIZE COMMAND bit
    uint8_t vpd[64]   = {};
    uint8_t vcdb[6]   = { 0x12, 0x01, 0x1C, 0, sizeof(vpd), 0 };
    sg_io_hdr_t io2   = {};
    uint8_t sense2[32]= {};
    io2.interface_id    = 'S';
    io2.cmd_len         = 6;
    io2.cmdp            = vcdb;
    io2.dxfer_direction = SG_DXFER_FROM_DEV;
    io2.dxfer_len       = sizeof(vpd);
    io2.dxferp          = vpd;
    io2.sbp             = sense2;
    io2.mx_sb_len       = sizeof(sense2);
    io2.timeout         = 2000;
    if (ioctl(fd, SG_IO, &io2) == 0 && !io2.status &&
        (io2.info & SG_INFO_OK_MASK) == SG_INFO_OK) {
        caps.supportsScsiSanitize = (vpd[8] & (1u << 6)) != 0;  // SANITIZE bit per SBC-4
    }
}

// ---------------------------------------------------------------------------
// 6. Virtual disk / hypervisor detection
// ---------------------------------------------------------------------------

void DeviceCapabilityProbe::probeVirtualDisk(int fd, DeviceCapabilities& caps) const {
    (void)fd;  // Not needed — we use sysfs model/vendor strings already collected

    // Canonicalise both to upper for comparison
    auto upper = [](std::string s) {
        for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        return s;
    };

    std::string m = upper(caps.model);
    std::string v = upper(caps.vendor);

    const char* virtKeys[] = {
        "VMWARE", "VBOX", "VIRTUALBOX", "QEMU", "KVM", "VIRTUAL", "VIRT", nullptr
    };
    for (const char** k = virtKeys; *k; ++k) {
        if (m.find(*k) != std::string::npos || v.find(*k) != std::string::npos) {
            caps.isVirtual = true;
            return;
        }
    }
}

} // namespace core::sanitization
