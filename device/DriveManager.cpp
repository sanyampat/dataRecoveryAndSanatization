#include "DriveManager.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

namespace core::drive {

    struct MountEntry {
        std::string device;
        std::string mountPoint;
    };

    static std::vector<MountEntry> readSystemMounts() {
        std::vector<MountEntry> mounts;
        std::ifstream file("/proc/mounts");
        if (!file.is_open()) {
            return mounts;
        }
        std::string line;
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string dev, mnt;
            if (iss >> dev >> mnt) {
                mounts.push_back({dev, mnt});
            }
        }
        return mounts;
    }

    std::string DriveManager::readSysfsValue(
        const std::string& path
    ) const {

        std::ifstream file(path);
        std::string value;

        if (file.is_open()) {
            std::getline(file, value);

            // Trim trailing whitespace safely
            const auto last = value.find_last_not_of(" \n\r\t");

            if (last != std::string::npos) {
                value.erase(last + 1);
            } else {
                value.clear();
            }
        }

        return value;
    }

    BusType DriveManager::determineBusType(
        const std::string& devName,
        const std::string& sysfsPath
    ) const {

        // ----------------------------------------------------
        // NVMe
        // ----------------------------------------------------

        if (devName.find("nvme") == 0) {
            return BusType::NVME;
        }

        // ----------------------------------------------------
        // USB
        // ----------------------------------------------------

        std::error_code ec;

        fs::path devPath(sysfsPath);
        fs::path realPath = fs::weakly_canonical(devPath, ec);

        if (!ec) {
            std::string path = realPath.string();

            if (path.find("/usb") != std::string::npos ||
                path.find("usb") != std::string::npos) {

                return BusType::USB;
            }
        }

        // ----------------------------------------------------
        // SATA / SCSI
        // ----------------------------------------------------

        /*
         * Linux exposes many SATA/SAS/SCSI disks as /dev/sdX.
         *
         * We currently classify standard sdX devices as SATA.
         *
         * This is a baseline only. Later we can use SCSI
         * INQUIRY / ATA IDENTIFY to distinguish them accurately.
         */

        if (devName.find("sd") == 0) {
            return BusType::SATA;
        }

        return BusType::UNKNOWN;
    }

    std::vector<DriveInfo> DriveManager::getAvailableDrives() {

        std::vector<DriveInfo> drives;

        const std::string sysBlockPath = "/sys/block";

        if (!fs::exists(sysBlockPath)) {

            std::cerr
                << "Error: /sys/block does not exist. "
                << "Are you running on Linux?\n";

            return drives;
        }

        const auto mounts = readSystemMounts();

        // ----------------------------------------------------
        // Scan /sys/block
        // ----------------------------------------------------

        for (const auto& entry :
             fs::directory_iterator(sysBlockPath)) {

            std::string devName =
                entry.path().filename().string();

            // ------------------------------------------------
            // Ignore virtual / optical devices
            // ------------------------------------------------

            if (devName.find("loop") == 0 ||
                devName.find("ram") == 0 ||
                devName.find("sr") == 0) {

                continue;
            }

            DriveInfo info;

            info.devicePath =
                "/dev/" + devName;

            std::string basePath =
                entry.path().string();

            // ------------------------------------------------
            // Model
            // ------------------------------------------------

            info.model =
                readSysfsValue(
                    basePath + "/device/model"
                );

            // ------------------------------------------------
            // Serial
            // ------------------------------------------------

            info.serialNumber =
                readSysfsValue(
                    basePath + "/device/serial"
                );

            // ------------------------------------------------
            // NVMe fallback paths
            // ------------------------------------------------

            if (devName.find("nvme") == 0 &&
                info.model.empty()) {

                info.model =
                    readSysfsValue(
                        basePath +
                        "/device/device/model"
                    );
            }

            // ------------------------------------------------
            // Logical sector size
            // ------------------------------------------------

            std::string logicalSizeStr =
                readSysfsValue(
                    basePath +
                    "/queue/logical_block_size"
                );

            if (!logicalSizeStr.empty()) {

                try {
                    info.logicalSectorSize =
                        static_cast<uint32_t>(
                            std::stoul(logicalSizeStr)
                        );

                } catch (...) {

                    info.logicalSectorSize = 512;
                }

            } else {

                info.logicalSectorSize = 512;
            }

            // ------------------------------------------------
            // Physical sector size
            // ------------------------------------------------

            std::string physicalSizeStr =
                readSysfsValue(
                    basePath +
                    "/queue/physical_block_size"
                );

            if (!physicalSizeStr.empty()) {

                try {
                    info.physicalSectorSize =
                        static_cast<uint32_t>(
                            std::stoul(physicalSizeStr)
                        );

                } catch (...) {

                    info.physicalSectorSize =
                        info.logicalSectorSize;
                }

            } else {

                info.physicalSectorSize =
                    info.logicalSectorSize;
            }

            // ------------------------------------------------
            // Capacity
            // ------------------------------------------------

            /*
             * /sys/block/<device>/size is expressed in
             * 512-byte sectors.
             */

            std::string sizeBlocksStr =
                readSysfsValue(
                    basePath + "/size"
                );

            uint64_t sizeBlocks = 0;

            if (!sizeBlocksStr.empty()) {

                try {

                    sizeBlocks =
                        std::stoull(sizeBlocksStr);

                } catch (...) {

                    sizeBlocks = 0;
                }
            }

            info.capacityBytes =
                sizeBlocks * 512ULL;

            // ------------------------------------------------
            // Rotational status
            // ------------------------------------------------

            std::string rotationalStr =
                readSysfsValue(
                    basePath +
                    "/queue/rotational"
                );

            info.isRotational =
                (rotationalStr == "1");

            // ------------------------------------------------
            // Media type
            // ------------------------------------------------

            if (rotationalStr == "1") {

                info.mediaType =
                    MediaType::HDD;

            } else if (rotationalStr == "0") {

                info.mediaType =
                    MediaType::SSD;

            } else {

                info.mediaType =
                    MediaType::UNKNOWN;
            }

            // ------------------------------------------------
            // Bus type
            // ------------------------------------------------

            info.bus =
                determineBusType(
                    devName,
                    basePath
                );

            // ------------------------------------------------
            // Mount Status and System Disk Protection
            // ------------------------------------------------

            for (const auto& m : mounts) {
                if (m.device == info.devicePath ||
                    (m.device.rfind(info.devicePath, 0) == 0)) {
                    info.isMounted = true;
                    info.mountPoints.push_back(m.mountPoint);

                    if (m.mountPoint == "/" ||
                        m.mountPoint == "/boot" ||
                        m.mountPoint == "/boot/efi" ||
                        m.mountPoint == "/usr" ||
                        m.mountPoint == "/etc" ||
                        m.mountPoint == "/home") {
                        info.isSystemDisk = true;
                    }
                }
            }

            // ------------------------------------------------
            // Store drive
            // ------------------------------------------------

            drives.push_back(info);
        }

        return drives;
    }

} // namespace core::drive