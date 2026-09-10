#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "sanitization/SanitizationEngine.h"
#include "sanitization/Verification.h"
#include "device/DriveInfo.h"
#include "device/DriveManager.h"
#include "acquisition/AcquisitionManager.h"
#include "recovery/FileCarver.h"
#include "recovery/FileValidator.h"
#include "recovery/ConfidenceScorer.h"
#include "recovery/FileClassifier.h"
#include "recovery/RecoveredFile.h"

#include <sys/stat.h>
#include <fcntl.h>
#if defined(__linux__)
#include <linux/fs.h>
#include <sys/ioctl.h>
#endif
#if !defined(_WIN32)
#include <unistd.h>
#endif

#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace py = pybind11;

// Helper method to inspect block device or regular image file
static core::drive::DriveInfo makeDriveInfo(const std::string& path)
{
    core::drive::DriveInfo drive;
    drive.devicePath = path;

    struct stat st{};
    if (stat(path.c_str(), &st) != 0) {
        throw std::runtime_error("Cannot stat target: " + path);
    }

    drive.physicalSectorSize = 512;
    drive.logicalSectorSize = 512;

#if defined(__linux__)
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        throw std::runtime_error("Cannot open target: " + path);
    }

    if (S_ISBLK(st.st_mode)) {
        unsigned long long bytes = 0;
        if (ioctl(fd, BLKGETSIZE64, &bytes) != 0) {
            close(fd);
            throw std::runtime_error("Cannot determine block-device capacity: " + path);
        }

        drive.capacityBytes = static_cast<uint64_t>(bytes);

        unsigned int sector = 512;
        if (ioctl(fd, BLKSSZGET, &sector) == 0 && sector > 0) {
            drive.logicalSectorSize = sector;
            drive.physicalSectorSize = sector;
        }

        close(fd);
    } else if (S_ISREG(st.st_mode)) {
        close(fd);
        drive.capacityBytes = static_cast<uint64_t>(st.st_size);
    } else {
        close(fd);
        throw std::runtime_error("Target is not a regular file or block device: " + path);
    }
#else
    drive.capacityBytes = static_cast<uint64_t>(st.st_size);
#endif

    if (path.rfind("/dev/nvme", 0) == 0) {
        drive.bus = core::drive::BusType::NVME;
        drive.mediaType = core::drive::MediaType::SSD;
        drive.isRotational = false;
    } else {
        drive.bus = core::drive::BusType::UNKNOWN;
    }

    return drive;
}

// --- C++ BACKEND API FUNCTIONS ---

py::list get_drives()
{
    core::drive::DriveManager manager;
    auto drives = manager.getAvailableDrives();

    py::list result;

    for (const auto& drive : drives) {
        py::dict d;

        d["device"] = drive.devicePath;
        d["model"] = drive.model;
        d["serial"] = drive.serialNumber;
        d["capacity"] = drive.capacityBytes;
        d["logical_sector_size"] = drive.logicalSectorSize;
        d["physical_sector_size"] = drive.physicalSectorSize;
        d["rotational"] = drive.isRotational;
        d["bus"] = drive.getBusTypeString();
        d["media_type"] = drive.getMediaTypeString();
        d["is_mounted"] = drive.isMounted;
        d["is_system_disk"] = drive.isSystemDisk;
        d["mount_points"] = drive.mountPoints;

        result.append(d);
    }

    return result;
}

py::dict get_drive_info(const std::string& device)
{
    py::dict d;
    core::drive::DriveManager manager;
    auto drives = manager.getAvailableDrives();

    const core::drive::DriveInfo* found = nullptr;
    for (const auto& drv : drives) {
        if (drv.devicePath == device) {
            found = &drv;
            break;
        }
    }

    core::drive::DriveInfo info;
    if (found) {
        info = *found;
    } else {
        try {
            info = makeDriveInfo(device);
        } catch (const std::exception& e) {
            d["device"] = device;
            d["error"] = e.what();
            d["status"] = "Error";
            return d;
        }
    }

    d["device"] = info.devicePath;
    d["model"] = info.model.empty() ? "Generic Block Device" : info.model;
    d["serial"] = info.serialNumber.empty() ? "N/A" : info.serialNumber;
    d["capacity"] = info.capacityBytes;
    d["logical_sector_size"] = info.logicalSectorSize;
    d["physical_sector_size"] = info.physicalSectorSize;
    d["rotational"] = info.isRotational;
    d["bus"] = info.getBusTypeString();
    d["media_type"] = info.getMediaTypeString();
    d["is_mounted"] = info.isMounted;
    d["is_system_disk"] = info.isSystemDisk;
    d["mount_points"] = info.mountPoints;
    d["status"] = info.isSystemDisk ? "Protected (System Disk)" : (info.isMounted ? "Mounted" : "Ready");
    return d;
}

py::dict get_sanitization_info(const std::string& device)
{
    py::dict d;
    d["device"] = device;

    core::drive::DriveManager manager;
    auto drives = manager.getAvailableDrives();

    core::drive::DriveInfo info;
    bool found = false;
    for (const auto& drv : drives) {
        if (drv.devicePath == device) {
            info = drv;
            found = true;
            break;
        }
    }

    if (!found) {
        try {
            info = makeDriveInfo(device);
        } catch (const std::exception& e) {
            d["error"] = e.what();
            d["recommended_protocol"] = "Unknown / Error";
            return d;
        }
    }

    std::string protocol;
    std::string standard;
    std::string description;
    int recommendedPasses = 1;

    switch (info.bus) {
        case core::drive::BusType::NVME:
            protocol = "NVMe Sanitize / Firmware Erase";
            standard = "NIST SP 800-88 Rev 1 (Purge / Clear Fallback)";
            description = "Attempts hardware NVMe Sanitize (Crypto / Block Erase) or NVMe Format; falls back to direct unbuffered O_DIRECT overwrite if unsupported by controller.";
            recommendedPasses = 1;
            break;
        case core::drive::BusType::SATA:
            if (!info.isRotational) {
                protocol = "ATA Sanitize / Secure Erase";
                standard = "NIST SP 800-88 Rev 1 (Purge / Clear Fallback)";
                description = "Attempts firmware-level ATA Sanitize (Crypto Scramble/Block Erase) or ATA Security Erase via SCSI passthrough; falls back to unbuffered block overwrite if unsupported.";
                recommendedPasses = 1;
            } else {
                protocol = "O_DIRECT Multi-Pass Overwrite";
                standard = "DoD 5220.22-M / NIST SP 800-88 Rev 1 (Clear)";
                description = "Direct I/O block overwrite (zeros / random patterns) followed by 1000-point pseudorandom sector verification.";
                recommendedPasses = 3;
            }
            break;
        default:
            protocol = "O_DIRECT Zero-Fill Overwrite";
            standard = "NIST SP 800-88 Rev 1 (Clear)";
            description = "Direct block zero-fill overwrite bypassing kernel page cache (O_DIRECT) with 1000-point random read verification.";
            recommendedPasses = 1;
            break;
    }

    d["bus"] = info.getBusTypeString();
    d["media_type"] = info.getMediaTypeString();
    d["capacity"] = info.capacityBytes;
    d["is_system_disk"] = info.isSystemDisk;
    d["is_mounted"] = info.isMounted;
    d["can_sanitize"] = !info.isSystemDisk && !info.isMounted;
    d["safety_status"] = info.isSystemDisk ? "BLOCKED (Host OS System Disk)" : (info.isMounted ? "WARNING (Device contains mounted partition)" : "SAFE (Unmounted target)");
    d["recommended_protocol"] = protocol;
    d["standard"] = standard;
    d["description"] = description;
    d["recommended_passes"] = recommendedPasses;
    return d;
}

py::dict sanitize_drive(const std::string& target_path, int /*passes*/ = 1)
{
    py::dict res;
    res["target_device"] = target_path;

    core::drive::DriveManager manager;
    auto drives = manager.getAvailableDrives();

    core::drive::DriveInfo info;
    bool found = false;
    for (const auto& drv : drives) {
        if (drv.devicePath == target_path) {
            info = drv;
            found = true;
            break;
        }
    }

    if (!found) {
        try {
            info = makeDriveInfo(target_path);
        } catch (const std::exception& e) {
            res["success"] = false;
            res["blocked"] = false;
            res["wipe_passed"] = false;
            res["verification_passed"] = false;
            res["error"] = e.what();
            return res;
        }
    }

    // CRITICAL SAFETY CHECK: System Disk Protection
    if (info.isSystemDisk) {
        res["success"] = false;
        res["blocked"] = true;
        res["wipe_passed"] = false;
        res["verification_passed"] = false;
        res["error"] = "CRITICAL SAFETY BLOCK: Target device (" + target_path + ") is an active system disk (root/boot). Sanitization blocked to prevent operating system destruction.";
        return res;
    }

    if (info.isMounted) {
        res["success"] = false;
        res["blocked"] = true;
        res["wipe_passed"] = false;
        res["verification_passed"] = false;
        res["error"] = "CRITICAL SAFETY BLOCK: Target device (" + target_path + ") contains actively mounted partitions. Please unmount all partitions before wiping.";
        return res;
    }

    auto start_time = std::chrono::steady_clock::now();

    core::sanitization::SanitizationEngine engine;
    auto sanitizer = engine.getSanitizerForDrive(info);
    std::string proto = sanitizer ? sanitizer->getProtocolName() : "Unknown";

    bool wipeOk = false;
    if (sanitizer) {
        wipeOk = sanitizer->wipe(info);
    }

    bool verifyOk = false;
    if (wipeOk) {
        core::sanitization::Verification verifier;
        verifyOk = verifier.verifyZeroes(info);
    }

    auto end_time = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end_time - start_time).count();

    res["success"] = (wipeOk && verifyOk);
    res["blocked"] = false;
    res["wipe_passed"] = wipeOk;
    res["verification_passed"] = verifyOk;
    res["protocol_applied"] = proto;
    res["duration_seconds"] = elapsed;
    res["capacity_bytes"] = info.capacityBytes;
    res["samples_verified"] = verifyOk ? 1000 : 0;
    res["sample_block_size_bytes"] = 1024 * 1024;

    if (!wipeOk) {
        res["error"] = "Wipe execution failed on device " + target_path + ". Check root permissions or device lock state.";
    } else if (!verifyOk) {
        res["error"] = "Post-sanitization verification failed: non-zero bytes detected during pseudorandom surface sampling.";
    } else {
        res["error"] = "";
    }

    return res;
}

py::list scan_image(const std::string& image_path, const std::string& output_dir = "")
{
    py::list result;
    core::recovery::FileCarver carver;
    core::recovery::FileValidator validator;
    core::recovery::ConfidenceScorer scorer;

    auto candidates = carver.scan(image_path);
    std::unique_ptr<core::recovery::FileClassifier> classifier;
    if (!output_dir.empty()) {
        classifier = std::make_unique<core::recovery::FileClassifier>(output_dir);
    }

    for (auto& candidate : candidates) {
        validator.validate(candidate, image_path);
        scorer.score(candidate, image_path);
        bool written = false;
        if (classifier) {
            written = classifier->classify(candidate, image_path);
        }

        py::dict item;
        item["file_type"] = core::recovery::toString(candidate.fileType);
        item["offset_start"] = candidate.offsetStart;
        item["offset_end"] = candidate.offsetEnd;
        item["size"] = candidate.size();
        item["validation"] = core::recovery::toString(candidate.validationState);
        item["confidence"] = core::recovery::toString(candidate.confidence);
        item["category"] = core::recovery::toString(candidate.category);
        item["output_path"] = candidate.outputPath;
        item["sha256"] = candidate.sha256;
        item["written"] = written;

        result.append(item);
    }
    return result;
}

py::dict acquire_image(const std::string& device_path, const std::string& output_image_path)
{
    py::dict d;
    core::drive::DriveManager manager;
    auto drives = manager.getAvailableDrives();

    core::drive::DriveInfo info;
    bool found = false;
    for (const auto& drv : drives) {
        if (drv.devicePath == device_path) {
            info = drv;
            found = true;
            break;
        }
    }

    if (!found) {
        try {
            info = makeDriveInfo(device_path);
        } catch (const std::exception& e) {
            d["success"] = false;
            d["error"] = e.what();
            return d;
        }
    }

    auto outcome = core::acquisition::AcquisitionManager::acquire(info, output_image_path);
    d["success"] = outcome.success;
    if (outcome.success) {
        d["image_path"] = outcome.metadata.imagePath;
        d["sha256"] = outcome.metadata.sha256;
        d["size_bytes"] = outcome.metadata.sizeBytes;
        d["acquired_at_utc"] = outcome.metadata.acquiredAtUtc;
        d["source_model"] = outcome.metadata.sourceModel;
        d["source_serial"] = outcome.metadata.sourceSerial;
    } else {
        d["error"] = outcome.errorMessage;
    }
    return d;
}

class DataSanitizer
{
public:
    bool sanitizeSector(const std::string& targetPath, int passes = 1)
    {
        auto res = sanitize_drive(targetPath, passes);
        return res["success"].cast<bool>();
    }

    bool zeroFill(const std::string& targetPath)
    {
        auto res = sanitize_drive(targetPath, 1);
        return res["success"].cast<bool>();
    }
};

PYBIND11_MODULE(cpp_sanitizer, m)
{
    m.doc() = "Python bindings for the SIH C++ SanitizerOS core engine";

    m.def("get_drives", &get_drives, "Get a list of all available storage drives with safety metadata");
    m.def("get_drive_info", &get_drive_info, py::arg("device"), "Get detailed metadata for a drive");
    m.def("get_sanitization_info", &get_sanitization_info, py::arg("device"), "Get recommended sanitization protocol and NIST standard");
    m.def("sanitize_drive", &sanitize_drive, py::arg("target_path"), py::arg("passes") = 1, "Sanitize drive with system protection, real verification, and audit metrics");
    m.def("scan_image", &scan_image, py::arg("image_path"), py::arg("output_dir") = "", "Scan an acquired forensic image for file signatures and carve files");
    m.def("acquire_image", &acquire_image, py::arg("device_path"), py::arg("output_image_path"), "Forensically acquire a device to raw image with write-blocking and SHA-256");

    py::class_<DataSanitizer>(m, "DataSanitizer")
        .def(py::init<>())
        .def(
            "sanitizeSector",
            &DataSanitizer::sanitizeSector,
            py::arg("targetPath"),
            py::arg("passes") = 3
        )
        .def(
            "zeroFill",
            &DataSanitizer::zeroFill,
            py::arg("targetPath")
        );
}