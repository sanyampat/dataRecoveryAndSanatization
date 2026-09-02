#include "../../device/DriveManager.h"
#include "../../acquisition/AcquisitionManager.h"

#include <iostream>

int main() {
    std::cout << "\n=====================================\n";
    std::cout << "      SIH ACQUISITION TEST\n";
    std::cout << "=====================================\n";

    core::drive::DriveManager manager;
    auto drives = manager.getAvailableDrives();

    if (drives.empty()) {
        std::cout << "No drives detected.\n";
        return 1;
    }

    for (std::size_t i = 0; i < drives.size(); ++i) {
        const auto& drive = drives[i];
        std::cout << "\n[" << i << "]\n";
        std::cout << "Device: " << drive.devicePath << "\n";
        std::cout << "Model: " << drive.model << "\n";
        std::cout << "Serial: " << drive.serialNumber << "\n";
        std::cout << "Bus: " << drive.getBusTypeString() << "\n";
        std::cout << "Capacity: " << drive.capacityBytes << " bytes\n";
        std::cout << "Media: " << drive.getMediaTypeString() << "\n";
    }

    std::cout << "\nSelect drive index: ";
    std::size_t index;
    if (!(std::cin >> index) || index >= drives.size()) {
        std::cerr << "Invalid drive selection.\n";
        return 1;
    }

    const auto& drive = drives[index];

    std::cout << "Output image path (e.g. ./CASE_DATA/CASE-001/evidence/image.dd): ";
    std::string outputPath;
    std::cin >> outputPath;

    std::cout << "\nSelected: " << drive.devicePath << "\n";
    std::cout << "Starting acquisition...\n";

    auto outcome = core::acquisition::AcquisitionManager::acquire(drive, outputPath);

    if (!outcome.success) {
        std::cout << "\nAcquisition failed: " << outcome.errorMessage << "\n";
        return 1;
    }

    const auto& meta = outcome.metadata;
    std::cout << "\nAcquisition succeeded.\n";
    std::cout << "Source       : " << meta.sourceDevicePath << " (" << meta.sourceModel << ")\n";
    std::cout << "Image path   : " << meta.imagePath << "\n";
    std::cout << "Size         : " << meta.sizeBytes << " bytes\n";
    std::cout << "SHA-256      : " << meta.sha256 << "\n";
    std::cout << "Acquired at  : " << meta.acquiredAtUtc << " (UTC)\n";

    return 0;
}
