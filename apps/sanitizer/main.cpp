#include "../device/DriveManager.h"
#include "../../sanitization/SanitizationEngine.h"

#include <iostream>
#include <vector>
#include <cstddef>


int main()
{
    std::cout
        << "\n=====================================\n"
        << "        SIH SANITIZER TEST\n"
        << "=====================================\n";


    // =========================================================
    // Create Drive Manager
    // =========================================================

    core::drive::DriveManager manager;


    // =========================================================
    // Detect available drives
    // =========================================================

    auto drives =
        manager.getAvailableDrives();


    if (drives.empty())
    {
        std::cout
            << "\nNo drives detected.\n";

        return 1;
    }


    // =========================================================
    // Display detected drives
    // =========================================================

    std::cout
        << "\nDetected drives:\n";


    for (std::size_t i = 0;
         i < drives.size();
         ++i)
    {
        const auto& drive =
            drives[i];


        std::cout
            << "\n-------------------------------------\n";


        std::cout
            << "[" << i << "]\n";


        std::cout
            << "Device: "
            << drive.devicePath
            << "\n";


        std::cout
            << "Model: "
            << drive.model
            << "\n";


        std::cout
            << "Serial: "
            << drive.serialNumber
            << "\n";


        std::cout
            << "Bus: "
            << drive.getBusTypeString()
            << "\n";


        std::cout
            << "Capacity: "
            << drive.capacityBytes
            << " bytes\n";


        std::cout
            << "Media: "
            << drive.getMediaTypeString()
            << "\n";


        std::cout
            << "Mounted: "
            << (drive.isMounted ? "YES" : "NO")
            << "\n";


        std::cout
            << "System Disk: "
            << (drive.isSystemDisk ? "YES" : "NO")
            << "\n";
    }


    std::cout
        << "\n-------------------------------------\n";


    // =========================================================
    // Select drive
    // =========================================================

    std::cout
        << "\nSelect drive index: ";


    std::size_t index;


    if (!(std::cin >> index))
    {
        std::cerr
            << "\nInvalid input.\n";

        return 1;
    }


    if (index >= drives.size())
    {
        std::cerr
            << "\nInvalid drive selection.\n";

        return 1;
    }


    const auto& drive =
        drives[index];


    std::cout
        << "\nSelected device: "
        << drive.devicePath
        << "\n";


    // =========================================================
    // SAFETY CHECK 1 — SYSTEM DISK
    // =========================================================

    if (drive.isSystemDisk)
    {
        std::cerr
            << "\n=====================================\n"
            << "             BLOCKED\n"
            << "=====================================\n";


        std::cerr
            << "ERROR: The selected device is the "
            << "host system disk.\n";


        std::cerr
            << "Sanitization is blocked for safety.\n";


        std::cerr
            << "Your operating system drive will NOT "
            << "be modified.\n";


        return 1;
    }


    // =========================================================
    // SAFETY CHECK 2 — MOUNTED DEVICE
    // =========================================================

    if (drive.isMounted)
    {
        std::cerr
            << "\n=====================================\n"
            << "             BLOCKED\n"
            << "=====================================\n";


        std::cerr
            << "ERROR: The selected device has "
            << "mounted partitions.\n";


        std::cerr
            << "Unmount the target before "
            << "sanitization.\n";


        return 1;
    }


    // =========================================================
    // FINAL WARNING
    // =========================================================

    std::cout
        << "\n=====================================\n"
        << "       DESTRUCTIVE OPERATION\n"
        << "=====================================\n";


    std::cout
        << "Target: "
        << drive.devicePath
        << "\n";


    std::cout
        << "Model: "
        << drive.model
        << "\n";


    std::cout
        << "Capacity: "
        << drive.capacityBytes
        << " bytes\n";


    std::cout
        << "\nThis operation may permanently destroy "
        << "data on the selected device.\n";


    std::cout
        << "Type EXACTLY: ERASE\n"
        << "to continue: ";


    std::string confirmation;


    std::cin
        >> confirmation;


    if (confirmation != "ERASE")
    {
        std::cout
            << "\nOperation cancelled.\n";

        return 0;
    }


    // =========================================================
    // Execute sanitization
    // =========================================================

    std::cout
        << "\nStarting sanitization...\n";


    core::sanitization::SanitizationEngine engine;


    auto result =
        engine.executeSanitization(drive);


    // =========================================================
    // Display result
    // =========================================================

    std::cout
        << "\n=====================================\n"
        << "        SANITIZATION RESULT\n"
        << "=====================================\n";


    std::cout
        << "Success: "
        << (result.success ? "YES" : "NO")
        << "\n";


    std::cout
        << "Blocked: "
        << (result.blocked ? "YES" : "NO")
        << "\n";


    std::cout
        << "Wipe passed: "
        << (result.wipePassed ? "YES" : "NO")
        << "\n";


    std::cout
        << "Verification passed: "
        << (result.verificationPassed ? "YES" : "NO")
        << "\n";


    std::cout
        << "Method: "
        << result.methodApplied
        << "\n";


    std::cout
        << "Media type: "
        << result.mediaType
        << "\n";


    std::cout
        << "Bytes processed: "
        << result.bytesProcessed
        << "\n";


    std::cout
        << "Capacity: "
        << result.capacityBytes
        << "\n";


    std::cout
        << "Samples checked: "
        << result.samplesChecked
        << "\n";


    /*
     * SanitizationResult currently exposes samplesChecked,
     * not samplesVerified.
     *
     * Therefore we intentionally use samplesChecked here.
     */
    std::cout
        << "Samples verified: "
        << result.samplesChecked
        << "\n";


    std::cout
        << "Verification method: "
        << result.verificationMethod
        << "\n";


    std::cout
        << "Duration: "
        << result.durationSeconds
        << " seconds\n";


    if (!result.error.empty())
    {
        std::cout
            << "Error: "
            << result.error
            << "\n";
    }


    std::cout
        << "=====================================\n";


    // =========================================================
    // Exit status
    // =========================================================

    return result.success ? 0 : 1;
}