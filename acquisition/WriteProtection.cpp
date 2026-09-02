#include "WriteProtection.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <iostream>

namespace core::acquisition {

    namespace {
        bool setReadOnlyFlag(const std::string& devicePath, int flagValue) {
            int fd = open(devicePath.c_str(), O_RDONLY);
            if (fd < 0) {
                std::cerr << "  -> WriteProtection: could not open " << devicePath << "\n";
                return false;
            }

            int flag = flagValue;
            if (ioctl(fd, BLKROSET, &flag) != 0) {
                std::cerr << "  -> WriteProtection: BLKROSET failed on " << devicePath
                          << " (are you root / do you have block-device access?)\n";
                close(fd);
                return false;
            }

            close(fd);
            return true;
        }
    }

    bool WriteProtection::enforce(const core::drive::DriveInfo& drive) {
        std::cout << "  -> Enforcing software write-block (BLKROSET) on " << drive.devicePath << "...\n";
        return setReadOnlyFlag(drive.devicePath, 1);
    }

    bool WriteProtection::release(const core::drive::DriveInfo& drive) {
        std::cout << "  -> Releasing software write-block on " << drive.devicePath << "...\n";
        return setReadOnlyFlag(drive.devicePath, 0);
    }

    bool WriteProtection::isReadOnly(const core::drive::DriveInfo& drive) {
        int fd = open(drive.devicePath.c_str(), O_RDONLY);
        if (fd < 0) {
            std::cerr << "  -> WriteProtection: could not open " << drive.devicePath << " to check status\n";
            return false;
        }

        int flag = 0;
        if (ioctl(fd, BLKROGET, &flag) != 0) {
            std::cerr << "  -> WriteProtection: BLKROGET failed on " << drive.devicePath << "\n";
            close(fd);
            return false;
        }

        close(fd);
        return flag != 0;
    }

} // namespace core::acquisition
