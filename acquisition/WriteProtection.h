#pragma once

#include "../device/DriveInfo.h"

namespace core::acquisition {

    // Enforces read-only access to a block device at the Linux block layer,
    // via the BLKROSET / BLKROGET ioctls.
    //
    // CAVEAT (state this accurately in the report): this is a *software*
    // write-block enforced by the kernel's block layer, not a hardware
    // write-blocker. It depends on nothing on the system bypassing the
    // block layer, and it is reversible by anyone with sufficient privilege
    // to re-issue BLKROSET with a 0 flag. It is not a substitute for a
    // hardware write-blocker in a real chain-of-custody workflow, but it is
    // a meaningful safeguard against ForensicOS itself (or another process
    // on the same live environment) accidentally writing to the evidence
    // device during acquisition.
    class WriteProtection {
    public:
        // Sets the device's soft read-only flag via BLKROSET.
        // Returns false if the device can't be opened or the ioctl fails —
        // commonly because the caller lacks permission (this needs root or
        // equivalent block-device access).
        static bool enforce(const core::drive::DriveInfo& drive);

        // Reads back the device's current read-only flag via BLKROGET.
        // Returns true only if the device is confirmed read-only. Returns
        // false both when it is NOT read-only and when the check itself
        // failed to run — check stderr output to tell which.
        static bool isReadOnly(const core::drive::DriveInfo& drive);

        // Clears the soft read-only flag (BLKROSET with arg 0).
        // Provided for test/cleanup convenience — the acquisition workflow
        // itself should never need to call this on evidence.
        static bool release(const core::drive::DriveInfo& drive);
    };

} // namespace core::acquisition
