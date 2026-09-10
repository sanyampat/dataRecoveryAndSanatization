#pragma once

#include "RecoveredFile.h"
#include <tsk/libtsk.h>

#include <string>

namespace core::recovery {

// Confirms structure for a carved candidate using Sleuthkit's optimized I/O
// rather than trusting the header byte alone — "sanity-check the fields you
// parsed, don't just trust the header byte" (TSK's fs-parsing discipline,
// applied here per format). 
//
// Mutates candidate.validationState in place and, for ZIP, corrects
// candidate.offsetEnd to the EOCD-derived authoritative archive length
// (FileCarver only ever gives ZIP a provisional upper bound).
class FileValidator {
public:
    FileValidator();
    ~FileValidator();

    void validate(RecoveredFile& candidate, const std::string& imagePath) const;

private:
    ValidationState validatePdf(TSK_IMG_INFO* imgInfo, uint64_t start, 
                                uint64_t end) const;
    ValidationState validateJpeg(TSK_IMG_INFO* imgInfo, uint64_t start, 
                                 uint64_t end) const;
    ValidationState validateZip(RecoveredFile& candidate, TSK_IMG_INFO* imgInfo) const;

    // Helper: read range using TSK's image API
    std::string readRange(TSK_IMG_INFO* imgInfo, uint64_t start, 
                          uint64_t length) const;
};

} // namespace core::recovery