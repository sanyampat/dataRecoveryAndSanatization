#pragma once

#include "RecoveredFile.h"

#include <string>

namespace core::recovery {

// Confirms structure for a carved candidate rather than trusting the
// header byte alone — "sanity-check the fields you parsed, don't just
// trust the header byte" (TSK's fs-parsing discipline, applied here per
// format). Mutates candidate.validationState in place and, for ZIP,
// corrects candidate.offsetEnd to the EOCD-derived authoritative archive
// length (FileCarver only ever gives ZIP a provisional upper bound).
class FileValidator {
public:
    void validate(RecoveredFile& candidate, const std::string& imagePath) const;

private:
    ValidationState validatePdf(const std::string& imagePath, uint64_t start, uint64_t end) const;
    ValidationState validateJpeg(const std::string& imagePath, uint64_t start, uint64_t end) const;
    ValidationState validateZip(RecoveredFile& candidate, const std::string& imagePath) const;
};

} // namespace core::recovery
