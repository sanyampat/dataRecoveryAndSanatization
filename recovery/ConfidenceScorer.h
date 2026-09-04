#pragma once

#include "RecoveredFile.h"

#include <string>

namespace core::recovery {

// Project-original four-tier confidence model (ForensicOS_README.md
// Sec.38/62) — NOT a NIST SP 800-86 concept, do not cite it as one in
// slides/report language. Neither PhotoRec nor TSK implement anything
// resembling this: PhotoRec's own model is binary (a candidate passes
// header_check/file_check and is kept, or it doesn't and is discarded —
// no gradation of confidence). The nearest relative found in either
// reference tool was TestDisk's primary-vs-backup-superblock distinction
// (a binary "found via fallback" note, not a graduated score) — worth
// citing as prior art for the *general idea*, not as precedent for this
// specific weighted mechanism.
class ConfidenceScorer {
public:
    // Scores candidate based on four signals: header match (baseline —
    // always true, a candidate only exists because FileCarver matched a
    // magic sequence), footer/terminator found (a bounded, non-zero-size
    // candidate), structural validation (from FileValidator), and an
    // entropy check (this project's own addition — see sampledEntropy).
    // Sets candidate.confidence in place.
    void score(RecoveredFile& candidate, const std::string& imagePath) const;

private:
    // Shannon entropy (bits/byte, range 0-8) over a sampled subset of the
    // candidate's bytes, capped at kMaxEntropySampleBytes — sufficient per
    // the spec's performance target; no need for a full-file pass on
    // large candidates.
    double sampledEntropy(const std::string& imagePath, uint64_t start, uint64_t end) const;
};

} // namespace core::recovery
