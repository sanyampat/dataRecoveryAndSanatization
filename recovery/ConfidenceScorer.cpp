#include "ConfidenceScorer.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <fstream>
#include <vector>

namespace core::recovery {

namespace {
// 1 MB sample cap per candidate — a full-file entropy pass on a large
// carved video/archive would be wasted work for a signal that's really
// just "does this look like real content, not carved-over garbage."
constexpr uint64_t kMaxEntropySampleBytes = 1ULL * 1024 * 1024;

// Entropy threshold below which a candidate's content reads as
// suspiciously flat/patterned rather than real file data. JPEG scan data
// and PDF binary streams both comfortably clear this; even PDF's plain-
// text sections (xref tables, dictionaries) typically don't fall this low
// unless the region is mostly padding/zero bytes.
constexpr double kMinPlausibleEntropy = 2.0; // bits/byte
} // namespace

void ConfidenceScorer::score(RecoveredFile& candidate, const std::string& imagePath) const {
    // A CORRUPT candidate has already failed structural validation
    // outright (bad header bytes, missing/inconsistent EOCD, etc.) —
    // don't dilute that with partial credit from the other signals below.
    if (candidate.validationState == ValidationState::CORRUPT) {
        candidate.confidence = ConfidenceLevel::UNVERIFIED;
        return;
    }

    int points = 0;
    constexpr int kMaxPoints = 4;

    // Header match: always true by construction — a candidate only exists
    // because FileCarver matched a magic sequence. Counted as a baseline
    // point rather than a discriminator between candidates (every
    // candidate that reaches this function gets it).
    points += 1;

    // Footer/terminator found: a bounded, non-zero-size candidate implies
    // FileCarver (or, for ZIP, FileValidator's EOCD parse) located a real
    // end rather than hitting the carver's safety-cap bound.
    if (candidate.offsetEnd > candidate.offsetStart) {
        points += 1;
    }

    // Structural validation, from FileValidator. VALID gets full credit;
    // PARTIAL/UNVERIFIED get none here (their uncertainty is instead
    // reflected by whichever other signals still pass).
    if (candidate.validationState == ValidationState::VALID) {
        points += 1;
    }

    // Entropy check (this project's addition — confirmed absent from both
    // PhotoRec and TSK by direct inspection): real file content shouldn't
    // read as flat/patterned across its whole span, which is what
    // carved-over garbage typically looks like.
    const double entropy = sampledEntropy(imagePath, candidate.offsetStart, candidate.offsetEnd);
    if (entropy >= kMinPlausibleEntropy) {
        points += 1;
    }

    if (points >= kMaxPoints) {
        candidate.confidence = ConfidenceLevel::HIGH;
    } else if (points == kMaxPoints - 1) {
        candidate.confidence = ConfidenceLevel::MEDIUM;
    } else if (points >= 1) {
        candidate.confidence = ConfidenceLevel::LOW;
    } else {
        candidate.confidence = ConfidenceLevel::UNVERIFIED;
    }
}

double ConfidenceScorer::sampledEntropy(const std::string& imagePath, uint64_t start, uint64_t end) const {
    if (end <= start) return 0.0;

    std::ifstream in(imagePath, std::ios::binary);
    if (!in) return 0.0;

    const uint64_t length = std::min(end - start, kMaxEntropySampleBytes);
    in.seekg(static_cast<std::streamoff>(start), std::ios::beg);

    std::vector<char> buf(static_cast<size_t>(length));
    in.read(buf.data(), static_cast<std::streamsize>(length));
    const size_t got = static_cast<size_t>(in.gcount());
    if (got == 0) return 0.0;

    std::array<uint64_t, 256> histogram{};
    for (size_t i = 0; i < got; ++i) {
        histogram[static_cast<unsigned char>(buf[i])]++;
    }

    double entropy = 0.0;
    for (uint64_t count : histogram) {
        if (count == 0) continue;
        const double p = static_cast<double>(count) / static_cast<double>(got);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

} // namespace core::recovery
