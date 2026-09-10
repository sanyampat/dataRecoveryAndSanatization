#include "ConfidenceScorer.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <vector>

namespace core::recovery {

namespace {

// 1 MB sample cap per candidate.
constexpr uint64_t kMaxEntropySampleBytes = 1ULL * 1024 * 1024;

// Entropy threshold below which content is considered suspiciously flat.
constexpr double kMinPlausibleEntropy = 2.0;

} // namespace

ConfidenceScorer::ConfidenceScorer() = default;

ConfidenceScorer::~ConfidenceScorer() = default;

void ConfidenceScorer::score(RecoveredFile& candidate,
                             const std::string& imagePath) const {
    // A CORRUPT candidate has already failed structural validation.
    if (candidate.validationState == ValidationState::CORRUPT) {
        candidate.confidence = ConfidenceLevel::UNVERIFIED;
        return;
    }

    // Open the normal disk-image file using TSK image-type detection.
    // TSK_IMG_TYPE_EXTERNAL is not appropriate for a normal image path.
    TSK_IMG_INFO* imgInfo = tsk_img_open_sing(
        imagePath.c_str(),
        TSK_IMG_TYPE_DETECT,
        0
    );

    if (!imgInfo) {
        candidate.confidence = ConfidenceLevel::UNVERIFIED;
        return;
    }

    int points = 0;
    constexpr int kMaxPoints = 4;

    // Header match: a candidate exists only because FileCarver matched
    // its magic bytes.
    points += 1;

    // Footer/terminator was located by the carver/validator.
    if (candidate.offsetEnd > candidate.offsetStart) {
        points += 1;
    }

    // Structural validation.
    if (candidate.validationState == ValidationState::VALID) {
        points += 1;
    }

    // Entropy check.
    const double entropy = sampledEntropy(
        imgInfo,
        candidate.offsetStart,
        candidate.offsetEnd
    );

    if (entropy >= kMinPlausibleEntropy) {
        points += 1;
    }

    tsk_img_close(imgInfo);

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

double ConfidenceScorer::sampledEntropy(TSK_IMG_INFO* imgInfo,
                                        uint64_t start,
                                        uint64_t end) const {
    if (end <= start || !imgInfo) {
        return 0.0;
    }

    const uint64_t length =
        std::min(end - start, kMaxEntropySampleBytes);

    std::vector<char> buf(static_cast<size_t>(length));

    ssize_t got = tsk_img_read(
        imgInfo,
        start,
        buf.data(),
        static_cast<size_t>(length)
    );

    if (got <= 0) {
        return 0.0;
    }

    std::array<uint64_t, 256> histogram{};

    for (ssize_t i = 0; i < got; ++i) {
        histogram[static_cast<unsigned char>(buf[i])]++;
    }

    double entropy = 0.0;

    for (uint64_t count : histogram) {
        if (count == 0) {
            continue;
        }

        const double p =
            static_cast<double>(count) /
            static_cast<double>(got);

        entropy -= p * std::log2(p);
    }

    return entropy;
}

} // namespace core::recovery