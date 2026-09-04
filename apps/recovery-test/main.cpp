// Root-relative includes: CMakeLists.txt's include_directories(${CMAKE_SOURCE_DIR} ...)
// already puts the project root on the include path, matching how the
// existing apps/*-test mains include their modules (e.g. "device/DriveManager.h").
#include "recovery/FileCarver.h"
#include "recovery/FileValidator.h"
#include "recovery/ConfidenceScorer.h"
#include "recovery/FileClassifier.h"

#include <iostream>

// Per-module test-app convention (mirrors apps/device-test,
// apps/acquisition-test): take an image path as input, run the full
// recovery pipeline, print one line per recovered candidate.
//
// Should be runnable against either:
//   - a real acquired image (AcquisitionManager's ImageMetadata::imagePath),
//     confirming the pipeline works on real acquisition output, or
//   - a small, hand-built test image (a real JPEG + PDF concatenated with
//     filler bytes) for basic testing without needing a full disk image.
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <image_path> [output_root]\n\n"
                  << "  image_path   Path to the forensic image to scan. This should be\n"
                  << "               the image file produced by AcquisitionManager\n"
                  << "               (ImageMetadata::imagePath) — never a raw device.\n"
                  << "               For basic testing without a real disk image, a small\n"
                  << "               hand-built file works too: concatenate a real JPEG +\n"
                  << "               a real PDF + some filler bytes into one file.\n\n"
                  << "  output_root  Directory recovered files are streamed into,\n"
                  << "               mirroring the CASE_DATA convention.\n"
                  << "               (default: CASE_DATA)\n";
        return 1;
    }

    const std::string imagePath = argv[1];
    const std::string outputRoot = (argc >= 3) ? argv[2] : "CASE_DATA";

    core::recovery::FileCarver carver;
    core::recovery::FileValidator validator;
    core::recovery::ConfidenceScorer scorer;
    core::recovery::FileClassifier classifier(outputRoot);

    const auto candidates = carver.scan(imagePath);
    std::cout << "Carved " << candidates.size() << " candidate(s) from " << imagePath << "\n\n";

    if (candidates.empty()) {
        std::cout << "No candidates found. If this is unexpected, confirm imagePath "
                  << "points at a real image file (not a device path), and that it "
                  << "actually contains JPEG/PDF/ZIP data.\n";
        return 0;
    }

    int written = 0;
    for (auto candidate : candidates) { // copy: classify()/score()/validate() mutate in place
        validator.validate(candidate, imagePath);
        scorer.score(candidate, imagePath);
        const bool wasWritten = classifier.classify(candidate, imagePath);
        if (wasWritten) ++written;

        std::cout << "offset=" << candidate.offsetStart
                   << " type=" << core::recovery::toString(candidate.fileType)
                   << " size=" << candidate.size()
                   << " validation=" << core::recovery::toString(candidate.validationState)
                   << " confidence=" << core::recovery::toString(candidate.confidence)
                   << " category=" << core::recovery::toString(candidate.category)
                   << " output=" << (candidate.outputPath.empty() ? "(not written)" : candidate.outputPath);
        if (!candidate.sha256.empty()) {
            std::cout << " sha256=" << candidate.sha256;
        }
        std::cout << "\n";
    }

    std::cout << "\n" << written << "/" << candidates.size()
              << " candidate(s) written to " << outputRoot << "\n";

    return 0;
}
