#include "FileClassifier.h"
#include "../acquisition/HashEngine.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

namespace core::recovery {

namespace {
// 1 MB chunks, matching DiskImager's buffer-sizing convention elsewhere
// in the project — streamed copy, never the whole candidate in RAM.
constexpr size_t kStreamChunkSize = 1ULL * 1024 * 1024;
} // namespace

FileClassifier::FileClassifier(std::string outputRoot) : outputRoot_(std::move(outputRoot)) {}

FileCategory FileClassifier::categoryFor(FileType type) {
    switch (type) {
        case FileType::JPEG: return FileCategory::Images;
        case FileType::PDF:  return FileCategory::Documents;
        case FileType::ZIP:  return FileCategory::Archives;
        default:             return FileCategory::Unknown;
    }
}

std::string FileClassifier::extensionFor(FileType type) {
    switch (type) {
        case FileType::JPEG: return ".jpg";
        case FileType::PDF:  return ".pdf";
        case FileType::ZIP:  return ".zip";
        default:             return ".bin";
    }
}

bool FileClassifier::classify(RecoveredFile& candidate, const std::string& imagePath) const {
    candidate.category = categoryFor(candidate.fileType);
    candidate.timestampUtc = currentTimestampUtc();

    // Per the spec's recommendation: write everything scored LOW or
    // above; log but don't write UNVERIFIED/discarded candidates, so
    // CASE_DATA doesn't fill up with carved-over garbage.
    if (candidate.confidence == ConfidenceLevel::UNVERIFIED || candidate.offsetEnd <= candidate.offsetStart) {
        candidate.outputPath.clear();
        return false;
    }

    const std::string categoryDir = outputRoot_ + "/" + toString(candidate.category);
    std::error_code ec;
    std::filesystem::create_directories(categoryDir, ec);
    if (ec) {
        candidate.outputPath.clear();
        return false;
    }

    std::ostringstream nameStream;
    nameStream << categoryDir << "/recovered_" << candidate.offsetStart << extensionFor(candidate.fileType);
    const std::string outPath = nameStream.str();

    std::ifstream src(imagePath, std::ios::binary);
    std::ofstream dst(outPath, std::ios::binary);
    if (!src || !dst) {
        candidate.outputPath.clear();
        return false;
    }

    src.seekg(static_cast<std::streamoff>(candidate.offsetStart), std::ios::beg);
    uint64_t remaining = candidate.offsetEnd - candidate.offsetStart;
    std::vector<char> buf(kStreamChunkSize);

    while (remaining > 0) {
        const auto chunk = static_cast<std::streamsize>(std::min<uint64_t>(remaining, buf.size()));
        src.read(buf.data(), chunk);
        const std::streamsize got = src.gcount();
        if (got <= 0) break;
        dst.write(buf.data(), got);
        remaining -= static_cast<uint64_t>(got);
    }
    dst.close();

    if (remaining > 0) {
        // Short read from the image — don't leave a silently-truncated
        // file behind with no record of the problem.
        std::filesystem::remove(outPath, ec);
        candidate.outputPath.clear();
        return false;
    }

    candidate.outputPath = outPath;
    candidate.sha256 = computeSha256(outPath);
    return true;
}

std::string FileClassifier::computeSha256(const std::string& path) const {
    // Reuses the project's existing streaming HashEngine (acquisition/)
    // rather than a second hashing implementation — same one DiskImager
    // hashes-as-it-streams with.
    std::ifstream in(path, std::ios::binary);
    if (!in) return "";

    core::acquisition::HashEngine hasher;
    std::vector<char> buf(kStreamChunkSize);

    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) {
            hasher.update(buf.data(), static_cast<size_t>(got));
        }
    }

    return hasher.finalize();
}

std::string FileClassifier::currentTimestampUtc() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm utcTm{};
#if defined(_WIN32)
    gmtime_s(&utcTm, &t);
#else
    gmtime_r(&t, &utcTm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&utcTm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // namespace core::recovery
