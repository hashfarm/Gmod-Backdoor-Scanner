#pragma once
#include <filesystem>
#include <functional>
#include <memory>
#include <set>
#include <thread>
#include <vector>
#include "CleanString.h"
#include "Report.h"

#ifndef _WIN32
#include <pthread.h>
#endif

// libstdc++ regex matching recurses per character; 8 MB is not enough.
#ifndef BDSCAN_WORKER_STACK_MB
#define BDSCAN_WORKER_STACK_MB 32
#endif
constexpr size_t kWorkerStackBytes = static_cast<size_t>(BDSCAN_WORKER_STACK_MB) * 1024 * 1024;

class ScanWorker {
public:
    explicit ScanWorker(std::function<void()> body) {
#ifdef _WIN32
        m_thread = std::thread(std::move(body));
#else
        auto* held = new std::function<void()>(std::move(body));
        pthread_attr_t attributes;
        pthread_attr_init(&attributes);
        pthread_attr_setstacksize(&attributes, kWorkerStackBytes);
        const int started = pthread_create(&m_thread, &attributes, &ScanWorker::Run, held);
        pthread_attr_destroy(&attributes);
        if (started != 0) {
            delete held;
            throw std::runtime_error("could not start a scan worker");
        }
        m_started = true;
#endif
    }

    ScanWorker(const ScanWorker&) = delete;
    ScanWorker& operator=(const ScanWorker&) = delete;

#ifdef _WIN32
    ScanWorker(ScanWorker&&) = default;
#else
    // A defaulted move would leave both objects joining the same thread.
    ScanWorker(ScanWorker&& other) noexcept : m_thread(other.m_thread), m_started(other.m_started) {
        other.m_started = false;
    }
#endif

    void Join() {
#ifdef _WIN32
        if (m_thread.joinable()) m_thread.join();
#else
        if (m_started) {
            pthread_join(m_thread, nullptr);
            m_started = false;
        }
#endif
    }

private:
#ifdef _WIN32
    std::thread m_thread;
#else
    static void* Run(void* argument) {
        std::unique_ptr<std::function<void()>> body(static_cast<std::function<void()>*>(argument));
        (*body)();
        return nullptr;
    }

    pthread_t m_thread{};
    bool m_started = false;
#endif
};

inline std::filesystem::path ExtendedPath(const std::filesystem::path& path) {
#ifdef _WIN32
    std::error_code ec;
    std::filesystem::path absolute = std::filesystem::absolute(path, ec);
    if (ec) return path;
    absolute = absolute.lexically_normal();

    std::wstring text = absolute.wstring();
    if (text.rfind(L"\\\\?\\", 0) == 0) return absolute;
    for (wchar_t& c : text) {
        if (c == L'/') c = L'\\';
    }
    if (text.rfind(L"\\\\", 0) == 0) return std::filesystem::path(L"\\\\?\\UNC" + text.substr(1));
    if (text.size() < 2 || text[1] != L':') return absolute;
    return std::filesystem::path(L"\\\\?\\" + text);
#else
    return path;
#endif
}

inline std::string NormalizedPath(const std::filesystem::path& path) {
    const auto encoded = path.generic_u8string();
    std::string text = SanitizeUtf8(std::string(encoded.begin(), encoded.end()));
    if (text.rfind("//?/UNC/", 0) == 0) return "//" + text.substr(8);
    if (text.rfind("//?/", 0) == 0) return text.substr(4);
    return text;
}

inline std::vector<std::filesystem::path> CollectScanTargets(
    const std::filesystem::path& root,
    const std::function<bool(const std::filesystem::path&)>& accepts,
    SkipRegistry& skipped) {
    namespace fs = std::filesystem;
    std::vector<fs::path> targets;
    std::set<std::string> visited;
    std::vector<fs::path> directories = { root };
    while (!directories.empty()) {
        const fs::path directory = std::move(directories.back());
        directories.pop_back();
        std::error_code ec;

        // Not lowercased: weakly_canonical already folds case where the
        // filesystem does, and folding it again merged Addons with addons on Linux.
        const fs::path resolved = fs::weakly_canonical(directory, ec);
        const std::string identity = ec ? NormalizedPath(directory) : NormalizedPath(resolved);
        ec.clear();
        if (!visited.insert(identity).second) continue;

        fs::directory_iterator it(directory, ec);
        if (ec) {
            skipped.Add(SkipReason::Unreadable, NormalizedPath(directory), ec.message());
            continue;
        }
        const fs::directory_iterator end;
        while (it != end) {
            const fs::path path = it->path();
            const fs::file_status link = it->symlink_status(ec);
            if (ec) {
                skipped.Add(SkipReason::Unreadable, NormalizedPath(path), ec.message());
            }
            else {
                const fs::file_status status = it->status(ec);
                if (ec) skipped.Add(SkipReason::Unreadable, NormalizedPath(path), ec.message());
                else if (fs::is_directory(status) && !fs::is_symlink(link)) directories.push_back(path);
                else if (fs::is_directory(status)) {
                    std::error_code linkEc;
                    const fs::path target = fs::weakly_canonical(path, linkEc);
                    const fs::path base = fs::weakly_canonical(root, linkEc);
                    const std::string inside = NormalizedPath(base);
                    const std::string points = NormalizedPath(target);
                    if (linkEc || points.rfind(inside, 0) != 0) {
                        skipped.Add(SkipReason::Unreadable, NormalizedPath(path),
                                    "directory link, not followed; its target lies outside the scan");
                    }
                }
                else if (fs::is_regular_file(status) && accepts(path)) targets.push_back(path);
            }
            ec.clear();
            it.increment(ec);
            if (ec) {
                skipped.Add(SkipReason::Unreadable, NormalizedPath(directory), ec.message());
                break;
            }
        }
    }
    return targets;
}

template <typename Work>
inline void ExecuteScanTask(const std::filesystem::path& path, SkipRegistry& skipped, Work&& work) {
    try {
        work();
    }
    catch (const std::exception& error) {
        skipped.Add(SkipReason::ScanError, NormalizedPath(path), error.what());
    }
    catch (...) {
        skipped.Add(SkipReason::ScanError, NormalizedPath(path), "unknown processing error");
    }
}
