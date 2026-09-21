#pragma once
#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "Scanner.h"

struct ScanCacheEntry {
    uint64_t size = 0;
    int64_t modified = 0;
    std::string hash;
    std::vector<Detection> detections;
};

class ScanCache {
public:
    void SetIdentity(const std::string& ruleset, const std::string& policy) {
        m_ruleset = ruleset;
        m_policy = policy;
    }

    const std::string& Ruleset() const { return m_ruleset; }
    const std::string& Policy() const { return m_policy; }

    void Adopt(std::map<std::string, ScanCacheEntry> loaded) {
        m_loaded = std::move(loaded);
    }

    const ScanCacheEntry* Lookup(const std::string& path, const std::string& hash) const {
        const auto it = m_loaded.find(path);
        if (it == m_loaded.end()) return nullptr;
        if (it->second.hash != hash || hash.empty()) return nullptr;
        return &it->second;
    }

    void Store(const std::string& path, ScanCacheEntry entry) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_fresh[path] = std::move(entry);
    }

    const std::map<std::string, ScanCacheEntry>& Fresh() const { return m_fresh; }
    size_t LoadedCount() const { return m_loaded.size(); }
    size_t Hits() const { return m_hits; }
    void NoteHit() { m_hits++; }

private:
    std::string m_ruleset;
    std::string m_policy;
    std::map<std::string, ScanCacheEntry> m_loaded;
    std::map<std::string, ScanCacheEntry> m_fresh;
    std::atomic<size_t> m_hits{0};
    std::mutex m_mutex;
};
