#pragma once
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <stdexcept>

class MemoryBudget {
public:
    explicit MemoryBudget(uint64_t capacity) : m_capacity(capacity) {}

    class Reservation {
    public:
        Reservation(MemoryBudget& budget, uint64_t bytes) : m_budget(budget), m_bytes(bytes) {
            if (bytes > budget.m_capacity) throw std::length_error("archive exceeds memory budget");
            std::unique_lock<std::mutex> lock(budget.m_mutex);
            budget.m_available.wait(lock, [&]() { return bytes <= budget.m_capacity - budget.m_used; });
            budget.m_used += bytes;
            if (budget.m_used > budget.m_peak) budget.m_peak = budget.m_used;
        }
        ~Reservation() {
            {
                std::lock_guard<std::mutex> lock(m_budget.m_mutex);
                m_budget.m_used -= m_bytes;
            }
            m_budget.m_available.notify_all();
        }

        void Resize(uint64_t bytes) {
            if (bytes > m_budget.m_capacity) throw std::length_error("archive exceeds memory budget");
            std::unique_lock<std::mutex> lock(m_budget.m_mutex);
            m_budget.m_used -= m_bytes;
            m_bytes = 0;
            m_budget.m_available.notify_all();
            m_budget.m_available.wait(lock, [&]() {
                return bytes <= m_budget.m_capacity - m_budget.m_used;
            });
            m_budget.m_used += bytes;
            m_bytes = bytes;
            if (m_budget.m_used > m_budget.m_peak) m_budget.m_peak = m_budget.m_used;
        }
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;

    private:
        MemoryBudget& m_budget;
        uint64_t m_bytes;
    };

    uint64_t Capacity() const { return m_capacity; }
    uint64_t Peak() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_peak;
    }

private:
    uint64_t m_capacity;
    uint64_t m_used = 0;
    uint64_t m_peak = 0;
    mutable std::mutex m_mutex;
    std::condition_variable m_available;
};
