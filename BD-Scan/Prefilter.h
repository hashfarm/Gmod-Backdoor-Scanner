#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>
#include <queue>
#include <algorithm>
#include <cstddef>

static constexpr size_t kMinPrefilterLiteral = 3;

class LiteralExtractor {
public:
    static std::vector<std::string> Required(const std::string& pattern) {
        LiteralExtractor extractor(pattern);
        const Options options = extractor.ParseAlternation();
        if (extractor.m_position != pattern.size()) return {};
        if (!options.constrained) return {};

        std::vector<std::string> result(options.literals.begin(), options.literals.end());
        for (const std::string& literal : result) {
            if (literal.size() < kMinPrefilterLiteral) return {};
        }
        return result;
    }

private:
    struct Options {
        bool constrained = false;
        std::set<std::string> literals;

        size_t Weakest() const {
            size_t shortest = SIZE_MAX;
            for (const std::string& literal : literals) shortest = std::min(shortest, literal.size());
            return literals.empty() ? 0 : shortest;
        }
    };

    explicit LiteralExtractor(const std::string& pattern) : m_pattern(pattern) {}

    bool AtEnd() const { return m_position >= m_pattern.size(); }
    char Peek() const { return AtEnd() ? '\0' : m_pattern[m_position]; }

    Options ParseAlternation() {
        std::vector<Options> branches;
        branches.push_back(ParseSequence());

        while (!AtEnd() && Peek() == '|') {
            m_position++;
            branches.push_back(ParseSequence());
        }

        if (branches.size() == 1) return branches[0];

        Options merged;
        merged.constrained = true;
        for (const Options& branch : branches) {
            if (!branch.constrained) return Options();
            merged.literals.insert(branch.literals.begin(), branch.literals.end());
        }
        return merged;
    }

    Options ParseSequence() {
        std::vector<Options> constraints;
        std::string run;

        auto flushRun = [&]() {
            if (run.size() >= kMinPrefilterLiteral) {
                Options option;
                option.constrained = true;
                option.literals.insert(run);
                constraints.push_back(option);
            }
            run.clear();
        };

        while (!AtEnd() && Peek() != '|' && Peek() != ')') {
            const char c = Peek();

            if (c == '(') {
                flushRun();
                m_position++;

                bool capturing = true;
                bool assertion = false;
                if (m_position + 1 < m_pattern.size() && m_pattern[m_position] == '?') {
                    const char kind = m_pattern[m_position + 1];
                    if (kind == ':') { capturing = false; m_position += 2; }
                    else if (kind == '=' || kind == '!') { assertion = true; m_position += 2; }
                    else return Options();
                }
                (void)capturing;

                const Options inner = ParseAlternation();
                if (AtEnd() || Peek() != ')') return Options();
                m_position++;

                const bool optional = ConsumeQuantifier();
                if (!assertion && !optional && inner.constrained) constraints.push_back(inner);
                continue;
            }

            if (c == '[') {
                flushRun();
                if (!SkipCharacterClass()) return Options();
                ConsumeQuantifier();
                continue;
            }

            if (c == '\\') {
                if (m_position + 1 >= m_pattern.size()) return Options();
                const char escaped = m_pattern[m_position + 1];
                m_position += 2;

                static const std::string literalEscapes = ".^$*+?()[]{}|/\\-";
                if (literalEscapes.find(escaped) != std::string::npos) {
                    run += escaped;
                    if (ConsumeQuantifierAfterChar(run)) flushRun();
                }
                else {
                    flushRun();
                    ConsumeQuantifier();
                }
                continue;
            }

            if (c == '.' || c == '^' || c == '$') {
                flushRun();
                m_position++;
                ConsumeQuantifier();
                continue;
            }

            run += c;
            m_position++;
            if (ConsumeQuantifierAfterChar(run)) flushRun();
        }
        flushRun();

        if (constraints.empty()) return Options();

        const Options* best = &constraints[0];
        for (const Options& candidate : constraints) {
            if (candidate.Weakest() > best->Weakest()) best = &candidate;
        }
        return *best;
    }

    bool SkipCharacterClass() {
        m_position++;
        if (!AtEnd() && Peek() == '^') m_position++;
        if (!AtEnd() && Peek() == ']') m_position++;

        while (!AtEnd() && Peek() != ']') {
            if (Peek() == '\\') {
                m_position += 2;
                continue;
            }
            if (Peek() == '[' && m_position + 1 < m_pattern.size() &&
                (m_pattern[m_position + 1] == ':' || m_pattern[m_position + 1] == '.' ||
                 m_pattern[m_position + 1] == '=')) {
                const std::string terminator = std::string(1, m_pattern[m_position + 1]) + "]";
                const size_t close = m_pattern.find(terminator, m_position + 2);
                if (close == std::string::npos) return false;
                m_position = close + 2;
                continue;
            }
            m_position++;
        }
        if (AtEnd()) return false;
        m_position++;
        return true;
    }

    bool ConsumeQuantifier() {
        if (AtEnd()) return false;
        const char c = Peek();

        if (c == '?' || c == '*') {
            m_position++;
            if (!AtEnd() && Peek() == '?') m_position++;
            return true;
        }
        if (c == '+') {
            m_position++;
            if (!AtEnd() && Peek() == '?') m_position++;
            return false;
        }
        if (c == '{') {
            const size_t close = m_pattern.find('}', m_position);
            if (close == std::string::npos) return false;

            const std::string body = m_pattern.substr(m_position + 1, close - m_position - 1);
            m_position = close + 1;
            if (!AtEnd() && Peek() == '?') m_position++;
            return body.empty() || body[0] == '0';
        }
        return false;
    }

    bool ConsumeQuantifierAfterChar(std::string& run) {
        if (AtEnd()) return false;
        const char c = Peek();
        if (c != '?' && c != '*' && c != '+' && c != '{') return false;

        const bool optional = ConsumeQuantifier();
        if (optional && !run.empty()) run.pop_back();
        return true;
    }

    const std::string& m_pattern;
    size_t m_position = 0;
};

class AhoCorasick {
public:
    size_t Add(const std::string& literal) {
        const auto existing = m_index.find(literal);
        if (existing != m_index.end()) return existing->second;

        const size_t id = m_literals.size();
        m_literals.push_back(literal);
        m_index[literal] = id;
        return id;
    }

    void Build() {
        m_nodes.clear();
        m_nodes.push_back(Node());

        for (size_t id = 0; id < m_literals.size(); ++id) {
            size_t node = 0;
            for (unsigned char c : m_literals[id]) {
                if (m_nodes[node].next[c] == 0) {
                    m_nodes[node].next[c] = static_cast<uint32_t>(m_nodes.size());
                    m_nodes.push_back(Node());
                }
                node = m_nodes[node].next[c];
            }
            m_nodes[node].outputs.push_back(id);
        }

        std::queue<size_t> pending;
        for (int c = 0; c < 256; ++c) {
            const uint32_t child = m_nodes[0].next[c];
            if (child != 0) {
                m_nodes[child].fail = 0;
                pending.push(child);
            }
        }

        while (!pending.empty()) {
            const size_t node = pending.front();
            pending.pop();

            for (int c = 0; c < 256; ++c) {
                const uint32_t child = m_nodes[node].next[c];
                if (child == 0) {
                    m_nodes[node].next[c] = m_nodes[m_nodes[node].fail].next[c];
                    continue;
                }

                size_t fail = m_nodes[node].fail;
                m_nodes[child].fail = m_nodes[fail].next[c];
                const std::vector<size_t>& inherited = m_nodes[m_nodes[child].fail].outputs;
                m_nodes[child].outputs.insert(m_nodes[child].outputs.end(),
                                              inherited.begin(), inherited.end());
                pending.push(child);
            }
        }
        m_built = true;
    }

    bool Built() const { return m_built; }
    size_t LiteralCount() const { return m_literals.size(); }
    size_t NodeCount() const { return m_nodes.size(); }

    void Search(const char* data, size_t length, std::vector<bool>& present) const {
        present.assign(m_literals.size(), false);
        if (!m_built || m_nodes.empty()) return;

        size_t node = 0;
        for (size_t i = 0; i < length; ++i) {
            node = m_nodes[node].next[static_cast<unsigned char>(data[i])];
            for (size_t id : m_nodes[node].outputs) present[id] = true;
        }
    }

private:
    struct Node {
        uint32_t next[256] = {};
        uint32_t fail = 0;
        std::vector<size_t> outputs;
    };

    std::vector<std::string> m_literals;
    std::map<std::string, size_t> m_index;
    std::vector<Node> m_nodes;
    bool m_built = false;
};
