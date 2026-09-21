#pragma once
#include <string>
#include <vector>
#include <set>
#include <map>
#include <memory>
#include <iostream>
#include <algorithm>
#include <filesystem>

#include "Rules.h"
#include "Heuristics.h"

struct CompositeNode {
    enum class Kind { Id, And, Or, Not, CountAtLeast };

    Kind kind = Kind::Id;
    std::string id;
    int threshold = 0;
    std::vector<std::unique_ptr<CompositeNode>> children;
};

class CompositeExpression {
public:
    bool Parse(const std::string& text, std::string& error) {
        m_tokens.clear();
        m_position = 0;
        m_depth = 0;
        m_terms = 0;
        if (!Tokenize(text, error)) return false;

        m_root = ParseOr(error);
        if (!m_root) return false;
        if (m_position != m_tokens.size()) {
            error = "unexpected '" + m_tokens[m_position] + "'";
            return false;
        }
        return true;
    }

    bool Evaluate(const std::map<std::string, int>& counts) const {
        return m_root ? Evaluate(*m_root, counts) : false;
    }

    void CollectIds(std::set<std::string>& target) const {
        if (m_root) CollectIds(*m_root, target);
    }

private:
    static bool IsIdToken(const std::string& token) {
        const size_t dash = token.find('-');
        if (dash == std::string::npos || dash == 0 || dash + 1 == token.size()) return false;
        for (size_t i = 0; i < dash; ++i) {
            if (token[i] < 'A' || token[i] > 'Z') return false;
        }
        for (size_t i = dash + 1; i < token.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(token[i]))) return false;
        }
        return true;
    }

    bool Tokenize(const std::string& text, std::string& error) {
        std::string current;
        auto flush = [&]() {
            if (!current.empty()) {
                m_tokens.push_back(current);
                current.clear();
            }
        };

        for (char c : text) {
            if (c == '(' || c == ')' || c == ',') {
                flush();
                m_tokens.push_back(std::string(1, c));
            }
            else if (std::isspace(static_cast<unsigned char>(c))) {
                flush();
            }
            else {
                current += c;
            }
        }
        flush();

        if (m_tokens.empty()) {
            error = "empty expression";
            return false;
        }
        return true;
    }

    const std::string& Peek() const {
        static const std::string empty;
        return m_position < m_tokens.size() ? m_tokens[m_position] : empty;
    }

    bool Accept(const std::string& token) {
        if (m_position < m_tokens.size() && ToLowerAscii(m_tokens[m_position]) == token) {
            m_position++;
            return true;
        }
        return false;
    }

    std::unique_ptr<CompositeNode> ParseOr(std::string& error) {
        auto left = ParseAnd(error);
        if (!left) return nullptr;

        while (Accept("or")) {
            auto right = ParseAnd(error);
            if (!right) return nullptr;

            auto node = std::make_unique<CompositeNode>();
            node->kind = CompositeNode::Kind::Or;
            node->children.push_back(std::move(left));
            node->children.push_back(std::move(right));
            left = std::move(node);
        }
        return left;
    }

    std::unique_ptr<CompositeNode> ParseAnd(std::string& error) {
        auto left = ParseFactor(error);
        if (!left) return nullptr;

        while (Accept("and")) {
            auto right = ParseFactor(error);
            if (!right) return nullptr;

            auto node = std::make_unique<CompositeNode>();
            node->kind = CompositeNode::Kind::And;
            node->children.push_back(std::move(left));
            node->children.push_back(std::move(right));
            left = std::move(node);
        }
        return left;
    }

    static constexpr int kMaxDepth = 64;
    static constexpr int kMaxTerms = 256;

    std::unique_ptr<CompositeNode> ParseFactor(std::string& error) {
        const DepthGuard guard(m_depth);
        if (m_depth > kMaxDepth) {
            error = "expression nested deeper than " + std::to_string(kMaxDepth) + " levels";
            return nullptr;
        }
        if (++m_terms > kMaxTerms) {
            error = "expression has more than " + std::to_string(kMaxTerms) + " terms";
            return nullptr;
        }
        if (Accept("not")) {
            auto child = ParseFactor(error);
            if (!child) return nullptr;

            auto node = std::make_unique<CompositeNode>();
            node->kind = CompositeNode::Kind::Not;
            node->children.push_back(std::move(child));
            return node;
        }

        if (Accept("(")) {
            auto inner = ParseOr(error);
            if (!inner) return nullptr;
            if (!Accept(")")) {
                error = "missing ')'";
                return nullptr;
            }
            return inner;
        }

        if (ToLowerAscii(Peek()) == "atleast") {
            m_position++;
            return ParseAtLeast(error);
        }

        const std::string token = Peek();
        if (!IsIdToken(token)) {
            error = token.empty() ? "expression ended early" : ("expected a pattern id, got '" + token + "'");
            return nullptr;
        }
        m_position++;

        auto node = std::make_unique<CompositeNode>();
        node->kind = CompositeNode::Kind::Id;
        node->id = token;
        return node;
    }

    std::unique_ptr<CompositeNode> ParseAtLeast(std::string& error) {
        if (!Accept("(")) {
            error = "atleast requires '(' after it";
            return nullptr;
        }

        const std::string count = Peek();
        if (count.empty() || !std::all_of(count.begin(), count.end(), [](unsigned char c) {
                return std::isdigit(c) != 0;
            })) {
            error = "atleast requires a number first";
            return nullptr;
        }
        m_position++;

        auto node = std::make_unique<CompositeNode>();
        node->kind = CompositeNode::Kind::CountAtLeast;
        if (count.size() > 6) {
            error = "atleast count is outside the number of distinct ids given";
            return nullptr;
        }
        node->threshold = static_cast<int>(std::strtol(count.c_str(), nullptr, 10));

        while (Accept(",")) {
            const std::string id = Peek();
            if (!IsIdToken(id)) {
                error = "atleast expects pattern ids, got '" + id + "'";
                return nullptr;
            }
            m_position++;

            auto child = std::make_unique<CompositeNode>();
            child->kind = CompositeNode::Kind::Id;
            child->id = id;
            node->children.push_back(std::move(child));
        }

        if (!Accept(")")) {
            error = "missing ')' after atleast";
            return nullptr;
        }
        if (node->children.empty()) {
            error = "atleast needs at least one pattern id";
            return nullptr;
        }
        std::set<std::string> distinct;
        for (const auto& child : node->children) distinct.insert(child->id);
        if (node->threshold < 1 || node->threshold > static_cast<int>(distinct.size())) {
            error = "atleast count is outside the number of distinct ids given";
            return nullptr;
        }
        return node;
    }

    static bool Evaluate(const CompositeNode& node, const std::map<std::string, int>& counts) {
        switch (node.kind) {
            case CompositeNode::Kind::Id:
                return counts.find(node.id) != counts.end();
            case CompositeNode::Kind::And:
                return Evaluate(*node.children[0], counts) && Evaluate(*node.children[1], counts);
            case CompositeNode::Kind::Or:
                return Evaluate(*node.children[0], counts) || Evaluate(*node.children[1], counts);
            case CompositeNode::Kind::Not:
                return !Evaluate(*node.children[0], counts);
            case CompositeNode::Kind::CountAtLeast: {
                std::set<std::string> present;
                for (const auto& child : node.children) {
                    if (counts.find(child->id) != counts.end()) present.insert(child->id);
                }
                return static_cast<int>(present.size()) >= node.threshold;
            }
        }
        return false;
    }

    static void CollectIds(const CompositeNode& node, std::set<std::string>& target) {
        if (node.kind == CompositeNode::Kind::Id) target.insert(node.id);
        for (const auto& child : node.children) CollectIds(*child, target);
    }

    struct DepthGuard {
        explicit DepthGuard(int& value) : depth(value) { depth++; }
        ~DepthGuard() { depth--; }
        DepthGuard(const DepthGuard&) = delete;
        DepthGuard& operator=(const DepthGuard&) = delete;
        int& depth;
    };

    int m_depth = 0;
    int m_terms = 0;
    std::vector<std::string> m_tokens;
    size_t m_position = 0;
    std::unique_ptr<CompositeNode> m_root;
};

struct CompositeRule {
    std::string id;
    std::string definition;
    std::string severity;
    std::string hint;
    std::string expressionText;
    bool scanLevel = false;
    CompositeExpression expression;
};

class CompositeRuleSet {
public:
    bool Load(const std::filesystem::path& path, const PatternSet& patterns) {
        std::vector<std::string> lines;
        if (!ReadRuleLines(path, lines, false)) return false;
        return LoadFromLines(lines, patterns, PathText(path.filename()));
    }

    bool LoadFromLines(const std::vector<std::string>& lines, const PatternSet& patterns,
                       const std::string& label) {
        m_rules.clear();
        m_rawContent.clear();
        std::vector<CompositeRule> loaded;

        std::set<std::string> known;
        for (const std::string& id : patterns.Ids()) known.insert(id);
        known.insert("HASH-001");
        known.insert("MOD-001");
        known.insert("GMA-001");
        for (const StructuralSignal& signal : StructuralSignals()) known.insert(signal.id);

        for (const std::string& line : lines) {
            if (line.empty() || line[0] == '#') continue;
            m_rawContent += line;
            m_rawContent += char(10);
        }

        std::set<std::string> seenIds;

        for (size_t i = 0; i < lines.size(); ++i) {
            const std::string& line = lines[i];
            if (line.empty() || line[0] == '#') continue;

            const size_t separator = line.find(";;;");
            if (separator == std::string::npos) {
                std::cerr << "Error: Missing ';;;' separator in " << label
                          << " line " << (i + 1) << ": " << line << std::endl;
                return false;
            }

            CompositeRule rule;
            rule.expressionText = TrimAscii(line.substr(0, separator));

            const std::string scanPrefix = "scan:";
            if (rule.expressionText.rfind(scanPrefix, 0) == 0) {
                rule.scanLevel = true;
                rule.expressionText = TrimAscii(rule.expressionText.substr(scanPrefix.size()));
            }

            const std::string remainder = line.substr(separator + 3);
            const size_t hintSeparator = remainder.find(";;;");
            if (hintSeparator == std::string::npos) {
                rule.definition = TrimAscii(remainder);
            }
            else {
                rule.definition = TrimAscii(remainder.substr(0, hintSeparator));
                rule.hint = TrimAscii(remainder.substr(hintSeparator + 3));
            }

            rule.severity = SeverityFromDefinition(rule.definition);
            if (rule.severity.empty()) {
                std::cerr << "Error: No severity tag in " << label << " line " << (i + 1)
                          << ": " << rule.definition << std::endl;
                return false;
            }

            rule.id = IdFromDefinition(rule.definition);
            if (rule.id.empty()) {
                std::cerr << "Error: No rule id in " << label << " line " << (i + 1)
                          << ": " << rule.definition << std::endl;
                return false;
            }
            if (!seenIds.insert(rule.id).second) {
                std::cerr << "Error: Duplicate composite id " << rule.id << " in " << label
                          << " line " << (i + 1) << std::endl;
                return false;
            }

            std::string error;
            if (!rule.expression.Parse(rule.expressionText, error)) {
                std::cerr << "Invalid composite expression in " << label << " line " << (i + 1)
                          << ": " << ElideRuleText(rule.expressionText) << " (" << error << ")" << std::endl;
                return false;
            }

            std::set<std::string> referenced;
            rule.expression.CollectIds(referenced);
            bool unknownId = false;
            for (const std::string& id : referenced) {
                if (known.find(id) == known.end()) {
                    std::cerr << "Invalid composite expression in " << label << " line " << (i + 1)
                              << ": unknown pattern id " << id << std::endl;
                    unknownId = true;
                }
            }
            if (unknownId) return false;

            loaded.push_back(std::move(rule));
        }
        m_rules = std::move(loaded);
        return true;
    }

    const std::vector<CompositeRule>& Rules() const { return m_rules; }
    size_t Count() const { return m_rules.size(); }
    const std::string& RawContent() const { return m_rawContent; }

    std::vector<const CompositeRule*> Match(const std::map<std::string, int>& counts, bool scanLevel) const {
        std::vector<const CompositeRule*> matched;
        for (const CompositeRule& rule : m_rules) {
            if (rule.scanLevel != scanLevel) continue;
            if (rule.expression.Evaluate(counts)) matched.push_back(&rule);
        }
        return matched;
    }

    size_t CountAtLevel(bool scanLevel) const {
        size_t total = 0;
        for (const CompositeRule& rule : m_rules) {
            if (rule.scanLevel == scanLevel) total++;
        }
        return total;
    }

private:
    std::string m_rawContent;
    std::vector<CompositeRule> m_rules;
};
