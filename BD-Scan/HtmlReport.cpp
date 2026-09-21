#include "HtmlReport.h"
#include <fstream>
#include <set>

static constexpr size_t kFilesOpenByDefault = 10;
static constexpr size_t kMaxDetailedFilesInHtml = 100;
static constexpr size_t kMaxDetectionsPerFileInHtml = 20;
static constexpr size_t kSkipSamplesInSummary = 5;

std::string HtmlEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;        break;
        }
    }
    return out;
}

std::string ShortenPath(const std::string& file, const std::string& root) {
    if (root.empty() || file.size() <= root.size()) return file;
    if (file.compare(0, root.size(), root) != 0) return file;
    size_t start = root.size();
    while (start < file.size() && (file[start] == '/' || file[start] == '\\')) start++;
    return file.substr(start);
}

bool GenerateHtmlReport(const std::vector<Detection>& detections, const std::vector<FileScore>& scores,
                        const SeverityTotals& totals, const HtmlReportSummary& summary,
                        const SkipRegistry& skipped, const std::filesystem::path& path) {
    std::ofstream html(path);
    if (!html.is_open()) return false;

    html << R"(<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BD-Scan report</title>
<style>
:root {
  --ink: #16181d;
  --muted: #5f6570;
  --faint: #8b919b;
  --rule: #dcdfe4;
  --bg: #fdfdfc;
  --panel: #f5f6f4;
  --crit: #b3170b;
  --high: #9a6000;
  --med: #7a5a1e;
  --low: #7c828d;
  --hit: #e7e4d8;
  --hit-edge: #8a7c42;
  --crit-fill: #d70000;
  --high-fill: #ffaf00;
  --med-fill: #d7af5f;
  --low-fill: #a8a8a8;
  --on-fill: #14161b;
  --on-crit: #ffffff;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ink: #dfe2e8;
    --muted: #97a0b0;
    --faint: #737c8c;
    --rule: #262c36;
    --bg: #101319;
    --panel: #171b22;
    --hit: #26303d;
    --hit-edge: #4d7ea8;
    --crit: #ff6b60;
    --high: #ffaf00;
    --med: #d7af5f;
    --low: #9aa1ad;
  }
}
:root[data-theme="dark"] {
  --ink: #dfe2e8;
  --muted: #97a0b0;
  --faint: #737c8c;
  --rule: #262c36;
  --bg: #101319;
  --panel: #171b22;
  --hit: #26303d;
  --hit-edge: #4d7ea8;
  --crit: #ff6b60;
  --high: #ffaf00;
  --med: #d7af5f;
  --low: #9aa1ad;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; padding: 0 2rem 4rem;
  background: var(--bg); color: var(--ink);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-variant-numeric: tabular-nums;
}
.wrap { max-width: 68rem; margin: 0 auto; }
code, pre, .mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace; }

header { padding: 2.25rem 0 1rem; border-bottom: 1px solid var(--rule); }
h1 { margin: 0; font-size: 1.15rem; font-weight: 600; letter-spacing: -0.01em; }
.sub { margin: 0.35rem 0 0; color: var(--muted); font-size: 0.85rem; }

.tally { margin: 1.25rem 0 0; display: flex; gap: 1.75rem; flex-wrap: wrap; align-items: baseline; }
.tally div { display: flex; gap: 0.4rem; align-items: baseline; }
.tally b { font-size: 1.45rem; font-weight: 600; line-height: 1; }
.tally span { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
.tally .c-critical b { color: var(--crit); }
.tally .c-high b { color: var(--high); }
.tally .zero b { color: var(--faint); font-weight: 400; }

.note { margin: 1.5rem 0; padding: 0 0 0 0.9rem; border-left: 2px solid var(--rule); color: var(--muted); font-size: 0.875rem; }
.note.alert { border-left-color: var(--crit); color: var(--ink); }
.note.alert strong { color: var(--crit); }
.note ul { margin: 0.4rem 0 0; padding-left: 1.1rem; }
.note li { margin: 0.15rem 0; }
.note .mono { font-size: 0.8rem; color: var(--muted); word-break: break-all; }

.toolbar {
  position: sticky; top: 0; z-index: 5; background: var(--bg);
  border-bottom: 1px solid var(--rule); padding: 0.7rem 0; margin: 1.75rem 0 0;
  display: flex; gap: 1.1rem; flex-wrap: wrap; align-items: center; font-size: 0.85rem;
}
.toolbar > b { font-weight: 600; color: var(--muted); }
.toolbar label { cursor: pointer; user-select: none; display: inline-flex; gap: 0.3rem; align-items: center; }
.toolbar button {
  font: inherit; background: none; border: 1px solid var(--rule); border-radius: 3px;
  padding: 0.15rem 0.6rem; cursor: pointer; color: var(--muted);
}
.toolbar button:hover { border-color: var(--faint); color: var(--ink); }
#q {
  font: inherit; font-size: 0.85rem; color: var(--ink);
  background: var(--bg); border: 1px solid var(--rule); border-radius: 3px;
  padding: 0.2rem 0.55rem; min-width: 15rem; flex: 1 1 15rem;
}
#q:focus { outline: 2px solid var(--high-fill); outline-offset: 1px; border-color: transparent; }
#q::placeholder { color: var(--faint); }
mark { background: var(--high-fill); color: var(--on-fill); border-radius: 2px; padding: 0 1px; }
#counter { margin-left: auto; color: var(--faint); }
h2.section {
  margin: 2.25rem 0 0.75rem; font-size: 0.78rem; font-weight: 600;
  letter-spacing: 0.09em; text-transform: uppercase; color: var(--faint);
}
h2.section:first-of-type { margin-top: 1.5rem; }
.visually-hidden {
  position: absolute; width: 1px; height: 1px; margin: -1px;
  padding: 0; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}

details.file { border-bottom: 1px solid var(--rule); }
details.file[hidden] { display: none; }
details.file > summary {
  cursor: pointer; list-style: none; padding: 0.85rem 0;
  display: grid; grid-template-columns: 3.2rem 1fr auto; gap: 0.9rem; align-items: baseline;
}
details.file > summary::-webkit-details-marker { display: none; }
summary .score { font-weight: 600; text-align: right; font-size: 0.9rem; }
summary .path { word-break: break-all; font-size: 0.875rem; }
summary .counts { color: var(--faint); font-size: 0.78rem; white-space: nowrap; }
details.file > summary:hover .path { text-decoration: underline; text-underline-offset: 2px; }

.finding { padding: 0.15rem 0 1.1rem 0.9rem; margin: 0 0 0 3.2rem; border-left: 2px solid var(--rule); }
.finding[hidden] { display: none; }
.finding.critical { border-left-color: var(--crit); }
.finding.high { border-left-color: var(--high); }
.finding .head { display: flex; gap: 0.55rem; flex-wrap: wrap; align-items: baseline; }
.sev {
  font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.07em; font-weight: 700;
  padding: 2px 7px; border-radius: 3px; white-space: nowrap;
}
.critical > .head .sev { background: var(--crit-fill); color: var(--on-crit); }
.high > .head .sev { background: var(--high-fill); color: var(--on-fill); }
.medium > .head .sev { background: var(--med-fill); color: var(--on-fill); }
.low > .head .sev { background: var(--low-fill); color: var(--on-fill); }
.rid { font-size: 0.8rem; color: var(--muted); }
.title { font-size: 0.9rem; }
.at { color: var(--faint); font-size: 0.8rem; }

pre.src {
  margin: 0.5rem 0 0; padding: 0.6rem 0; background: var(--panel);
  border-radius: 2px; overflow-x: auto; font-size: 0.8rem; line-height: 1.6;
}
pre.src .row { display: block; padding: 0 0.8rem 0 0.55rem; white-space: pre; border-left: 0.25rem solid transparent; }
pre.src .row.hit { background: var(--hit); border-left-color: var(--hit-edge); color: var(--ink); font-weight: 600; }
pre.src .no { display: inline-block; width: 3.2rem; text-align: right; padding-right: 1rem; color: var(--faint); user-select: none; }
.decoded { margin: 0.45rem 0 0; font-size: 0.8rem; color: var(--muted); }
.decoded .mono { color: var(--ink); }
.hint { margin: 0.5rem 0 0; font-size: 0.83rem; color: var(--muted); max-width: 52rem; }
.more { margin: 0 0 0 3.2rem; padding: 0.2rem 0 1rem 0.9rem; font-size: 0.8rem; color: var(--faint); }

.rest { margin-top: 2.5rem; }
.rest h2 { font-size: 0.95rem; font-weight: 600; margin: 0 0 0.3rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.8rem; margin-top: 0.9rem; }
th { text-align: left; font-weight: 600; color: var(--muted); border-bottom: 1px solid var(--rule); padding: 0.35rem 0.5rem; }
th.n, td.n { text-align: right; width: 3rem; }
td { padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--rule); word-break: break-all; }
td.n { color: var(--muted); }
td.n.s { color: var(--ink); font-weight: 600; }

footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--rule); color: var(--faint); font-size: 0.78rem; }

@media print {
  .toolbar { display: none; }
  details.file { break-inside: avoid; }
  details.file > summary::before { content: none; }
}
</style></head><body><div class="wrap">
)";

    html << "<div class='stats'>";
    html << "<header><h1>Backdoor scan</h1><p class='sub'>";
    html << summary.filesProcessed << " file" << (summary.filesProcessed == 1 ? "" : "s") << " examined";
    html << " &middot; " << scores.size() << " with findings";
    if (summary.decompressedArchives > 0) {
        html << " &middot; " << summary.decompressedArchives << " archive"
             << (summary.decompressedArchives == 1 ? "" : "s") << " decompressed";
    }
    const int whitelisted = summary.whitelisted;
    if (whitelisted > 0) html << " &middot; " << whitelisted << " whitelisted";
    if (summary.diff) html << " &middot; " << summary.baseline << " already in baseline";
    if (summary.minSeverity != "low") html << " &middot; " << HtmlEscape(summary.minSeverity) << " and above only";
    html << "</p>";

    struct Tally { const char* key; const char* label; int value; };
    const Tally tallies[] = {
        { "critical", "critical", totals.critical },
        { "high",     "high",     totals.high },
        { "medium",   "medium",   totals.medium },
        { "low",      "low",      totals.low },
    };
    html << "<h2 class='section'>Summary</h2>";
    html << "<div class='tally'>";
    for (const Tally& tally : tallies) {
        html << "<div class='c-" << tally.key << (tally.value == 0 ? " zero" : "") << "'>"
             << "<b>" << tally.value << "</b><span>" << tally.label << "</span></div>";
    }
    html << "</div></header></div>";

    const int unscanned = skipped.Total();
    if (unscanned > 0) {
        html << "<h2 class='section'>Not examined</h2>";
        html << "<div class='note alert'><strong>" << unscanned << " file"
             << (unscanned == 1 ? " was" : "s were") << " not examined.</strong> "
             << "This scan is incomplete and its result is not a clean bill of health.<ul>";
        for (int i = 0; i < static_cast<int>(SkipReason::Count); ++i) {
            const SkipReason reason = static_cast<SkipReason>(i);
            const int count = skipped.Count(reason);
            if (count == 0) continue;

            html << "<li>" << count << " " << HtmlEscape(SkipReasonText(reason));
            const std::vector<std::string> samples = skipped.Samples(reason, kSkipSamplesInSummary);
            if (!samples.empty()) {
                html << "<br>";
                for (const std::string& sample : samples) {
                    html << "<span class='mono'>" << HtmlEscape(sample) << "</span><br>";
                }
                if (count > static_cast<int>(samples.size())) {
                    html << "<span class='mono'>&hellip; and " << (count - static_cast<int>(samples.size()))
                         << " more, listed in scan_log.json</span>";
                }
            }
            html << "</li>";
        }
        html << "</ul></div>";
    }

    html << "<h2 class='section'>Findings</h2>";
    html << "<p class='note'>Files are ordered by score, which adds a weight for each "
            "<em>distinct</em> kind of finding (critical 10, high 3, medium 1). A file combining "
            "several kinds of evidence therefore ranks above one that repeats a single rule.</p>";

    html << "<div class='toolbar'><b id='showlabel'>Show</b>";
    for (const char* severity : { "critical", "high", "medium", "low" }) {
        html << "<label><input type='checkbox' class='sev' value='" << severity << "' checked>"
             << severity << "</label>";
    }
    html << "<label class='visually-hidden' for='q'>Filter findings</label>";
    html << "<input type='search' id='q' placeholder='Filter by file, rule or code'>";
    html << "<button onclick=\"setAll(true)\">Expand all</button>";
    html << "<button onclick=\"setAll(false)\">Collapse all</button>";
    html << "<span id='counter' role='status' aria-live='polite' data-total='"
         << detections.size() << "'></span>";
    html << "</div>";

    std::map<std::string, std::vector<const Detection*>> byFile;
    for (const Detection& detection : detections) byFile[detection.file].push_back(&detection);

    size_t fileIndex = 0;
    for (const FileScore& score : scores) {
        if (fileIndex >= kMaxDetailedFilesInHtml) break;
        const bool openByDefault = (fileIndex < kFilesOpenByDefault);
        fileIndex++;

        html << "<details class='file'" << (openByDefault ? " open" : "") << ">";
        html << "<summary><span class='score'>" << score.score << "</span>"
             << "<span class='path mono' title='" << HtmlEscape(score.file) << "'>"
             << HtmlEscape(ShortenPath(score.file, summary.scanRoot)) << "</span>"
             << "<span class='counts'>";
        bool first = true;
        const std::pair<int, const char*> parts[] = {
            { score.critical, "critical" }, { score.high, "high" },
            { score.medium, "medium" }, { score.low, "low" },
        };
        for (const auto& part : parts) {
            if (part.first == 0) continue;
            if (!first) html << " &middot; ";
            html << part.first << " " << part.second;
            first = false;
        }
        html << "</span></summary>";

        std::vector<const Detection*> ordered = byFile[score.file];
        std::stable_sort(ordered.begin(), ordered.end(), [](const Detection* a, const Detection* b) {
            if (SeverityRank(a->severity) != SeverityRank(b->severity)) {
                return SeverityRank(a->severity) < SeverityRank(b->severity);
            }
            return a->lineNumber < b->lineNumber;
        });

        std::vector<const Detection*> shown;
        std::set<const Detection*> picked;
        std::set<std::string> seenRules;
        for (const Detection* detection : ordered) {
            if (shown.size() >= kMaxDetectionsPerFileInHtml) break;
            if (!seenRules.insert(detection->id).second) continue;
            shown.push_back(detection);
            picked.insert(detection);
        }
        for (const Detection* detection : ordered) {
            if (shown.size() >= kMaxDetectionsPerFileInHtml) break;
            if (picked.count(detection) != 0) continue;
            shown.push_back(detection);
            picked.insert(detection);
        }
        std::stable_sort(shown.begin(), shown.end(), [](const Detection* a, const Detection* b) {
            if (SeverityRank(a->severity) != SeverityRank(b->severity)) {
                return SeverityRank(a->severity) < SeverityRank(b->severity);
            }
            return a->lineNumber < b->lineNumber;
        });
        const bool everyRuleShown = seenRules.size() == shown.size() ||
                                    seenRules.size() <= kMaxDetectionsPerFileInHtml;

        for (const Detection* detection : shown) {

            std::string title = detection->detection;
            const size_t tagEnd = title.find(']');
            if (tagEnd != std::string::npos) title = TrimAscii(title.substr(tagEnd + 1));
            if (!detection->id.empty() && title.rfind(detection->id, 0) == 0) {
                title = TrimAscii(title.substr(detection->id.size()));
            }

            html << "<div class='finding " << detection->severity << "'><div class='head'>";
            html << "<span class='sev'>" << detection->severity << "</span>";
            if (!detection->id.empty()) html << "<span class='rid mono'>" << HtmlEscape(detection->id) << "</span>";
            html << "<span class='title'>" << HtmlEscape(title) << "</span>";
            if (detection->lineNumber > 0) html << "<span class='at'>line " << detection->lineNumber << "</span>";
            html << "</div>";

            if (detection->context.empty()) {
                if (!detection->lineText.empty()) {
                    html << "<pre class='src'><span class='row'>"
                         << HtmlEscape(detection->lineText) << "</span></pre>";
                }
            }
            else {
                const bool numbered = detection->contextStart > 0;
                html << "<pre class='src'>";
                for (size_t i = 0; i < detection->context.size(); ++i) {
                    const int number = detection->contextStart + static_cast<int>(i);
                    const bool isMatch = numbered ? (number == detection->lineNumber)
                                                  : (detection->context[i] == detection->lineText);
                    html << "<span class='row" << (isMatch ? " hit" : "") << "'>";
                    if (numbered) html << "<span class='no'>" << number << "</span>";
                    html << HtmlEscape(detection->context[i]) << "</span>";
                }
                html << "</pre>";
            }

            if (!detection->related.empty()) {
                html << "<ul class='hint'>";
                for (const DetectionEvidence& evidence : detection->related) {
                    html << "<li><span class='mono'>" << HtmlEscape(evidence.id) << " &middot; "
                         << HtmlEscape(evidence.file) << "</span>";
                    if (evidence.lineNumber > 0) html << " &middot; line " << evidence.lineNumber;
                    html << "</li>";
                }
                html << "</ul>";
            }

            if (!detection->decodedContent.empty()) {
                html << "<p class='decoded'>decodes to <span class='mono'>"
                     << HtmlEscape(detection->decodedContent) << "</span></p>";
            }
            if (!detection->hint.empty()) {
                html << "<p class='hint'>" << HtmlEscape(detection->hint) << "</p>";
            }
            html << "</div>";
        }
        if (shown.size() < ordered.size()) {
            const size_t remaining = ordered.size() - shown.size();
            html << "<div class='more'>" << remaining << " further finding"
                 << (remaining == 1 ? "" : "s") << " in this file, listed in scan_log.json."
                 << (everyRuleShown ? " Every rule that fired here is shown above." : "")
                 << "</div>";
        }
        html << "</details>";
    }

    if (scores.size() > kMaxDetailedFilesInHtml) {
        const size_t remaining = scores.size() - kMaxDetailedFilesInHtml;
        html << "<div class='rest'><h2 class='section'>" << remaining << " further file"
             << (remaining == 1 ? "" : "s") << " with findings</h2>";
        html << "<p class='note'>Detail is shown for the " << kMaxDetailedFilesInHtml
             << " highest-scoring files. Every finding, including these, is in scan_log.json.</p>";
        html << "<table><thead><tr><th class='n'>Score</th><th>File</th>"
             << "<th class='n'>Crit</th><th class='n'>High</th>"
             << "<th class='n'>Med</th><th class='n'>Low</th></tr></thead><tbody>";
        for (size_t i = kMaxDetailedFilesInHtml; i < scores.size(); ++i) {
            const FileScore& score = scores[i];
            html << "<tr><td class='n s'>" << score.score << "</td>"
                 << "<td class='mono'>" << HtmlEscape(score.file) << "</td>"
                 << "<td class='n'>" << score.critical << "</td><td class='n'>" << score.high << "</td>"
                 << "<td class='n'>" << score.medium << "</td><td class='n'>" << score.low << "</td></tr>";
        }
        html << "</tbody></table></div>";
    }

    html << R"(
<script>
var boxes = document.querySelectorAll('input.sev');
var files = document.querySelectorAll('details.file');
var query = document.getElementById('q');

function haystack(file, finding) {
  var path = file.querySelector('.path');
  var id = finding.querySelector('.rid');
  var title = finding.querySelector('.title');
  var code = finding.querySelector('.src');
  return [
    path ? path.textContent : '',
    id ? id.textContent : '',
    title ? title.textContent : '',
    code ? code.textContent : ''
  ].join(' ').toLowerCase();
}

function apply() {
  var on = {};
  boxes.forEach(function (b) { on[b.value] = b.checked; });
  var needle = (query.value || '').trim().toLowerCase();

  var shown = 0;
  files.forEach(function (file) {
    var visible = 0;
    file.querySelectorAll('.finding').forEach(function (d) {
      var match = false;
      ['critical', 'high', 'medium', 'low'].forEach(function (s) {
        if (d.classList.contains(s) && on[s]) match = true;
      });
      if (match && needle) match = haystack(file, d).indexOf(needle) !== -1;
      d.hidden = !match;
      if (match) visible++;
    });
    file.hidden = visible === 0;
    if (needle && visible > 0) file.open = true;
    shown += visible;
  });

  var counter = document.getElementById('counter');
  var total = parseInt(counter.getAttribute('data-total'), 10);
  var rendered = document.querySelectorAll('.finding').length;

  counter.textContent = shown === 0
    ? 'nothing matches'
    : (total > rendered
       ? shown + ' of ' + rendered + ' shown · ' + total + ' total, rest in scan_log.json'
       : shown + ' finding' + (shown === 1 ? '' : 's') + ' shown');
}

function setAll(open) {
  files.forEach(function (file) { if (!file.hidden) file.open = open; });
}

boxes.forEach(function (b) { b.addEventListener('change', apply); });
query.addEventListener('input', apply);
query.addEventListener('keydown', function (event) {
  if (event.key === 'Escape') { query.value = ''; apply(); }
});
apply();
</script>
</div></body></html>)";
    html.close();
    return static_cast<bool>(html);
}
