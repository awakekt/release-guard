/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.report

import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.BaselineDiff
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseScorecard
import com.awakekt.releaseguard.model.TargetScorecard

/**
 * Renders a [ReleaseScorecard] as a self-contained, zero-CDN, interactive HTML dashboard with
 * visual score gauges, per-target cards, plain-English "What an attacker can do" explanations,
 * attacker skill ratings, filter chips, and collapsible evidence panels.
 */
public object HtmlReportRenderer {
    /** Generates a standalone UTF-8 HTML document for [scorecard]. */
    public fun renderHtml(scorecard: ReleaseScorecard): String = buildString {
        appendLine("<!DOCTYPE html>")
        appendLine("<html lang=\"en\">")
        appendLine("<head>")
        appendLine("  <meta charset=\"UTF-8\" />")
        appendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />")
        appendLine("  <title>Release Guard Report - ${scorecard.overallScore}/100 (${scorecard.grade.label})</title>")
        appendLine("  <style>")
        appendLine(DASHBOARD_CSS)
        appendLine("  </style>")
        appendLine("</head>")
        appendLine("<body>")
        appendLine("  <div class=\"wrap\">")
        appendHeader(this, scorecard)
        scorecard.baselineDiff?.let { appendBaselineBanner(this, it) }
        appendTargetCards(this, scorecard.targets)
        appendFindingsSection(this, scorecard.findings)
        if (scorecard.metrics.isNotEmpty()) appendMetricsSection(this, scorecard.metrics)
        appendLine("  </div>")
        appendLine("  <script>")
        appendLine(DASHBOARD_JS)
        appendLine("  </script>")
        appendLine("</body>")
        appendLine("</html>")
    }

    private fun appendHeader(out: StringBuilder, scorecard: ReleaseScorecard) {
        val gateClass = if (scorecard.passedGate) "badge-pass" else "badge-fail"
        val gateText = if (scorecard.passedGate) "GATE PASSED" else "GATE FAILED"
        val scoreColor = scoreAccentColor(scorecard.overallScore)
        val failCount = scorecard.findings.count { it.status == CheckStatus.FAIL }
        val warnCount = scorecard.findings.count { it.status == CheckStatus.WARN }
        val passCount = scorecard.findings.count { it.status == CheckStatus.PASS }

        out.appendLine("    <header class=\"hero\">")
        out.appendLine("      <div class=\"hero-score\" style=\"--pct:${scorecard.overallScore};--accent:$scoreColor;\">")
        out.appendLine("        <div class=\"ring\"><div class=\"ring-inner\"><span class=\"score-num\">${scorecard.overallScore}</span><span class=\"score-den\">/100</span><span class=\"grade\">${escapeHtml(scorecard.grade.label)}</span></div></div>")
        out.appendLine("      </div>")
        out.appendLine("      <div class=\"hero-meta\">")
        out.appendLine("        <div class=\"eyebrow\">Release Guard - Static Release Hygiene &amp; Obfuscation Report</div>")
        out.appendLine("        <h1>Release Readiness Summary <span class=\"badge $gateClass\">$gateText</span></h1>")
        out.appendLine("        <p class=\"lead\">Found <strong>$failCount failing</strong>, <strong>$warnCount warning</strong>, and <strong>$passCount passing</strong> check(s) across ${scorecard.targets.size} target(s). Click any check below to see what a rookie or advanced attacker sees and how to fix it.</p>")
        out.appendLine("        <div class=\"trust-note\"><strong>Trust boundary:</strong> Static obfuscation, binary hardening, and packaging checks raise reverse-engineering cost and prevent accidental leaks, but never replace server-authoritative validation or runtime RASP.</div>")
        if (scorecard.gateReasons.isNotEmpty()) {
            out.appendLine("        <ul class=\"gate-list\">")
            scorecard.gateReasons.forEach { reason -> out.appendLine("          <li>${escapeHtml(reason)}</li>") }
            out.appendLine("        </ul>")
        }
        out.appendLine("      </div>")
        out.appendLine("    </header>")
    }

    private fun appendBaselineBanner(out: StringBuilder, diff: BaselineDiff) {
        val sign = if (diff.scoreDelta >= 0) "+" else ""
        val cls = if (diff.hasRegressions) "banner-fail" else "banner-pass"
        out.appendLine("    <section class=\"banner $cls\">")
        out.appendLine("      <strong>Baseline comparison:</strong> ${diff.baselineScore} &rarr; ${diff.currentScore} (<strong>$sign${diff.scoreDelta}</strong>)")
        if (diff.newFailures.isNotEmpty()) {
            out.appendLine("      &nbsp;&middot;&nbsp; New failures: <code>${escapeHtml(diff.newFailures.joinToString(", "))}</code>")
        }
        if (diff.resolvedFailures.isNotEmpty()) {
            out.appendLine("      &nbsp;&middot;&nbsp; Resolved: <code>${escapeHtml(diff.resolvedFailures.joinToString(", "))}</code>")
        }
        out.appendLine("    </section>")
    }

    private fun appendTargetCards(out: StringBuilder, targets: List<TargetScorecard>) {
        if (targets.isEmpty()) return
        out.appendLine("    <section class=\"targets\">")
        for (t in targets) {
            val color = scoreAccentColor(t.score)
            out.appendLine("      <button class=\"target-card\" data-target-filter=\"${escapeHtml(t.target.name)}\" type=\"button\">")
            out.appendLine("        <div class=\"target-top\"><span class=\"target-name\">${escapeHtml(t.target.displayName)}</span><span class=\"target-grade\" style=\"color:$color\">${t.score}/100 (${escapeHtml(t.grade.label)})</span></div>")
            out.appendLine("        <div class=\"bar\"><div class=\"bar-fill\" style=\"width:${t.score}%;background:$color\"></div></div>")
            out.appendLine("        <div class=\"target-counts\"><span class=\"c-pass\">${t.passedChecks} pass</span><span class=\"c-warn\">${t.warnedChecks} warn</span><span class=\"c-fail\">${t.failedChecks} fail</span><span class=\"c-skip\">${t.skippedChecks} skip</span></div>")
            out.appendLine("      </button>")
        }
        out.appendLine("    </section>")
    }

    private fun appendFindingsSection(out: StringBuilder, findings: List<AuditFinding>) {
        val sorted = findings.sortedWith(compareByDescending<AuditFinding> { it.status.severityRank }.thenByDescending { it.severity.rank })
        out.appendLine("    <section class=\"panel\">")
        out.appendLine("      <div class=\"toolbar\">")
        out.appendLine("        <h2>Detailed Findings</h2>")
        out.appendLine("        <div class=\"filters\" role=\"group\" aria-label=\"Status filters\">")
        out.appendLine("          <button class=\"chip active\" data-status-filter=\"ALL\" type=\"button\">All (${findings.size})</button>")
        out.appendLine("          <button class=\"chip\" data-status-filter=\"FAIL\" type=\"button\">Failed (${findings.count { it.status == CheckStatus.FAIL }})</button>")
        out.appendLine("          <button class=\"chip\" data-status-filter=\"WARN\" type=\"button\">Warnings (${findings.count { it.status == CheckStatus.WARN }})</button>")
        out.appendLine("          <button class=\"chip\" data-status-filter=\"PASS\" type=\"button\">Passed (${findings.count { it.status == CheckStatus.PASS }})</button>")
        out.appendLine("          <button class=\"chip\" data-status-filter=\"SKIP\" type=\"button\">Skipped (${findings.count { it.status == CheckStatus.SKIP }})</button>")
        out.appendLine("        </div>")
        out.appendLine("      </div>")
        out.appendLine("      <div class=\"findings-list\" id=\"findings\">")
        for (finding in sorted) {
            appendFindingCard(out, finding)
        }
        out.appendLine("      </div>")
        out.appendLine("    </section>")
    }

    private fun appendFindingCard(out: StringBuilder, finding: AuditFinding) {
        val explanation = FindingExplainer.explain(finding)
        val narrative = FindingExplainer.narrativeFor(finding)
        val statusLower = finding.status.name.lowercase()
        val openAttr = if (finding.status == CheckStatus.FAIL || finding.status == CheckStatus.WARN) " open" else ""
        val impactHeading = if (finding.status == CheckStatus.PASS) "Why this is good" else "What an attacker can see / do"

        out.appendLine("        <details class=\"finding status-$statusLower\" data-status=\"${finding.status.name}\" data-target=\"${finding.target.name}\"$openAttr>")
        out.appendLine("          <summary>")
        out.appendLine("            <span class=\"pill pill-$statusLower\">${finding.status.name}</span>")
        out.appendLine("            <span class=\"pill pill-sev\">${finding.severity.name}</span>")
        out.appendLine("            <span class=\"finding-title\">${escapeHtml(finding.title)}</span>")
        out.appendLine("            <span class=\"finding-target\">${escapeHtml(finding.target.displayName)}</span>")
        out.appendLine("            <code class=\"finding-id\">${escapeHtml(finding.checkId)}</code>")
        out.appendLine("          </summary>")
        out.appendLine("          <div class=\"finding-body\">")
        out.appendLine("            <div class=\"explain-box\">")
        out.appendLine("              <div class=\"explain-head\"><strong>$impactHeading</strong><span class=\"attacker-tag\">Difficulty / Vector: ${escapeHtml(explanation.attackerLevel)}</span></div>")
        out.appendLine("              <p>${escapeHtml(narrative)}</p>")
        out.appendLine("            </div>")
        out.appendLine("            <div class=\"tech-row\"><strong>Measured result:</strong> ${escapeHtml(finding.summary)} <span class=\"weight\">(weight ${finding.weight})</span></div>")
        if (finding.evidence.isNotEmpty() && finding.status != CheckStatus.PASS) {
            out.appendLine("            <div class=\"evidence\"><strong>Evidence found:</strong><ul>")
            finding.evidence.forEach { item -> out.appendLine("              <li><code>${escapeHtml(item)}</code></li>") }
            out.appendLine("            </ul></div>")
        }
        if (finding.remediation.isNotBlank() && finding.status != CheckStatus.PASS && finding.status != CheckStatus.SKIP) {
            out.appendLine("            <div class=\"fix-box\"><strong>How to fix:</strong> ${escapeHtml(finding.remediation)}</div>")
        }
        out.appendLine("          </div>")
        out.appendLine("        </details>")
    }

    private fun appendMetricsSection(out: StringBuilder, metrics: Map<String, String>) {
        out.appendLine("    <details class=\"panel metrics-panel\">")
        out.appendLine("      <summary><h2>Raw Telemetry Metrics (${metrics.size})</h2></summary>")
        out.appendLine("      <table class=\"metrics-table\"><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>")
        for ((k, v) in metrics) {
            out.appendLine("        <tr><td><code>${escapeHtml(k)}</code></td><td><code>${escapeHtml(v)}</code></td></tr>")
        }
        out.appendLine("      </tbody></table>")
        out.appendLine("    </details>")
    }

    private fun scoreAccentColor(score: Int): String = when {
        score >= 90 -> "#22c55e"
        score >= 75 -> "#eab308"
        score >= 60 -> "#f97316"
        else -> "#ef4444"
    }

    private fun escapeHtml(raw: String): String = buildString(raw.length + 16) {
        for (ch in raw) {
            when (ch) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '"' -> append("&quot;")
                '\'' -> append("&#39;")
                else -> append(ch)
            }
        }
    }

    private const val DASHBOARD_CSS: String = """
    :root{--bg:#0f172a;--surface:#1e293b;--surface2:#0b1220;--border:#334155;--text:#f1f5f9;--muted:#94a3b8;--pass:#22c55e;--warn:#f59e0b;--fail:#ef4444;--skip:#64748b;--accent:#38bdf8}
    @media (prefers-color-scheme:light){:root{--bg:#f8fafc;--surface:#ffffff;--surface2:#f1f5f9;--border:#e2e8f0;--text:#0f172a;--muted:#475569}}
    *{box-sizing:border-box}body{margin:0;font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}
    .wrap{max-width:1120px;margin:0 auto;padding:28px 20px 64px}
    .hero{display:flex;gap:28px;align-items:center;flex-wrap:wrap;background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;margin-bottom:20px}
    .ring{width:136px;height:136px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--accent) calc(var(--pct)*1%), var(--border) 0)}
    .ring-inner{width:108px;height:108px;border-radius:50%;background:var(--surface);display:flex;flex-direction:column;align-items:center;justify-content:center}
    .score-num{font-size:32px;font-weight:800;line-height:1}.score-den{font-size:12px;color:var(--muted)}.grade{margin-top:2px;font-weight:800;color:var(--accent);font-size:15px}
    .hero-meta{flex:1;min-width:260px}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
    h1{margin:6px 0 8px;font-size:24px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}h2{margin:0;font-size:17px}
    .lead{margin:0 0 12px;color:var(--muted)}.lead strong{color:var(--text)}
    .trust-note{font-size:12.5px;color:var(--muted);background:var(--surface2);border-left:3px solid var(--accent);padding:8px 12px;border-radius:6px}
    .gate-list{margin:12px 0 0;padding-left:18px;color:#fca5a5;font-size:13px}
    .badge{font-size:11px;font-weight:800;padding:4px 10px;border-radius:999px;letter-spacing:.05em}
    .badge-pass{background:rgba(34,197,94,.16);color:var(--pass);border:1px solid rgba(34,197,94,.4)}
    .badge-fail{background:rgba(239,68,68,.16);color:var(--fail);border:1px solid rgba(239,68,68,.4)}
    .banner{padding:12px 16px;border-radius:10px;margin-bottom:20px;border:1px solid var(--border);background:var(--surface)}
    .banner-fail{border-color:rgba(239,68,68,.5)}.banner-pass{border-color:rgba(34,197,94,.5)}
    .targets{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:20px}
    .target-card{text-align:left;cursor:pointer;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:12px;padding:14px;transition:border-color .15s,transform .15s}
    .target-card:hover,.target-card.active{border-color:var(--accent);transform:translateY(-1px)}
    .target-top{display:flex;justify-content:space-between;font-weight:700;margin-bottom:8px;gap:8px}
    .bar{height:8px;background:var(--surface2);border-radius:999px;overflow:hidden;margin-bottom:8px}.bar-fill{height:100%;border-radius:999px}
    .target-counts{display:flex;gap:10px;font-size:12px;color:var(--muted)}.c-pass{color:var(--pass)}.c-warn{color:var(--warn)}.c-fail{color:var(--fail)}
    .panel{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px;margin-bottom:18px}
    .toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}
    .filters{display:flex;gap:6px;flex-wrap:wrap}
    .chip{border:1px solid var(--border);background:var(--surface2);color:var(--text);padding:5px 11px;border-radius:999px;font-size:12px;font-weight:600;cursor:pointer}
    .chip.active{background:var(--accent);color:#0f172a;border-color:var(--accent)}
    .finding{border:1px solid var(--border);border-radius:10px;margin-bottom:10px;background:var(--surface2);overflow:hidden}
    .finding.status-fail{border-left:4px solid var(--fail)}.finding.status-warn{border-left:4px solid var(--warn)}.finding.status-pass{border-left:4px solid var(--pass)}.finding.status-skip{border-left:4px solid var(--skip);opacity:.78}
    .finding>summary{list-style:none;cursor:pointer;padding:12px 14px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
    .finding>summary::-webkit-details-marker{display:none}
    .finding-title{font-weight:700;flex:1;min-width:180px}.finding-target{font-size:12px;color:var(--muted)}.finding-id{font-size:11.5px;color:var(--muted);background:var(--surface);padding:2px 6px;border-radius:4px}
    .pill{font-size:11px;font-weight:800;padding:2px 8px;border-radius:6px;letter-spacing:.04em}
    .pill-fail{background:rgba(239,68,68,.2);color:var(--fail)}.pill-warn{background:rgba(245,158,11,.2);color:var(--warn)}.pill-pass{background:rgba(34,197,94,.2);color:var(--pass)}.pill-skip{background:rgba(100,116,139,.25);color:var(--muted)}.pill-sev{background:var(--surface);color:var(--muted);border:1px solid var(--border)}
    .finding-body{padding:0 14px 14px;border-top:1px solid var(--border)}
    .explain-box{margin-top:12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
    .explain-head{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px}
    .attacker-tag{font-size:11.5px;color:var(--accent);font-weight:700}.explain-box p{margin:4px 0 0}
    .tech-row{margin-top:10px;font-size:13px;color:var(--muted)}.tech-row strong{color:var(--text)}.weight{opacity:.8}
    .evidence{margin-top:10px;font-size:12.5px}.evidence ul{margin:6px 0 0;padding-left:18px}.evidence code{word-break:break-all}
    .fix-box{margin-top:10px;padding:9px 12px;border-radius:8px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.3);font-size:13px}
    .metrics-panel>summary{cursor:pointer;list-style:none}.metrics-table{width:100%;border-collapse:collapse;margin-top:12px;font-size:12.5px}
    .metrics-table th,.metrics-table td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border)}
    .hidden{display:none!important}
    """

    private const val DASHBOARD_JS: String = """
    (function(){
      var statusFilter = 'ALL';
      var targetFilter = 'ALL';
      function applyFilters() {
        document.querySelectorAll('.finding').forEach(function(el) {
          var okStatus = statusFilter === 'ALL' || el.dataset.status === statusFilter;
          var okTarget = targetFilter === 'ALL' || el.dataset.target === targetFilter;
          el.classList.toggle('hidden', !(okStatus && okTarget));
        });
      }
      document.querySelectorAll('[data-status-filter]').forEach(function(btn) {
        btn.addEventListener('click', function() {
          statusFilter = btn.dataset.statusFilter;
          document.querySelectorAll('[data-status-filter]').forEach(function(b){ b.classList.remove('active'); });
          btn.classList.add('active');
          applyFilters();
        });
      });
      document.querySelectorAll('[data-target-filter]').forEach(function(card) {
        card.addEventListener('click', function() {
          var clicked = card.dataset.targetFilter;
          targetFilter = (targetFilter === clicked) ? 'ALL' : clicked;
          document.querySelectorAll('[data-target-filter]').forEach(function(c){
            c.classList.toggle('active', c.dataset.targetFilter === targetFilter);
          });
          applyFilters();
        });
      });
    })();
    """
}
