#!/usr/bin/env bash
set -euo pipefail

echo "==> [1/4] Creando DashboardController con 1-Click Demo Login, Simulador de Webhooks y Consola de Mitigacion..."

cat << 'EOF' > src/app/Http/Controllers/DashboardController.php
<?php

namespace App\Http\Controllers;

use App\Enums\AbuseCategory;
use App\Enums\IncidentSeverity;
use App\Enums\IncidentStatus;
use App\Jobs\EnrichIncidentDnsJob;
use App\Jobs\EvaluateIncidentRiskJob;
use App\Models\AbuseReport;
use App\Models\Incident;
use App\Models\User;
use DomainException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\View\View;

class DashboardController extends Controller
{
    public function index(Request $request): View
    {
        $query = Incident::with(['enrichment', 'reports', 'mitigationActions.author', 'auditLogs', 'assignee'])
            ->latest('last_reported_at');

        if ($request->filled('category')) {
            $query->where('category', $request->string('category'));
        }

        if ($request->filled('status')) {
            $query->where('status', $request->string('status'));
        }

        if ($request->filled('severity')) {
            $query->where('severity', $request->string('severity'));
        }

        $incidents = $query->get();

        $allIncidents = Incident::all();
        $totalReports = AbuseReport::count();
        $openIncidents = $allIncidents->filter(fn (Incident $i) => $i->status->isOpen());

        $metrics = [
            'active_incidents' => $openIncidents->count(),
            'critical_threats' => $openIncidents->where('severity', IncidentSeverity::Critical)->count(),
            'total_reports' => $totalReports,
            'deduplicated_saves' => max(0, $totalReports - $allIncidents->count()),
            'avg_risk_score' => (int) round($openIncidents->avg('risk_score') ?? 0),
        ];

        return view('dashboard', [
            'incidents' => $incidents,
            'metrics' => $metrics,
            'categories' => AbuseCategory::cases(),
            'statuses' => IncidentStatus::cases(),
            'severities' => IncidentSeverity::cases(),
        ]);
    }

    public function demoLogin(): RedirectResponse
    {
        $analyst = User::where('email', 'demo@sentineldesk.local')->first();
        if ($analyst) {
            Auth::login($analyst);
        }

        return redirect()->route('dashboard')
            ->with('status', '1-Click Recruiter Demo active: Logged in as Claudio Leiva (Senior Abuse Desk Analyst).');
    }

    public function simulateWebhook(Request $request): RedirectResponse
    {
        $preset = $request->input('preset', 'phishing_campaign');

        $presets = [
            'phishing_campaign' => [
                'target_type' => 'domain',
                'target_value' => 'secure-login-update-bank.example.com',
                'category' => AbuseCategory::Phishing,
                'reporter_email' => 'soc-alert@cert-latam.example.org',
                'reporter_organization' => 'CERT Financial Threat Feed',
                'dmca' => false,
            ],
            'dmca_notice' => [
                'target_type' => 'url',
                'target_value' => 'https://cdn-stream-mirror.example.net/movies/4k-rip.mp4',
                'category' => AbuseCategory::Dmca,
                'reporter_email' => 'copyright@mpa-enforcement.example.com',
                'reporter_organization' => 'Motion Picture Anti-Piracy Alliance',
                'dmca' => true,
            ],
            'wp_malware' => [
                'target_type' => 'domain',
                'target_value' => 'wp-admin-shell-upload.example.org',
                'category' => AbuseCategory::Malware,
                'reporter_email' => 'honeypot@shadowserver.example.org',
                'reporter_organization' => 'Shadowserver Botnet Sensor',
                'dmca' => false,
            ],
            'ddos_botnet' => [
                'target_type' => 'ip',
                'target_value' => '198.51.100.214',
                'category' => AbuseCategory::Ddos,
                'reporter_email' => 'netops@cloudflare-radar.example.com',
                'reporter_organization' => 'Upstream DDoS Telemetry',
                'dmca' => false,
            ],
        ];

        $data = $presets[$preset] ?? $presets['phishing_campaign'];
        $idempotencyKey = 'sim-' . Str::lower(Str::random(10));
        $fingerprint = Incident::makeFingerprint($data['target_value'], $data['category']);
        $wasDeduplicated = false;

        $incident = DB::transaction(function () use ($data, $idempotencyKey, $fingerprint, $request, &$wasDeduplicated) {
            $openIncident = Incident::where('fingerprint', $fingerprint)
                ->whereNotIn('status', [IncidentStatus::Mitigated->value, IncidentStatus::Dismissed->value])
                ->lockForUpdate()
                ->first();

            if ($openIncident) {
                $wasDeduplicated = true;
                $openIncident->increment('reports_count');
                $openIncident->update(['last_reported_at' => now()]);
                $incident = $openIncident;
            } else {
                $nextNumber = (Incident::max('id') ?? 0) + 101;
                $incident = Incident::create([
                    'reference_code' => sprintf('SD-%s-%05d', now()->format('Y'), $nextNumber),
                    'fingerprint' => $fingerprint,
                    'target_type' => $data['target_type'],
                    'target_value' => $data['target_value'],
                    'category' => $data['category'],
                    'status' => IncidentStatus::Received,
                    'severity' => IncidentSeverity::Medium,
                    'risk_score' => 0,
                    'reports_count' => 1,
                    'assigned_to' => Auth::id() ?? User::first()?->id,
                    'sla_due_at' => now()->addHours($data['category']->defaultSlaHours()),
                    'first_reported_at' => now(),
                    'last_reported_at' => now(),
                ]);
            }

            $incident->reports()->create([
                'idempotency_key' => $idempotencyKey,
                'source_type' => 'webhook',
                'reporter_email' => $data['reporter_email'],
                'reporter_organization' => $data['reporter_organization'],
                'dmca_sworn_statement' => $data['dmca'],
                'evidence_urls' => [$data['target_value']],
                'raw_payload' => ['simulated_preset' => $data['category']->value, 'idempotency_key' => $idempotencyKey],
                'sender_ip' => $request->ip(),
            ]);

            $incident->auditLogs()->create([
                'actor_id' => Auth::id(),
                'event' => $wasDeduplicated ? 'duplicate_report_merged' : 'incident_ingested_via_webhook',
                'old_values' => [],
                'new_values' => [
                    'idempotency_key' => $idempotencyKey,
                    'reports_count' => $incident->reports_count,
                ],
                'ip_address' => $request->ip(),
            ]);

            return $incident;
        });

        // Ejecutamos los Jobs de inmediato en la demo para que el reclutador vea el resultado al instante
        EnrichIncidentDnsJob::dispatchSync($incident->id);
        EvaluateIncidentRiskJob::dispatchSync($incident->id);

        $incident->refresh();

        $msg = $wasDeduplicated
            ? "SHA-256 Fingerprint Match! Report merged into {$incident->reference_code} (Reports: {$incident->reports_count}, Risk Score: {$incident->risk_score}/100)."
            : "New Incident {$incident->reference_code} created & enriched via DNS/Heuristic Pipeline (Risk Score: {$incident->risk_score}/100).";

        return redirect()->route('dashboard')->with('status', $msg);
    }

    public function mitigate(Request $request, Incident $incident): RedirectResponse
    {
        $validated = $request->validate([
            'next_status' => ['required', 'string'],
            'action_type' => ['required', 'string', 'max:40'],
            'notes' => ['required', 'string', 'max:500'],
        ]);

        $nextStatus = IncidentStatus::from($validated['next_status']);

        try {
            $incident->transitionStatusTo(
                $nextStatus,
                Auth::id() ?? User::first()?->id,
                $request->ip()
            );

            $incident->mitigationActions()->create([
                'user_id' => Auth::id() ?? User::first()?->id,
                'action_type' => $validated['action_type'],
                'notes' => $validated['notes'],
                'executed_at' => now(),
            ]);

            return redirect()->route('dashboard')
                ->with('status', "Incident {$incident->reference_code} transitioned to [{$nextStatus->label()}] and recorded in immutable audit trail.");
        } catch (DomainException $e) {
            return redirect()->route('dashboard')
                ->with('error', "State Machine Guardrail: " . $e->getMessage());
        }
    }

    public function resetDemo(): RedirectResponse
    {
        Artisan::call('migrate:fresh', ['--seed' => true, '--force' => true]);

        return redirect()->route('dashboard')
            ->with('status', 'Demo database reset to initial state with 3 baseline Abuse Desk incidents.');
    }
}
EOF

echo "==> [2/4] Creando la vista interactiva SOC / Abuse Desk en src/resources/views/dashboard.blade.php..."
mkdir -p src/resources/views

cat << 'EOF' > src/resources/views/dashboard.blade.php
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelDesk — Abuse Desk & Threat Triage Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen font-sans antialiased">

    <!-- Top Navigation Bar -->
    <header class="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-30">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-wrap items-center justify-between gap-4">
            <div class="flex items-center gap-3">
                <div class="h-9 w-9 rounded-lg bg-indigo-600 flex items-center justify-center font-bold text-white shadow-lg shadow-indigo-600/30">
                    SD
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <span class="font-bold text-lg tracking-tight text-white">SentinelDesk</span>
                        <span class="text-xs px-2 py-0.5 rounded-full bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 font-medium">
                            Abuse Desk &amp; Threat Triage SaaS
                        </span>
                    </div>
                    <p class="text-xs text-slate-400">
                        Laravel 11 &middot; PostgreSQL 16 (JSONB) &middot; Redis / Horizon Async Pipeline &middot; SHA-256 Deduplication
                    </p>
                </div>
            </div>

            <div class="flex items-center gap-2.5">
                @auth
                    <span class="text-xs bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 px-3 py-1.5 rounded-lg flex items-center gap-1.5">
                        <span class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
                        {{ auth()->user()->name }}
                    </span>
                @else
                    <form method="POST" action="{{ route('demo.login') }}">
                        @csrf
                        <button type="submit" class="text-xs bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-3.5 py-2 rounded-lg shadow transition">
                            ⚡ 1-Click Recruiter Demo Login
                        </button>
                    </form>
                @endauth

                <a href="/api/v1/incidents" target="_blank" class="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-2 rounded-lg transition">
                    { } Raw JSON API
                </a>

                <form method="POST" action="{{ route('demo.reset') }}" onsubmit="return confirm('Reset database to initial demo state?');">
                    @csrf
                    <button type="submit" class="text-xs bg-slate-800 hover:bg-rose-950/60 hover:text-rose-300 hover:border-rose-800 text-slate-400 border border-slate-700 px-3 py-2 rounded-lg transition">
                        ↺ Reset Demo
                    </button>
                </form>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">

        <!-- Flash Notifications -->
        @if (session('status'))
            <div class="bg-indigo-950/70 border border-indigo-500/40 text-indigo-200 px-4 py-3 rounded-xl text-sm flex items-center justify-between">
                <span><strong>Pipeline Event:</strong> {{ session('status') }}</span>
            </div>
        @endif

        @if (session('error'))
            <div class="bg-rose-950/80 border border-rose-500/50 text-rose-200 px-4 py-3 rounded-xl text-sm">
                <strong>Error:</strong> {{ session('error') }}
            </div>
        @endif

        <!-- KPI Metrics Row -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Active Queue</p>
                <p class="text-2xl font-bold text-white mt-1">{{ $metrics['active_incidents'] }}</p>
                <p class="text-xs text-slate-500 mt-1">Open incidents requiring action</p>
            </div>
            <div class="bg-slate-900 border border-rose-900/50 rounded-xl p-4">
                <p class="text-xs uppercase tracking-wider text-rose-400 font-semibold">Critical Severity</p>
                <p class="text-2xl font-bold text-rose-400 mt-1">{{ $metrics['critical_threats'] }}</p>
                <p class="text-xs text-slate-500 mt-1">Risk score &ge; 80 / 100</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Ingested Reports</p>
                <p class="text-2xl font-bold text-white mt-1">{{ $metrics['total_reports'] }}</p>
                <p class="text-xs text-slate-500 mt-1">Idempotent webhook payloads</p>
            </div>
            <div class="bg-slate-900 border border-emerald-900/50 rounded-xl p-4">
                <p class="text-xs uppercase tracking-wider text-emerald-400 font-semibold">Deduplicated Saves</p>
                <p class="text-2xl font-bold text-emerald-400 mt-1">{{ $metrics['deduplicated_saves'] }}</p>
                <p class="text-xs text-slate-500 mt-1">Merged via SHA-256 fingerprint</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-xs uppercase tracking-wider text-indigo-400 font-semibold">Avg Threat Score</p>
                <p class="text-2xl font-bold text-indigo-300 mt-1">{{ $metrics['avg_risk_score'] }} <span class="text-sm font-normal text-slate-500">/ 100</span></p>
                <p class="text-xs text-slate-500 mt-1">Heuristic + DNS enrichment</p>
            </div>
        </div>

        <!-- Live Webhook Simulator Bar & Filters -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
            <div>
                <h2 class="text-sm font-semibold text-white flex items-center gap-2">
                    <span>⚡ Live Abuse Webhook &amp; Deduplication Simulator</span>
                </h2>
                <p class="text-xs text-slate-400 mt-0.5">
                    Click any attack vector twice to see automatic <strong>SHA-256 fingerprint deduplication</strong> and real-time risk score escalation.
                </p>
            </div>

            <div class="flex flex-wrap items-center gap-2">
                <form method="POST" action="{{ route('demo.simulate') }}">
                    @csrf
                    <input type="hidden" name="preset" value="phishing_campaign">
                    <button type="submit" class="text-xs bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30 px-3 py-2 rounded-lg font-medium transition">
                        + Simulate Phishing Report
                    </button>
                </form>

                <form method="POST" action="{{ route('demo.simulate') }}">
                    @csrf
                    <input type="hidden" name="preset" value="wp_malware">
                    <button type="submit" class="text-xs bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/30 px-3 py-2 rounded-lg font-medium transition">
                        + Simulate WP Malware Shell
                    </button>
                </form>

                <form method="POST" action="{{ route('demo.simulate') }}">
                    @csrf
                    <input type="hidden" name="preset" value="dmca_notice">
                    <button type="submit" class="text-xs bg-sky-600/20 hover:bg-sky-600/30 text-sky-300 border border-sky-500/30 px-3 py-2 rounded-lg font-medium transition">
                        + Simulate Sworn DMCA Notice
                    </button>
                </form>

                <form method="POST" action="{{ route('demo.simulate') }}">
                    @csrf
                    <input type="hidden" name="preset" value="ddos_botnet">
                    <button type="submit" class="text-xs bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/30 px-3 py-2 rounded-lg font-medium transition">
                        + Simulate DDoS Telemetry
                    </button>
                </form>
            </div>
        </div>

        <!-- Incidents Table + Expandable Forensic Inspector -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div class="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
                <div>
                    <h3 class="text-base font-bold text-white">Abuse &amp; Security Incident Queue</h3>
                    <p class="text-xs text-slate-400">Click "Inspect &amp; Mitigate" on any incident to view DNS telemetry, merged reports, and the state machine audit trail.</p>
                </div>

                <form method="GET" action="{{ route('dashboard') }}" class="flex flex-wrap items-center gap-2">
                    <select name="category" onchange="this.form.submit()" class="bg-slate-950 border border-slate-700 text-xs text-slate-200 rounded-lg px-2.5 py-1.5">
                        <option value="">All Categories</option>
                        @foreach ($categories as $cat)
                            <option value="{{ $cat->value }}" @selected(request('category') === $cat->value)>{{ $cat->label() }}</option>
                        @endforeach
                    </select>

                    <select name="severity" onchange="this.form.submit()" class="bg-slate-950 border border-slate-700 text-xs text-slate-200 rounded-lg px-2.5 py-1.5">
                        <option value="">All Severities</option>
                        @foreach ($severities as $sev)
                            <option value="{{ $sev->value }}" @selected(request('severity') === $sev->value)>{{ ucfirst($sev->value) }}</option>
                        @endforeach
                    </select>

                    @if (request()->hasAny(['category', 'severity', 'status']))
                        <a href="{{ route('dashboard') }}" class="text-xs text-indigo-400 hover:underline px-2">Clear</a>
                    @endif
                </form>
            </div>

            <div class="divide-y divide-slate-800">
                @foreach ($incidents as $incident)
                    <div x-data="{ open: {{ $loop->first ? 'true' : 'false' }} }" class="p-5 hover:bg-slate-900/60 transition">
                        <!-- Summary Row -->
                        <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                            <div class="space-y-1">
                                <div class="flex flex-wrap items-center gap-2.5">
                                    <span class="font-mono text-xs font-bold px-2.5 py-1 rounded bg-slate-800 text-indigo-300 border border-slate-700">
                                        {{ $incident->reference_code }}
                                    </span>

                                    @php
                                        $sevColors = [
                                            'critical' => 'bg-rose-500/15 text-rose-300 border-rose-500/30',
                                            'high' => 'bg-amber-500/15 text-amber-300 border-amber-500/30',
                                            'medium' => 'bg-sky-500/15 text-sky-300 border-sky-500/30',
                                            'low' => 'bg-slate-500/15 text-slate-300 border-slate-500/30',
                                        ][$incident->severity->value] ?? 'bg-slate-800 text-slate-300';
                                    @endphp
                                    <span class="text-xs font-semibold uppercase px-2.5 py-0.5 rounded-full border {{ $sevColors }}">
                                        {{ $incident->severity->value }} ({{ $incident->risk_score }}/100)
                                    </span>

                                    <span class="text-xs font-medium px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-200 border border-slate-700">
                                        {{ $incident->category->label() }}
                                    </span>

                                    <span class="text-xs px-2.5 py-0.5 rounded-full bg-indigo-950 text-indigo-300 border border-indigo-700/50">
                                        Status: {{ $incident->status->label() }}
                                    </span>

                                    <span class="text-xs px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-700/40 font-mono">
                                        {{ $incident->reports_count }} {{ Str::plural('report', $incident->reports_count) }}
                                    </span>
                                </div>

                                <div class="pt-1 flex flex-wrap items-center gap-3 text-sm">
                                    <span class="text-slate-400 text-xs uppercase font-mono">[{{ $incident->target_type }}]</span>
                                    <span class="font-mono font-semibold text-white break-all">{{ $incident->target_value }}</span>
                                </div>
                            </div>

                            <div class="flex items-center gap-3 self-start lg:self-center">
                                <div class="text-right hidden sm:block">
                                    <p class="text-xs text-slate-400">SLA Due: <span class="text-slate-200">{{ $incident->sla_due_at?->diffForHumans() ?? 'N/A' }}</span></p>
                                    <p class="text-xs text-slate-500">Fingerprint: <span class="font-mono">{{ substr($incident->fingerprint, 0, 12) }}...</span></p>
                                </div>

                                <button @click="open = !open" class="text-xs bg-slate-800 hover:bg-indigo-600 text-slate-200 hover:text-white border border-slate-700 px-3.5 py-2 rounded-lg font-medium transition">
                                    <span x-text="open ? 'Hide Telemetry ▲' : 'Inspect & Mitigate ▼'"></span>
                                </button>
                            </div>
                        </div>

                        <!-- Expandable Forensic & Mitigation Drawer -->
                        <div x-show="open" x-transition class="mt-5 pt-5 border-t border-slate-800/80 grid grid-cols-1 lg:grid-cols-3 gap-5">

                            <!-- Col 1: DNS & Heuristic Threat Enrichment -->
                            <div class="bg-slate-950/90 border border-slate-800 rounded-xl p-4 space-y-3">
                                <h4 class="text-xs font-bold uppercase tracking-wider text-indigo-400">
                                    1. Async Threat Enrichment (Horizon Job)
                                </h4>

                                @if ($incident->enrichment)
                                    <div class="text-xs space-y-2">
                                        <div>
                                            <span class="text-slate-400">Hosting / ASN:</span>
                                            <p class="font-mono text-slate-200">{{ $incident->enrichment->asn_name }} ({{ $incident->enrichment->hosting_provider }})</p>
                                        </div>
                                        <div>
                                            <span class="text-slate-400">Resolved IPs &amp; DNS:</span>
                                            <pre class="mt-1 p-2 rounded bg-slate-900 text-emerald-300 font-mono text-[11px] overflow-x-auto">{{ json_encode($incident->enrichment->dns_records, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</pre>
                                        </div>
                                        <div>
                                            <span class="text-slate-400">Heuristic Risk Breakdown ({{ $incident->risk_score }}/100):</span>
                                            <ul class="mt-1 space-y-1 list-disc list-inside text-slate-300">
                                                @foreach ($incident->enrichment->risk_factors ?? [] as $factor)
                                                    <li>{{ $factor }}</li>
                                                @endforeach
                                            </ul>
                                        </div>
                                    </div>
                                @else
                                    <p class="text-xs text-slate-500 italic">Pending enrichment queue worker...</p>
                                @endif
                            </div>

                            <!-- Col 2: State Machine & Mitigation Console -->
                            <div class="bg-slate-950/90 border border-slate-800 rounded-xl p-4 space-y-3">
                                <h4 class="text-xs font-bold uppercase tracking-wider text-emerald-400">
                                    2. State Machine &amp; Mitigation Action
                                </h4>

                                @if ($incident->status->isOpen())
                                    <form method="POST" action="{{ route('incidents.mitigate', $incident) }}" class="space-y-3 text-xs">
                                        @csrf
                                        <div>
                                            <label class="block text-slate-400 mb-1">Transition Incident Status:</label>
                                            <select name="next_status" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-100">
                                                @foreach ($statuses as $st)
                                                    @if ($incident->status->canTransitionTo($st))
                                                        <option value="{{ $st->value }}">
                                                            {{ $incident->status->label() }} &rarr; {{ $st->label() }}
                                                        </option>
                                                    @endif
                                                @endforeach
                                            </select>
                                        </div>

                                        <div>
                                            <label class="block text-slate-400 mb-1">Abuse Desk Action Type:</label>
                                            <select name="action_type" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-100">
                                                <option value="notify_customer">Notify Customer (24h AUP/DMCA Warning)</option>
                                                <option value="suspend_url">Suspend Malicious VirtualHost / URL</option>
                                                <option value="null_route_ip">Null-Route IP / Block Outbound SMTP</option>
                                                <option value="escalate_legal">Escalate to Legal / Abuse Desk Manager</option>
                                                <option value="false_positive">Close as False Positive</option>
                                            </select>
                                        </div>

                                        <div>
                                            <label class="block text-slate-400 mb-1">Forensic Resolution Notes:</label>
                                            <textarea name="notes" rows="2" required placeholder="e.g. Verified phishing kit in /wp-content/uploads/, suspended domain and notified account owner..." class="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-100"></textarea>
                                        </div>

                                        <button type="submit" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2 rounded-lg shadow transition">
                                            Execute Mitigation &amp; Log Audit Event
                                        </button>
                                    </form>
                                @else
                                    <div class="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
                                        This incident is closed (<strong>{{ $incident->status->label() }}</strong>) at {{ $incident->resolved_at?->format('Y-m-d H:i:s') }}.
                                        State machine locks further transitions.
                                    </div>
                                @endif

                                @if ($incident->mitigationActions->isNotEmpty())
                                    <div class="pt-2 border-t border-slate-800 text-xs space-y-1.5">
                                        <span class="text-slate-400 font-semibold">Executed Mitigations:</span>
                                        @foreach ($incident->mitigationActions as $act)
                                            <div class="p-2 rounded bg-slate-900 border border-slate-800">
                                                <span class="font-mono text-indigo-300">[{{ $act->action_type }}]</span>
                                                <p class="text-slate-300 mt-0.5">{{ $act->notes }}</p>
                                            </div>
                                        @endforeach
                                    </div>
                                @endif
                            </div>

                            <!-- Col 3: Deduplicated Reports & Immutable Audit Log -->
                            <div class="bg-slate-950/90 border border-slate-800 rounded-xl p-4 space-y-3">
                                <h4 class="text-xs font-bold uppercase tracking-wider text-amber-400">
                                    3. Merged Reports ({{ $incident->reports->count() }}) &amp; Audit Trail
                                </h4>

                                <div class="text-xs space-y-1.5 max-h-32 overflow-y-auto pr-1">
                                    @foreach ($incident->reports as $rep)
                                        <div class="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                                            <div>
                                                <p class="font-semibold text-slate-200">{{ $rep->reporter_organization ?? $rep->reporter_email }}</p>
                                                <p class="text-[11px] text-slate-400 font-mono">Key: {{ $rep->idempotency_key }}</p>
                                            </div>
                                            @if ($rep->dmca_sworn_statement)
                                                <span class="text-[10px] px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">Sworn DMCA</span>
                                            @endif
                                        </div>
                                    @endforeach
                                </div>

                                <div class="pt-2 border-t border-slate-800 text-xs">
                                    <span class="text-slate-400 font-semibold">Immutable Audit Trail:</span>
                                    <div class="mt-1.5 space-y-1.5 max-h-36 overflow-y-auto pr-1">
                                        @foreach ($incident->auditLogs as $log)
                                            <div class="text-[11px] font-mono p-1.5 rounded bg-slate-900/80 text-slate-300">
                                                <span class="text-indigo-400">{{ $log->created_at?->format('H:i:s') }}</span>
                                                <strong class="text-white">{{ $log->event }}</strong>
                                                <span class="text-slate-400">{{ json_encode($log->new_values) }}</span>
                                            </div>
                                        @endforeach
                                    </div>
                                </div>
                            </div>

                        </div>
                    </div>
                @endforeach
            </div>
        </div>
    </main>
</body>
</html>
EOF

echo "==> [3/4] Registrando rutas en src/routes/web.php..."
cat << 'EOF' > src/routes/web.php
<?php

use App\Http\Controllers\DashboardController;
use Illuminate\Support\Facades\Route;

Route::get('/', [DashboardController::class, 'index'])->name('dashboard');
Route::post('/demo/login', [DashboardController::class, 'demoLogin'])->name('demo.login');
Route::post('/demo/simulate', [DashboardController::class, 'simulateWebhook'])->name('demo.simulate');
Route::post('/demo/reset', [DashboardController::class, 'resetDemo'])->name('demo.reset');
Route::post('/incidents/{incident}/mitigate', [DashboardController::class, 'mitigate'])->name('incidents.mitigate');
EOF

echo "==> [4/4] Limpiando caches de rutas y vistas en el contenedor..."
docker compose exec app php artisan optimize:clear
sudo chown -R "$USER":82 src
chmod -R 775 src/storage src/bootstrap/cache

echo "✅ ¡Dashboard de SentinelDesk instalado! Abre http://localhost:8080 en tu navegador."
