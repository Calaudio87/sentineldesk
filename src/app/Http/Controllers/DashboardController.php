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
