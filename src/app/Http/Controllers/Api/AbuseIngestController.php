<?php

namespace App\Http\Controllers\Api;

use App\Enums\AbuseCategory;
use App\Enums\IncidentSeverity;
use App\Enums\IncidentStatus;
use App\Http\Controllers\Controller;
use App\Jobs\EnrichIncidentDnsJob;
use App\Jobs\EvaluateIncidentRiskJob;
use App\Models\AbuseReport;
use App\Models\Incident;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

class AbuseIngestController extends Controller
{
    public function store(Request $request): JsonResponse
    {
        // 1. Validación opcional de firma HMAC (si se envía cabecera X-Sentinel-Signature)
        $webhookSecret = env('SENTINEL_WEBHOOK_SECRET');
        if ($webhookSecret && $request->hasHeader('X-Sentinel-Signature')) {
            $expected = hash_hmac('sha256', $request->getContent(), $webhookSecret);
            if (! hash_equals($expected, (string) $request->header('X-Sentinel-Signature'))) {
                return response()->json(['error' => 'Invalid HMAC webhook signature.'], 401);
            }
        }

        $validated = $request->validate([
            'idempotency_key' => ['required', 'string', 'max:64'],
            'target_type' => ['required', Rule::in(['domain', 'ip', 'url'])],
            'target_value' => ['required', 'string', 'max:255'],
            'category' => ['required', Rule::enum(AbuseCategory::class)],
            'reporter_email' => ['required', 'email', 'max:150'],
            'reporter_organization' => ['nullable', 'string', 'max:150'],
            'source_type' => ['nullable', Rule::in(['api', 'webhook', 'web_form'])],
            'dmca_sworn_statement' => ['nullable', 'boolean'],
            'evidence_urls' => ['nullable', 'array'],
        ]);

        // 2. Verificación de Idempotencia estricta (evita reprocesar reintentos de red)
        $existingReport = AbuseReport::with('incident')
            ->where('idempotency_key', $validated['idempotency_key'])
            ->first();

        if ($existingReport) {
            return response()->json([
                'message' => 'Idempotent replay detected. Returning existing report.',
                'idempotent_replay' => true,
                'deduplicated_into_existing_incident' => false,
                'incident_reference' => $existingReport->incident->reference_code,
                'report_id' => $existingReport->id,
                'status' => $existingReport->incident->status->value,
                'risk_score' => $existingReport->incident->risk_score,
            ], 200);
        }

        $category = AbuseCategory::from($validated['category']);
        $fingerprint = Incident::makeFingerprint($validated['target_value'], $category);
        $wasDeduplicated = false;

        // 3. Transacción atómica con deduplicación por huella (fingerprint)
        $incident = DB::transaction(function () use ($validated, $category, $fingerprint, $request, &$wasDeduplicated) {
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
                    'target_type' => $validated['target_type'],
                    'target_value' => strtolower(trim($validated['target_value'])),
                    'category' => $category,
                    'status' => IncidentStatus::Received,
                    'severity' => IncidentSeverity::Medium,
                    'risk_score' => 0,
                    'reports_count' => 1,
                    'sla_due_at' => now()->addHours($category->defaultSlaHours()),
                    'first_reported_at' => now(),
                    'last_reported_at' => now(),
                ]);
            }

            $incident->reports()->create([
                'idempotency_key' => $validated['idempotency_key'],
                'source_type' => $validated['source_type'] ?? 'api',
                'reporter_email' => $validated['reporter_email'],
                'reporter_organization' => $validated['reporter_organization'] ?? null,
                'dmca_sworn_statement' => (bool) ($validated['dmca_sworn_statement'] ?? false),
                'evidence_urls' => $validated['evidence_urls'] ?? [$validated['target_value']],
                'raw_payload' => $request->all(),
                'sender_ip' => $request->ip(),
            ]);

            $incident->auditLogs()->create([
                'event' => $wasDeduplicated ? 'duplicate_report_merged' : 'incident_ingested',
                'old_values' => [],
                'new_values' => [
                    'idempotency_key' => $validated['idempotency_key'],
                    'reports_count' => $incident->reports_count,
                ],
                'ip_address' => $request->ip(),
            ]);

            return $incident;
        });

        // 4. Despachar el pipeline asíncrono de enriquecimiento y cálculo de riesgo
        Bus::chain([
            new EnrichIncidentDnsJob($incident->id),
            new EvaluateIncidentRiskJob($incident->id),
        ])->dispatch();

        return response()->json([
            'message' => $wasDeduplicated
                ? 'Abuse report merged into active incident and queued for risk recalculation.'
                : 'New incident created and queued for asynchronous threat enrichment.',
            'idempotent_replay' => false,
            'deduplicated_into_existing_incident' => $wasDeduplicated,
            'incident_reference' => $incident->reference_code,
            'reports_count' => $incident->reports_count,
            'status' => $incident->status->value,
        ], 202);
    }
}
