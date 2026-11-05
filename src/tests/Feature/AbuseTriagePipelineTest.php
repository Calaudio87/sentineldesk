<?php

namespace Tests\Feature;

use App\Enums\AbuseCategory;
use App\Enums\IncidentSeverity;
use App\Enums\IncidentStatus;
use App\Jobs\EnrichIncidentDnsJob;
use App\Jobs\EvaluateIncidentRiskJob;
use App\Models\Incident;
use DomainException;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class AbuseTriagePipelineTest extends TestCase
{
    use DatabaseTransactions;

    public function test_it_ingests_new_abuse_report_and_queues_enrichment_pipeline(): void
    {
        Queue::fake();

        $payload = [
            'idempotency_key' => 'test-key-ingest-001',
            'target_type' => 'domain',
            'target_value' => 'secure-auth-wallet-verify.example.com',
            'category' => 'phishing',
            'reporter_email' => 'soc@netcraft.example.org',
            'reporter_organization' => 'Netcraft SOC',
        ];

        $response = $this->postJson('/api/v1/abuse/ingest', $payload);

        $response->assertStatus(202)
            ->assertJson([
                'idempotent_replay' => false,
                'deduplicated_into_existing_incident' => false,
                'reports_count' => 1,
                'status' => 'received',
            ]);

        $this->assertDatabaseHas('incidents', [
            'target_value' => 'secure-auth-wallet-verify.example.com',
            'category' => 'phishing',
            'reports_count' => 1,
        ]);

        Queue::assertPushedWithChain(EnrichIncidentDnsJob::class, [
            EvaluateIncidentRiskJob::class,
        ]);
    }

    public function test_it_enforces_strict_idempotency_on_duplicate_webhook_replays(): void
    {
        Queue::fake();

        $payload = [
            'idempotency_key' => 'replay-key-999',
            'target_type' => 'url',
            'target_value' => 'https://pirate-cdn.example.net/movie.mp4',
            'category' => 'dmca',
            'reporter_email' => 'dmca@mpa.example.org',
            'dmca_sworn_statement' => true,
        ];

        $first = $this->postJson('/api/v1/abuse/ingest', $payload);
        $first->assertStatus(202);

        $replay = $this->postJson('/api/v1/abuse/ingest', $payload);
        $replay->assertStatus(200)
            ->assertJson([
                'idempotent_replay' => true,
                'incident_reference' => $first->json('incident_reference'),
            ]);
    }

    public function test_it_deduplicates_multiple_reports_for_same_target_via_sha256_fingerprint(): void
    {
        Queue::fake();

        $first = $this->postJson('/api/v1/abuse/ingest', [
            'idempotency_key' => 'dedup-key-1',
            'target_type' => 'domain',
            'target_value' => 'wp-shell-compromised.example.org',
            'category' => 'malware',
            'reporter_email' => 'sensor1@shadowserver.example.org',
        ]);

        $second = $this->postJson('/api/v1/abuse/ingest', [
            'idempotency_key' => 'dedup-key-2',
            'target_type' => 'domain',
            'target_value' => 'WP-SHELL-COMPROMISED.EXAMPLE.ORG ',
            'category' => 'malware',
            'reporter_email' => 'sensor2@abusech.example.org',
        ]);

        $second->assertStatus(202)
            ->assertJson([
                'deduplicated_into_existing_incident' => true,
                'incident_reference' => $first->json('incident_reference'),
                'reports_count' => 2,
            ]);
    }

    public function test_async_jobs_enrich_dns_and_calculate_critical_heuristic_risk_score(): void
    {
        $incident = Incident::create([
            'reference_code' => 'SD-2026-99901',
            'fingerprint' => Incident::makeFingerprint('login-secure-bank.example.com', AbuseCategory::Phishing),
            'target_type' => 'domain',
            'target_value' => 'login-secure-bank.example.com',
            'category' => AbuseCategory::Phishing,
            'status' => IncidentStatus::Received,
            'severity' => IncidentSeverity::Medium,
            'risk_score' => 0,
            'reports_count' => 2,
            'sla_due_at' => now()->addHours(4),
            'first_reported_at' => now(),
            'last_reported_at' => now(),
        ]);

        (new EnrichIncidentDnsJob($incident->id))->handle();
        (new EvaluateIncidentRiskJob($incident->id))->handle();

        $incident->refresh();

        $this->assertSame(IncidentStatus::Triaged, $incident->status);
        $this->assertSame(IncidentSeverity::Critical, $incident->severity);
        $this->assertGreaterThanOrEqual(80, $incident->risk_score);
        $this->assertNotNull($incident->enrichment);
        $this->assertNotEmpty($incident->enrichment->resolved_ips);
    }

    public function test_state_machine_blocks_invalid_transitions_and_records_immutable_audit_trail(): void
    {
        $incident = Incident::create([
            'reference_code' => 'SD-2026-99902',
            'fingerprint' => Incident::makeFingerprint('spam-relay.example.net', AbuseCategory::Spam),
            'target_type' => 'domain',
            'target_value' => 'spam-relay.example.net',
            'category' => AbuseCategory::Spam,
            'status' => IncidentStatus::Triaged,
            'severity' => IncidentSeverity::Medium,
            'risk_score' => 45,
            'reports_count' => 1,
            'sla_due_at' => now()->addHours(12),
            'first_reported_at' => now(),
            'last_reported_at' => now(),
        ]);

        $incident->transitionStatusTo(IncidentStatus::Mitigated, null, '127.0.0.1');
        $this->assertSame(IncidentStatus::Mitigated, $incident->fresh()->status);
        $this->assertNotNull($incident->fresh()->resolved_at);

        $this->assertDatabaseHas('incident_audit_logs', [
            'incident_id' => $incident->id,
            'event' => 'status_transitioned',
        ]);

        $this->expectException(DomainException::class);
        $incident->transitionStatusTo(IncidentStatus::Investigating);
    }
}
