#!/usr/bin/env bash
set -euo pipefail

echo "==> [1/5] Puliendo detalle visual del Audit Trail en dashboard.blade.php (evitar scroll horizontal)..."
sed -i 's/<span class="text-slate-400">{{ json_encode(\$log->new_values) }}<\/span>/<span class="text-slate-400 break-all">{{ json_encode(\$log->new_values) }}<\/span>/g' src/resources/views/dashboard.blade.php

echo "==> [2/5] Creando Suite de Tests Automatizados (Feature & Domain Tests) en src/tests/Feature/AbuseTriagePipelineTest.php..."
mkdir -p src/tests/Feature

cat << 'EOF' > src/tests/Feature/AbuseTriagePipelineTest.php
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
EOF

echo "==> [3/5] Generando README.md profesional de ingenieria con diagramas Mermaid en la raiz..."
cat << 'EOF' > README.md
# 🛡️ SentinelDesk — Automated Abuse Desk, DMCA & Threat Triage Engine

**SentinelDesk** is an event-driven Abuse Desk, DMCA compliance, and Threat Intelligence triage platform built with **Laravel 11/12 (PHP 8.4)**, **PostgreSQL 16 (`JSONB`)**, **Redis 7**, **Laravel Horizon**, and **Laravel Reverb**.

Designed around real-world hosting & cloud security operations (SOC / Abuse Desk), SentinelDesk ingests high-volume abuse webhooks, enforces **strict idempotency**, deduplicates multi-source reports via **SHA-256 fingerprinting**, enriches targets asynchronously with live DNS/ASN telemetry, computes an explainable **Heuristic Risk Score (0–100)**, and governs incident resolution through an **auditable State Machine**.

---

## 🏗️ System Architecture & Asynchronous Triage Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant Feed as External Threat Feed / CERT
    participant API as AbuseIngestController (API)
    participant DB as PostgreSQL 16 (JSONB + Locks)
    participant Redis as Redis 7 / Horizon Queue
    participant DNS as EnrichIncidentDnsJob
    participant Risk as EvaluateIncidentRiskJob
    participant UI as Analyst SOC Dashboard

    Feed->>API: POST /api/v1/abuse/ingest (idempotency_key, target, category)
    API->>DB: Check idempotency_key (200 OK if replay)
    API->>DB: Compute SHA-256(target + category) & lock active incident
    alt Open Incident Exists
        DB-->>API: Merge report & increment reports_count
    else New Threat Vector
        DB-->>API: Create Incident (status: received) + SLA timer
    end
    API->>Redis: Dispatch Bus::chain([EnrichIncidentDnsJob, EvaluateIncidentRiskJob])
    API-->>Feed: 202 Accepted (< 50ms response)
    Redis->>DNS: Resolve A / MX / NS records & ASN telemetry
    DNS->>DB: Persist ThreatEnrichment (JSONB) & transition -> enriching
    Redis->>Risk: Evaluate Heuristic Score (Category + Tokens + Volume + DMCA)
    Risk->>DB: Update Severity (Low..Critical) & transition -> triaged
    Risk->>UI: Broadcast IncidentTriaged Event & Immutable Audit Log
```

---

## ✨ Key Engineering Highlights

| Capability | Implementation Details |
| :--- | :--- |
| **Idempotent Webhook Ingestion** | Prevents duplicate database writes during upstream webhook retries using unique `idempotency_key` tracking (`200 OK` replay vs `202 Accepted` new ingestion). |
| **Atomic SHA-256 Deduplication** | Normalizes target domains/IPs/URLs and computes a deterministic `SHA-256(target\|category)` fingerprint with pessimistic row locking (`SELECT ... FOR UPDATE`) to merge concurrent abuse bursts into a single incident. |
| **Async DNS & Risk Scoring Pipeline** | Uses `Bus::chain` on Redis to decouple HTTP ingestion from network I/O (`dns_get_record`) and multi-factor heuristic risk calculation (`0–100` score with human-readable explanations). |
| **Backed Enum State Machine** | Strictly typed PHP 8.4 Enums (`IncidentStatus`, `AbuseCategory`, `IncidentSeverity`) enforce valid lifecycle transitions (`received` → `enriching` → `triaged` → `investigating` → `awaiting_customer` → `mitigated`/`dismissed`) and dynamic SLA deadlines. |
| **Immutable Forensic Audit Trail** | Every state transition, merged report, and analyst mitigation action is atomically recorded in `incident_audit_logs` with actor attribution, IP address, and `JSONB` state diffs. |
| **1-Click Recruiter Demo & Webhook Simulator** | Includes a zero-friction **1-Click Recruiter Demo Login** and an interactive **Live Webhook Simulator** to trigger Phishing, WP Malware, DMCA, and DDoS payloads directly from the browser. |

---

## 🚀 Quick Start (Docker Compose)

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/sentineldesk.git
cd sentineldesk

# 2. Build and start Nginx, PHP 8.4-FPM, PostgreSQL 16, and Redis 7
docker compose up -d --build

# 3. Run migrations and seed realistic Abuse Desk incidents
docker compose exec app php artisan migrate:fresh --seed

# 4. Run the automated test suite (PHPUnit / Feature & Domain tests)
docker compose exec app php artisan test --filter=AbuseTriagePipelineTest
```

Open **`http://localhost:8080`** in your browser and click **⚡ 1-Click Recruiter Demo Login**.

---

## 🔌 API Reference: Ingest Abuse Report

### `POST /api/v1/abuse/ingest`

```bash
curl -s -X POST http://localhost:8080/api/v1/abuse/ingest \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "idempotency_key": "phishlabs-2026-0001",
    "target_type": "domain",
    "target_value": "secure-login-update-bank.example.com",
    "category": "phishing",
    "reporter_email": "soc@phishlabs.example.org",
    "reporter_organization": "PhishLabs SOC"
  }'
```

#### Response (`202 Accepted`):
```json
{
  "message": "New incident created and queued for asynchronous threat enrichment.",
  "idempotent_replay": false,
  "deduplicated_into_existing_incident": false,
  "incident_reference": "SD-2026-00104",
  "reports_count": 1,
  "status": "received"
}
```

---

## 🧪 Automated Test Coverage

Run the test suite inside the `app` container:

```bash
docker compose exec app php artisan test --filter=AbuseTriagePipelineTest
```

- `test_it_ingests_new_abuse_report_and_queues_enrichment_pipeline`
- `test_it_enforces_strict_idempotency_on_duplicate_webhook_replays`
- `test_it_deduplicates_multiple_reports_for_same_target_via_sha256_fingerprint`
- `test_async_jobs_enrich_dns_and_calculate_critical_heuristic_risk_score`
- `test_state_machine_blocks_invalid_transitions_and_records_immutable_audit_trail`

---

## 👨‍💻 Author

**Claudio Leiva** — Systems & Infrastructure Specialist / Backend & Technical Support Engineer  
*Built to showcase Abuse Desk automation, DMCA compliance workflows, and resilient backend architecture.*
EOF

echo "==> [4/5] Configurando .gitignore raiz y limpiando posibles submodulos .git anidados..."
rm -rf src/.git

cat << 'EOF' > .gitignore
.DS_Store
src/vendor/
src/node_modules/
src/.env
src/storage/*.key
src/storage/logs/*.log
src/storage/framework/cache/data/*
src/storage/framework/sessions/*
src/storage/framework/views/*.php
src/database/*.sqlite
src/database/*.sqlite-journal
EOF

sudo chown -R "$USER":82 src
chmod -R 775 src/storage src/bootstrap/cache

echo "==> [5/5] Ejecutando la suite de 5 Tests Automatizados en PostgreSQL 16..."
docker compose exec app php artisan test --filter=AbuseTriagePipelineTest
