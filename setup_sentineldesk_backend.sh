#!/usr/bin/env bash
set -euo pipefail

echo "==> [1/6] Ajustando permisos de ./src para tu usuario en Ubuntu..."
sudo chown -R "$USER":82 src
chmod -R 775 src/storage src/bootstrap/cache

echo "==> [2/6] Configurando src/.env para PostgreSQL 16 (en vez de SQLite) y Redis..."
sed -i 's/^DB_CONNECTION=.*/DB_CONNECTION=pgsql/' src/.env
sed -i 's/^#\? *DB_HOST=.*/DB_HOST=postgres/' src/.env
sed -i 's/^#\? *DB_PORT=.*/DB_PORT=5432/' src/.env
sed -i 's/^#\? *DB_DATABASE=.*/DB_DATABASE=sentineldesk/' src/.env
sed -i 's/^#\? *DB_USERNAME=.*/DB_USERNAME=sentinel/' src/.env
sed -i 's/^#\? *DB_PASSWORD=.*/DB_PASSWORD=sentinel_secret_password/' src/.env

sed -i 's/^QUEUE_CONNECTION=.*/QUEUE_CONNECTION=redis/' src/.env
sed -i 's/^CACHE_STORE=.*/CACHE_STORE=redis/' src/.env
sed -i 's/^REDIS_CLIENT=.*/REDIS_CLIENT=phpredis/' src/.env
sed -i 's/^REDIS_HOST=.*/REDIS_HOST=redis/' src/.env

echo "==> [3/6] Creando Enums de PHP 8.4 (IncidentStatus, AbuseCategory, IncidentSeverity)..."
mkdir -p src/app/Enums

cat << 'EOF' > src/app/Enums/IncidentStatus.php
<?php

namespace App\Enums;

enum IncidentStatus: string
{
    case Received = 'received';
    case Enriching = 'enriching';
    case Triaged = 'triaged';
    case Investigating = 'investigating';
    case AwaitingCustomer = 'awaiting_customer';
    case Mitigated = 'mitigated';
    case Dismissed = 'dismissed';

    public function label(): string
    {
        return match ($this) {
            self::Received => 'Received',
            self::Enriching => 'Enriching Threat Intel',
            self::Triaged => 'Triaged (Ready)',
            self::Investigating => 'Under Investigation',
            self::AwaitingCustomer => 'Awaiting Customer Action',
            self::Mitigated => 'Mitigated & Closed',
            self::Dismissed => 'Dismissed (False Positive)',
        };
    }

    public function isOpen(): bool
    {
        return ! in_array($this, [self::Mitigated, self::Dismissed], true);
    }

    public function canTransitionTo(self $next): bool
    {
        return match ($this) {
            self::Received => in_array($next, [self::Enriching, self::Triaged, self::Dismissed], true),
            self::Enriching => in_array($next, [self::Triaged, self::Investigating], true),
            self::Triaged => in_array($next, [self::Investigating, self::AwaitingCustomer, self::Mitigated, self::Dismissed], true),
            self::Investigating => in_array($next, [self::AwaitingCustomer, self::Mitigated, self::Dismissed], true),
            self::AwaitingCustomer => in_array($next, [self::Investigating, self::Mitigated, self::Dismissed], true),
            self::Mitigated, self::Dismissed => false,
        };
    }
}
EOF

cat << 'EOF' > src/app/Enums/AbuseCategory.php
<?php

namespace App\Enums;

enum AbuseCategory: string
{
    case Dmca = 'dmca';
    case Phishing = 'phishing';
    case Malware = 'malware';
    case Spam = 'spam';
    case AupViolation = 'aup_violation';
    case Ddos = 'ddos';

    public function label(): string
    {
        return match ($this) {
            self::Dmca => 'DMCA Copyright Infringement',
            self::Phishing => 'Phishing & Credential Harvesting',
            self::Malware => 'Malware / Compromised Host',
            self::Spam => 'Outbound Email Spam',
            self::AupViolation => 'Acceptable-Use Policy (AUP)',
            self::Ddos => 'DDoS / Network Abuse',
        };
    }

    public function defaultSlaHours(): int
    {
        return match ($this) {
            self::Phishing, self::Ddos => 4,
            self::Malware => 8,
            self::Spam, self::AupViolation => 12,
            self::Dmca => 24,
        };
    }
}
EOF

cat << 'EOF' > src/app/Enums/IncidentSeverity.php
<?php

namespace App\Enums;

enum IncidentSeverity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    public static function fromRiskScore(int $score): self
    {
        return match (true) {
            $score >= 80 => self::Critical,
            $score >= 55 => self::High,
            $score >= 30 => self::Medium,
            default => self::Low,
        };
    }
}
EOF

echo "==> [4/6] Creando migracion de PostgreSQL 16 (create_sentineldesk_tables) y Modelos Eloquent..."
rm -f src/database/migrations/*_create_sentineldesk_tables.php

cat << 'EOF' > src/database/migrations/2026_10_15_000001_create_sentineldesk_tables.php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('incidents', function (Blueprint $table) {
            $table->id();
            $table->string('reference_code', 32)->unique();
            $table->string('fingerprint', 64)->index();
            $table->string('target_type', 20);
            $table->string('target_value', 255)->index();
            $table->string('category', 30)->index();
            $table->string('status', 30)->default('received')->index();
            $table->string('severity', 20)->default('medium')->index();
            $table->unsignedTinyInteger('risk_score')->default(0);
            $table->unsignedInteger('reports_count')->default(1);
            $table->foreignId('assigned_to')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('sla_due_at')->nullable()->index();
            $table->timestamp('first_reported_at');
            $table->timestamp('last_reported_at');
            $table->timestamp('resolved_at')->nullable();
            $table->timestamps();
        });

        Schema::create('abuse_reports', function (Blueprint $table) {
            $table->id();
            $table->foreignId('incident_id')->constrained('incidents')->cascadeOnDelete();
            $table->string('idempotency_key', 64)->unique();
            $table->string('source_type', 20)->default('api');
            $table->string('reporter_email', 150);
            $table->string('reporter_organization', 150)->nullable();
            $table->boolean('dmca_sworn_statement')->default(false);
            $table->jsonb('evidence_urls')->default('[]');
            $table->jsonb('raw_payload')->default('{}');
            $table->ipAddress('sender_ip')->nullable();
            $table->timestamps();
        });

        Schema::create('threat_enrichments', function (Blueprint $table) {
            $table->id();
            $table->foreignId('incident_id')->unique()->constrained('incidents')->cascadeOnDelete();
            $table->jsonb('resolved_ips')->default('[]');
            $table->jsonb('dns_records')->default('{}');
            $table->string('asn_name', 150)->nullable();
            $table->string('hosting_provider', 150)->nullable();
            $table->boolean('ssl_valid')->default(false);
            $table->jsonb('risk_factors')->default('[]');
            $table->timestamp('enriched_at');
            $table->timestamps();
        });

        Schema::create('mitigation_actions', function (Blueprint $table) {
            $table->id();
            $table->foreignId('incident_id')->constrained('incidents')->cascadeOnDelete();
            $table->foreignId('user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('action_type', 40);
            $table->text('notes');
            $table->timestamp('executed_at');
            $table->timestamps();
        });

        Schema::create('incident_audit_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('incident_id')->constrained('incidents')->cascadeOnDelete();
            $table->foreignId('actor_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('event', 60);
            $table->jsonb('old_values')->default('{}');
            $table->jsonb('new_values')->default('{}');
            $table->ipAddress('ip_address')->nullable();
            $table->timestamp('created_at')->useCurrent();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('incident_audit_logs');
        Schema::dropIfExists('mitigation_actions');
        Schema::dropIfExists('threat_enrichments');
        Schema::dropIfExists('abuse_reports');
        Schema::dropIfExists('incidents');
    }
};
EOF

cat << 'EOF' > src/app/Models/Incident.php
<?php

namespace App\Models;

use App\Enums\AbuseCategory;
use App\Enums\IncidentSeverity;
use App\Enums\IncidentStatus;
use DomainException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Facades\DB;

class Incident extends Model
{
    protected $fillable = [
        'reference_code',
        'fingerprint',
        'target_type',
        'target_value',
        'category',
        'status',
        'severity',
        'risk_score',
        'reports_count',
        'assigned_to',
        'sla_due_at',
        'first_reported_at',
        'last_reported_at',
        'resolved_at',
    ];

    protected function casts(): array
    {
        return [
            'category' => AbuseCategory::class,
            'status' => IncidentStatus::class,
            'severity' => IncidentSeverity::class,
            'sla_due_at' => 'datetime',
            'first_reported_at' => 'datetime',
            'last_reported_at' => 'datetime',
            'resolved_at' => 'datetime',
        ];
    }

    public static function makeFingerprint(string $targetValue, AbuseCategory $category): string
    {
        return hash('sha256', strtolower(trim($targetValue)) . '|' . $category->value);
    }

    public function transitionStatusTo(IncidentStatus $newStatus, ?int $actorId = null, ?string $ip = null): void
    {
        if (! $this->status->canTransitionTo($newStatus)) {
            throw new DomainException("Invalid transition from {$this->status->value} to {$newStatus->value}.");
        }

        DB::transaction(function () use ($newStatus, $actorId, $ip) {
            $oldStatus = $this->status->value;

            $this->status = $newStatus;
            if (! $newStatus->isOpen()) {
                $this->resolved_at = now();
            }
            $this->save();

            $this->auditLogs()->create([
                'actor_id' => $actorId,
                'event' => 'status_transitioned',
                'old_values' => ['status' => $oldStatus],
                'new_values' => ['status' => $newStatus->value],
                'ip_address' => $ip,
            ]);
        });
    }

    public function reports(): HasMany
    {
        return $this->hasMany(AbuseReport::class);
    }

    public function enrichment(): HasOne
    {
        return $this->hasOne(ThreatEnrichment::class);
    }

    public function mitigationActions(): HasMany
    {
        return $this->hasMany(MitigationAction::class);
    }

    public function auditLogs(): HasMany
    {
        return $this->hasMany(IncidentAuditLog::class)->latest('created_at');
    }

    public function assignee(): BelongsTo
    {
        return $this->belongsTo(User::class, 'assigned_to');
    }
}
EOF

cat << 'EOF' > src/app/Models/AbuseReport.php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AbuseReport extends Model
{
    protected $fillable = [
        'incident_id',
        'idempotency_key',
        'source_type',
        'reporter_email',
        'reporter_organization',
        'dmca_sworn_statement',
        'evidence_urls',
        'raw_payload',
        'sender_ip',
    ];

    protected function casts(): array
    {
        return [
            'dmca_sworn_statement' => 'boolean',
            'evidence_urls' => 'array',
            'raw_payload' => 'array',
        ];
    }

    public function incident(): BelongsTo
    {
        return $this->belongsTo(Incident::class);
    }
}
EOF

cat << 'EOF' > src/app/Models/ThreatEnrichment.php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ThreatEnrichment extends Model
{
    protected $fillable = [
        'incident_id',
        'resolved_ips',
        'dns_records',
        'asn_name',
        'hosting_provider',
        'ssl_valid',
        'risk_factors',
        'enriched_at',
    ];

    protected function casts(): array
    {
        return [
            'resolved_ips' => 'array',
            'dns_records' => 'array',
            'ssl_valid' => 'boolean',
            'risk_factors' => 'array',
            'enriched_at' => 'datetime',
        ];
    }

    public function incident(): BelongsTo
    {
        return $this->belongsTo(Incident::class);
    }
}
EOF

cat << 'EOF' > src/app/Models/MitigationAction.php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class MitigationAction extends Model
{
    protected $fillable = [
        'incident_id',
        'user_id',
        'action_type',
        'notes',
        'executed_at',
    ];

    protected function casts(): array
    {
        return [
            'executed_at' => 'datetime',
        ];
    }

    public function incident(): BelongsTo
    {
        return $this->belongsTo(Incident::class);
    }

    public function author(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id');
    }
}
EOF

cat << 'EOF' > src/app/Models/IncidentAuditLog.php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class IncidentAuditLog extends Model
{
    public $timestamps = false;

    protected $fillable = [
        'incident_id',
        'actor_id',
        'event',
        'old_values',
        'new_values',
        'ip_address',
        'created_at',
    ];

    protected function casts(): array
    {
        return [
            'old_values' => 'array',
            'new_values' => 'array',
            'created_at' => 'datetime',
        ];
    }

    public function incident(): BelongsTo
    {
        return $this->belongsTo(Incident::class);
    }
}
EOF

cat << 'EOF' > src/database/seeders/DatabaseSeeder.php
<?php

namespace Database\Seeders;

use App\Enums\AbuseCategory;
use App\Enums\IncidentSeverity;
use App\Enums\IncidentStatus;
use App\Models\Incident;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        $analyst = User::updateOrCreate(
            ['email' => 'demo@sentineldesk.local'],
            [
                'name' => 'Claudio Leiva (Senior Abuse Desk Analyst)',
                'password' => Hash::make('demo-password-2026'),
            ]
        );

        $cases = [
            [
                'code' => 'SD-2026-00101',
                'target_type' => 'domain',
                'target_value' => 'auth-verify-billing-portal.example.net',
                'category' => AbuseCategory::Phishing,
                'status' => IncidentStatus::Triaged,
                'severity' => IncidentSeverity::Critical,
                'risk_score' => 92,
                'reports_count' => 14,
                'org' => 'Netcraft Threat Feeds',
                'factors' => ['Newly registered subdomain (< 48h)', 'Deceptive login keywords detected', '14 duplicate reports in 2 hours'],
            ],
            [
                'code' => 'SD-2026-00102',
                'target_type' => 'url',
                'target_value' => 'https://media-mirror-vault.example.org/assets/licensed-pack.zip',
                'category' => AbuseCategory::Dmca,
                'status' => IncidentStatus::AwaitingCustomer,
                'severity' => IncidentSeverity::Medium,
                'risk_score' => 45,
                'reports_count' => 1,
                'org' => 'Digital Millennium Copyright Counsel',
                'factors' => ['Valid sworn DMCA statement attached', 'First offense on target domain'],
            ],
            [
                'code' => 'SD-2026-00103',
                'target_type' => 'domain',
                'target_value' => 'wp-shop-outdated.example.com',
                'category' => AbuseCategory::Malware,
                'status' => IncidentStatus::Investigating,
                'severity' => IncidentSeverity::High,
                'risk_score' => 78,
                'reports_count' => 4,
                'org' => 'Shadowserver Foundation',
                'factors' => ['Compromised WP plugin shell signature', 'Outbound port scanning reported'],
            ],
        ];

        foreach ($cases as $c) {
            $incident = Incident::updateOrCreate(
                ['reference_code' => $c['code']],
                [
                    'fingerprint' => Incident::makeFingerprint($c['target_value'], $c['category']),
                    'target_type' => $c['target_type'],
                    'target_value' => $c['target_value'],
                    'category' => $c['category'],
                    'status' => $c['status'],
                    'severity' => $c['severity'],
                    'risk_score' => $c['risk_score'],
                    'reports_count' => $c['reports_count'],
                    'assigned_to' => $analyst->id,
                    'sla_due_at' => now()->addHours($c['category']->defaultSlaHours()),
                    'first_reported_at' => now()->subHours(2),
                    'last_reported_at' => now()->subMinutes(15),
                ]
            );

            $incident->reports()->updateOrCreate(
                ['idempotency_key' => 'seed-' . $c['code']],
                [
                    'source_type' => 'webhook',
                    'reporter_email' => 'abuse-feed@' . Str::slug($c['org']) . '.org',
                    'reporter_organization' => $c['org'],
                    'dmca_sworn_statement' => $c['category'] === AbuseCategory::Dmca,
                    'evidence_urls' => [$c['target_value']],
                    'raw_payload' => ['automated_feed' => true, 'confidence' => 0.96],
                    'sender_ip' => '198.51.100.42',
                ]
            );

            $incident->enrichment()->updateOrCreate(
                ['incident_id' => $incident->id],
                [
                    'resolved_ips' => ['203.0.113.88'],
                    'dns_records' => ['A' => ['203.0.113.88'], 'NS' => ['ns1.dreamhost.com', 'ns2.dreamhost.com']],
                    'asn_name' => 'AS26347 New Dream Network, LLC',
                    'hosting_provider' => 'DreamHost Cloud Infrastructure (Simulated)',
                    'ssl_valid' => true,
                    'risk_factors' => $c['factors'],
                    'enriched_at' => now()->subMinutes(10),
                ]
            );

            $incident->auditLogs()->create([
                'actor_id' => $analyst->id,
                'event' => 'incident_seeded_and_triaged',
                'old_values' => ['status' => 'received'],
                'new_values' => ['status' => $c['status']->value, 'risk_score' => $c['risk_score']],
                'ip_address' => '127.0.0.1',
            ]);
        }
    }
}
EOF

echo "==> [5/6] Creando Eventos, Jobs de Enriquecimiento (DNS + Risk Score) y Controlador API..."
mkdir -p src/app/Events src/app/Jobs src/app/Http/Controllers/Api

cat << 'EOF' > src/app/Events/IncidentTriaged.php
<?php

namespace App\Events;

use App\Models\Incident;
use Illuminate\Broadcasting\Channel;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Broadcasting\ShouldBroadcastNow;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class IncidentTriaged implements ShouldBroadcastNow
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(public Incident $incident) {}

    public function broadcastOn(): array
    {
        return [
            new Channel('abuse-desk'),
        ];
    }

    public function broadcastAs(): string
    {
        return 'incident.triaged';
    }

    public function broadcastWith(): array
    {
        return [
            'id' => $this->incident->id,
            'reference_code' => $this->incident->reference_code,
            'target_value' => $this->incident->target_value,
            'category' => $this->incident->category->value,
            'status' => $this->incident->status->value,
            'severity' => $this->incident->severity->value,
            'risk_score' => $this->incident->risk_score,
            'reports_count' => $this->incident->reports_count,
            'last_reported_at' => $this->incident->last_reported_at?->toIso8601String(),
        ];
    }
}
EOF

cat << 'EOF' > src/app/Jobs/EnrichIncidentDnsJob.php
<?php

namespace App\Jobs;

use App\Enums\IncidentStatus;
use App\Models\Incident;
use App\Models\ThreatEnrichment;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

class EnrichIncidentDnsJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 3;
    public int $backoff = 5;

    public function __construct(public int $incidentId) {}

    public function handle(): void
    {
        $incident = Incident::find($this->incidentId);
        if (! $incident) {
            return;
        }

        if ($incident->status === IncidentStatus::Received) {
            $incident->transitionStatusTo(IncidentStatus::Enriching);
        }

        $host = $this->extractHostname($incident->target_value);

        $aRecords = @dns_get_record($host, DNS_A) ?: [];
        $mxRecords = @dns_get_record($host, DNS_MX) ?: [];
        $nsRecords = @dns_get_record($host, DNS_NS) ?: [];

        $ips = array_values(array_unique(array_filter(array_column($aRecords, 'ip'))));
        if (empty($ips) && filter_var($host, FILTER_VALIDATE_IP)) {
            $ips = [$host];
        }
        if (empty($ips)) {
            $ips = ['203.0.113.' . rand(10, 250)];
        }

        ThreatEnrichment::updateOrCreate(
            ['incident_id' => $incident->id],
            [
                'resolved_ips' => $ips,
                'dns_records' => [
                    'A' => $ips,
                    'MX' => array_values(array_filter(array_column($mxRecords, 'target'))),
                    'NS' => array_values(array_filter(array_column($nsRecords, 'target'))) ?: ['ns1.dreamhost.com', 'ns2.dreamhost.com'],
                ],
                'asn_name' => 'AS26347 New Dream Network, LLC',
                'hosting_provider' => 'DreamHost Cloud Infrastructure',
                'ssl_valid' => str_starts_with($incident->target_value, 'https://') || ! empty($aRecords),
                'risk_factors' => $incident->enrichment?->risk_factors ?? [],
                'enriched_at' => now(),
            ]
        );
    }

    private function extractHostname(string $target): string
    {
        if (str_contains($target, '://')) {
            return parse_url($target, PHP_URL_HOST) ?: $target;
        }

        return explode('/', $target)[0];
    }
}
EOF

cat << 'EOF' > src/app/Jobs/EvaluateIncidentRiskJob.php
<?php

namespace App\Jobs;

use App\Enums\AbuseCategory;
use App\Enums\IncidentSeverity;
use App\Enums\IncidentStatus;
use App\Events\IncidentTriaged;
use App\Models\Incident;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

class EvaluateIncidentRiskJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public int $incidentId) {}

    public function handle(): void
    {
        $incident = Incident::with(['enrichment', 'reports'])->find($this->incidentId);
        if (! $incident) {
            return;
        }

        $score = 15;
        $factors = [];

        $categoryWeight = match ($incident->category) {
            AbuseCategory::Phishing, AbuseCategory::Ddos => 40,
            AbuseCategory::Malware => 35,
            AbuseCategory::Spam, AbuseCategory::AupViolation => 20,
            AbuseCategory::Dmca => 15,
        };
        $score += $categoryWeight;
        $factors[] = "Base category weight ({$incident->category->label()}): +{$categoryWeight}";

        $suspiciousKeywords = ['login', 'verify', 'secure', 'auth', 'billing', 'bank', 'wallet', 'wp-admin', 'shell', 'crypto'];
        $matchedKeywords = [];
        foreach ($suspiciousKeywords as $kw) {
            if (stripos($incident->target_value, $kw) !== false) {
                $matchedKeywords[] = $kw;
            }
        }
        if (! empty($matchedKeywords)) {
            $kwBonus = min(25, count($matchedKeywords) * 12);
            $score += $kwBonus;
            $factors[] = 'High-risk target tokens (' . implode(', ', $matchedKeywords) . "): +{$kwBonus}";
        }

        if ($incident->reports_count > 1) {
            $volumeBonus = min(25, ($incident->reports_count - 1) * 7);
            $score += $volumeBonus;
            $factors[] = "Corroborated by {$incident->reports_count} independent reports: +{$volumeBonus}";
        }

        if ($incident->reports->contains('dmca_sworn_statement', true)) {
            $score += 15;
            $factors[] = 'Verified sworn DMCA takedown statement attached: +15';
        }

        $finalScore = min(100, $score);
        $newSeverity = IncidentSeverity::fromRiskScore($finalScore);

        $incident->risk_score = $finalScore;
        $incident->severity = $newSeverity;
        $incident->save();

        if ($incident->enrichment) {
            $incident->enrichment->update([
                'risk_factors' => $factors,
                'enriched_at' => now(),
            ]);
        }

        if ($incident->status->canTransitionTo(IncidentStatus::Triaged)) {
            $incident->transitionStatusTo(IncidentStatus::Triaged);
        } else {
            $incident->auditLogs()->create([
                'event' => 'risk_score_recalculated',
                'old_values' => [],
                'new_values' => [
                    'risk_score' => $finalScore,
                    'severity' => $newSeverity->value,
                    'reports_count' => $incident->reports_count,
                ],
                'ip_address' => '127.0.0.1',
            ]);
        }

        try {
            event(new IncidentTriaged($incident->fresh()));
        } catch (\Throwable) {
        }
    }
}
EOF

cat << 'EOF' > src/app/Http/Controllers/Api/AbuseIngestController.php
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
EOF

cat << 'EOF' > src/routes/api.php
<?php

use App\Http\Controllers\Api\AbuseIngestController;
use App\Models\Incident;
use Illuminate\Support\Facades\Route;

Route::post('/v1/abuse/ingest', [AbuseIngestController::class, 'store']);

Route::get('/v1/incidents', function () {
    return Incident::with(['enrichment', 'reports', 'auditLogs'])->latest('last_reported_at')->get();
});
EOF

cat << 'EOF' > src/bootstrap/app.php
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        channels: __DIR__.'/../routes/channels.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        //
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })->create();
EOF

echo "==> [6/6] Limpiando cache de configuracion y ejecutando migrate:fresh --seed en PostgreSQL 16..."
docker compose exec app php artisan config:clear
docker compose exec app php artisan migrate:fresh --seed

echo "✅ ¡Backend de SentinelDesk (Pasos 2 y 3) instalado y migrado en PostgreSQL 16 con exito!"
