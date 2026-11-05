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
