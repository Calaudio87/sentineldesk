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

        // 1. Peso por categoría de amenaza
        $categoryWeight = match ($incident->category) {
            AbuseCategory::Phishing, AbuseCategory::Ddos => 40,
            AbuseCategory::Malware => 35,
            AbuseCategory::Spam, AbuseCategory::AupViolation => 20,
            AbuseCategory::Dmca => 15,
        };
        $score += $categoryWeight;
        $factors[] = "Base category weight ({$incident->category->label()}): +{$categoryWeight}";

        // 2. Detección heurística de palabras clave de suplantación/phishing o shells
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

        // 3. Volumen de reportes acumulados (Deduplicación de campañas activas)
        if ($incident->reports_count > 1) {
            $volumeBonus = min(25, ($incident->reports_count - 1) * 7);
            $score += $volumeBonus;
            $factors[] = "Corroborated by {$incident->reports_count} independent reports: +{$volumeBonus}";
        }

        // 4. Declaración jurada DMCA verificada
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
            // Si el servidor Reverb aún no está encendido en consola, no interrumpe el triaje
        }
    }
}
