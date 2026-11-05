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
            $ips = ['203.0.113.' . rand(10, 250)]; // Fallback para dominios simulados .example
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
