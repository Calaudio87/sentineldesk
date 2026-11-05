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
