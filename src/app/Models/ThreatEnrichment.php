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
