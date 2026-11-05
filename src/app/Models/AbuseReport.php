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
