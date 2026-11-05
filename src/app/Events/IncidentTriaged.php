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
