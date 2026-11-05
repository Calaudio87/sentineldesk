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
