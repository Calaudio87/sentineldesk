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
