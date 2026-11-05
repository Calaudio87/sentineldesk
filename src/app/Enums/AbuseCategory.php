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
