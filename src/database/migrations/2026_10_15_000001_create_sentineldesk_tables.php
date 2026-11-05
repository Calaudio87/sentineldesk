<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('incidents', function (Blueprint $table) {
            $table->id();
            $table->string('reference_code', 32)->unique();
            $table->string('fingerprint', 64)->index();
            $table->string('target_type', 20);
            $table->string('target_value', 255)->index();
            $table->string('category', 30)->index();
            $table->string('status', 30)->default('received')->index();
            $table->string('severity', 20)->default('medium')->index();
            $table->unsignedTinyInteger('risk_score')->default(0);
            $table->unsignedInteger('reports_count')->default(1);
            $table->foreignId('assigned_to')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('sla_due_at')->nullable()->index();
            $table->timestamp('first_reported_at');
            $table->timestamp('last_reported_at');
            $table->timestamp('resolved_at')->nullable();
            $table->timestamps();
        });

        Schema::create('abuse_reports', function (Blueprint $table) {
            $table->id();
            $table->foreignId('incident_id')->constrained('incidents')->cascadeOnDelete();
            $table->string('idempotency_key', 64)->unique();
            $table->string('source_type', 20)->default('api');
            $table->string('reporter_email', 150);
            $table->string('reporter_organization', 150)->nullable();
            $table->boolean('dmca_sworn_statement')->default(false);
            $table->jsonb('evidence_urls')->default('[]');
            $table->jsonb('raw_payload')->default('{}');
            $table->ipAddress('sender_ip')->nullable();
            $table->timestamps();
        });

        Schema::create('threat_enrichments', function (Blueprint $table) {
            $table->id();
            $table->foreignId('incident_id')->unique()->constrained('incidents')->cascadeOnDelete();
            $table->jsonb('resolved_ips')->default('[]');
            $table->jsonb('dns_records')->default('{}');
            $table->string('asn_name', 150)->nullable();
            $table->string('hosting_provider', 150)->nullable();
            $table->boolean('ssl_valid')->default(false);
            $table->jsonb('risk_factors')->default('[]');
            $table->timestamp('enriched_at');
            $table->timestamps();
        });

        Schema::create('mitigation_actions', function (Blueprint $table) {
            $table->id();
            $table->foreignId('incident_id')->constrained('incidents')->cascadeOnDelete();
            $table->foreignId('user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('action_type', 40);
            $table->text('notes');
            $table->timestamp('executed_at');
            $table->timestamps();
        });

        Schema::create('incident_audit_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('incident_id')->constrained('incidents')->cascadeOnDelete();
            $table->foreignId('actor_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('event', 60);
            $table->jsonb('old_values')->default('{}');
            $table->jsonb('new_values')->default('{}');
            $table->ipAddress('ip_address')->nullable();
            $table->timestamp('created_at')->useCurrent();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('incident_audit_logs');
        Schema::dropIfExists('mitigation_actions');
        Schema::dropIfExists('threat_enrichments');
        Schema::dropIfExists('abuse_reports');
        Schema::dropIfExists('incidents');
    }
};
