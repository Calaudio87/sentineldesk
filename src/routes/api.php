<?php

use App\Http\Controllers\Api\AbuseIngestController;
use App\Models\Incident;
use Illuminate\Support\Facades\Route;

Route::post('/v1/abuse/ingest', [AbuseIngestController::class, 'store']);

Route::get('/v1/incidents', function () {
    return Incident::with(['enrichment', 'reports', 'auditLogs'])->latest('last_reported_at')->get();
});
