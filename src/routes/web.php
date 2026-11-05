<?php

use App\Http\Controllers\DashboardController;
use Illuminate\Support\Facades\Route;

Route::get('/', [DashboardController::class, 'index'])->name('dashboard');
Route::post('/demo/login', [DashboardController::class, 'demoLogin'])->name('demo.login');
Route::post('/demo/simulate', [DashboardController::class, 'simulateWebhook'])->name('demo.simulate');
Route::post('/demo/reset', [DashboardController::class, 'resetDemo'])->name('demo.reset');
Route::post('/incidents/{incident}/mitigate', [DashboardController::class, 'mitigate'])->name('incidents.mitigate');
