<script setup lang="ts">
import { proxyListString, isLoading, results, checkProxyList, progress, stats } from './App.ts'
import './App.css'
</script>

<template>
  <div class="container">
    <h1 class="title">🔌 Proxy Checker Migration (PoC)</h1>
    
    <div class="control-panel">
      <!-- Textarea để nhập nhiều proxy -->
      <div class="input-group paste-group">
        <label for="proxyListString">📋 Paste Danh Sách Proxy (mỗi dòng 1 proxy - host:port:user:pass)</label>
        <textarea 
          id="proxyListString" 
          v-model="proxyListString" 
          placeholder="prxserver72025.ddns.net:4587:user34:oaprr&#10;prxserver72026.ddns.net:4588:user35:oaprr" 
          class="input-field paste-field textarea-field" 
          rows="6"
        ></textarea>
        <div class="proxy-count">
          {{ proxyListString.split('\n').filter(l => l.trim()).length }} proxy(s) được phát hiện
        </div>
      </div>
      
      <button @click="checkProxyList" :disabled="isLoading" class="check-btn">
        <span class="btn-icon">🔍</span>
        {{ isLoading ? `Đang check... (${progress.current}/${progress.total})` : 'Check Danh Sách Proxy' }}
      </button>

      <!-- Thống kê -->
      <div v-if="results.length > 0" class="stats-panel">
        <div class="stat-item stat-total">
          <span class="stat-label">Tổng:</span>
          <span class="stat-value">{{ stats.total }}</span>
        </div>
        <div class="stat-item stat-live">
          <span class="stat-label">LIVE:</span>
          <span class="stat-value">{{ stats.live }}</span>
        </div>
        <div class="stat-item stat-dead">
          <span class="stat-label">DEAD:</span>
          <span class="stat-value">{{ stats.dead }}</span>
        </div>
      </div>
    </div>

    <!-- Danh sách kết quả -->
    <div v-if="results.length > 0" class="results-list">
      <div 
        v-for="(result, index) in results" 
        :key="index" 
        class="result-card" 
        :class="result.success ? 'status-live' : 'status-dead'"
      >
        <div class="result-header">
          <span class="status-badge">{{ result.success ? '✅ LIVE' : '❌ DEAD' }}</span>
          <span class="proxy-string">{{ result.proxy }}</span>
          <span class="latency" v-if="result.response_time">⏱ {{ result.response_time }}ms</span>
        </div>
        
        <div class="result-body">
          <p><strong>Protocol:</strong> 
            <span :class="result.success ? 'protocol-live' : 'protocol-dead'">
              {{ result.success ? (result.verified_protocol || result.type || 'Detected').toUpperCase() : 'UNKNOWN' }}
            </span>
          </p>
          <p v-if="result.public_ip"><strong>Public IP:</strong> {{ result.public_ip }}</p>
          <p><strong>Info:</strong> {{ result.info }}</p>
        </div>
      </div>
    </div>
  </div>
</template>
