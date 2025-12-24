import { ref, computed } from 'vue'
import axios from 'axios'

// Protocol types supported
export type ProtocolType = 'auto' | 'http' | 'socks5' | 'https'

export const PROTOCOL_OPTIONS = [
    { value: 'auto', label: '🔍 Auto Detect' },
    { value: 'http', label: '🌐 HTTP' },
    { value: 'socks5', label: '🧦 SOCKS5' },
    { value: 'https', label: '🔒 HTTPS/CONNECT' }
]

// Interface cho kết quả proxy
export interface ProxyResult {
    proxy: string
    success: boolean
    info: string
    response_time?: number
    public_ip?: string
    verified_protocol?: string
    type?: string
    error?: string
}

// State quản lý dữ liệu
export const proxyListString = ref('') // Empty by default
export const selectedProtocol = ref<ProtocolType>('auto') // Protocol mặc định: auto detect
export const isLoading = ref(false)
export const results = ref<ProxyResult[]>([])
export const progress = ref({ current: 0, total: 0 })

// Parse proxy string format: host:port:user:pass
export const parseProxy = (input: string): { host: string, port: number, username: string, password: string } | null => {
    const parts = input.trim().split(':')
    if (parts.length >= 2) {
        return {
            host: parts[0] || '',
            port: parseInt(parts[1]) || 0,
            username: parts[2] || '',
            password: parts[3] || ''
        }
    }
    return null
}

// Parse danh sách proxy từ textarea (mỗi dòng 1 proxy)
export const parseProxyList = (input: string): string[] => {
    return input
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0)
}

// API Base URL - sẽ được load từ port.json
let API_URL = ''

// Load API URL từ port.json (được backend ghi vào fontend/public)
const loadApiUrl = async (): Promise<string> => {
    if (API_URL) return API_URL

    try {
        const response = await axios.get('/port.json?t=' + Date.now())
        if (response.data?.url) {
            API_URL = response.data.url
            console.log('✅ Backend URL:', API_URL)
            return API_URL
        }
    } catch (e) {
        console.error('❌ Could not load port.json - Backend chưa chạy?')
    }
    return ''
}

// Hàm check một proxy đơn lẻ
const checkSingleProxy = async (proxyString: string): Promise<ProxyResult> => {
    const parsed = parseProxy(proxyString)
    if (!parsed) {
        return {
            proxy: proxyString,
            success: false,
            info: "❌ Định dạng proxy không hợp lệ",
            error: "Invalid format"
        }
    }

    try {
        // Load API URL nếu chưa có
        const apiUrl = await loadApiUrl()
        if (!apiUrl) {
            return {
                proxy: proxyString,
                success: false,
                info: "❌ Không tìm thấy Backend - Hãy chạy Backend trước!",
                error: "Backend not found"
            }
        }

        const response = await axios.post(`${apiUrl}/api/check-proxy`, {
            host: parsed.host,
            port: Number(parsed.port),
            login: parsed.username,
            password: parsed.password
        })
        return {
            proxy: proxyString,
            ...response.data
        }
    } catch (error: any) {
        console.error(`Error checking proxy ${proxyString}:`, error)
        return {
            proxy: proxyString,
            success: false,
            info: error.response?.data?.detail || "❌ Lỗi: Không kết nối được với Python Backend",
            error: error.message
        }
    }
}

// Hàm check danh sách proxy
export const checkProxyList = async () => {
    const proxyList = parseProxyList(proxyListString.value)

    if (proxyList.length === 0) {
        alert('Vui lòng nhập ít nhất một proxy!')
        return
    }

    isLoading.value = true
    results.value = []
    progress.value = { current: 0, total: proxyList.length }

    // Check từng proxy (có thể chạy song song hoặc tuần tự)
    // Ở đây tôi sẽ chạy song song để nhanh hơn, nhưng giới hạn số lượng đồng thời
    const batchSize = 5 // Check 5 proxy cùng lúc
    const allResults: ProxyResult[] = []

    for (let i = 0; i < proxyList.length; i += batchSize) {
        const batch = proxyList.slice(i, i + batchSize)
        const batchPromises = batch.map(proxy => checkSingleProxy(proxy))
        const batchResults = await Promise.all(batchPromises)

        allResults.push(...batchResults)
        results.value = [...allResults] // Cập nhật kết quả theo thời gian thực
        progress.value = { current: allResults.length, total: proxyList.length }
    }

    isLoading.value = false
}

// Thống kê kết quả
export const stats = computed(() => {
    const total = results.value.length
    const live = results.value.filter(r => r.success).length
    const dead = total - live
    return { total, live, dead }
})
