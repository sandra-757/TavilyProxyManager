import axios from 'axios'
import { ref } from 'vue'

const STORAGE_KEY = 'tavily_proxy_master_key'

// The admin (master) key is kept in sessionStorage, not localStorage: it
// disappears when the tab closes instead of persisting on disk indefinitely.
const masterKeyRef = ref<string>(sessionStorage.getItem(STORAGE_KEY) ?? '')

export function getMasterKey(): string {
  return masterKeyRef.value
}

export function setMasterKey(value: string): void {
  sessionStorage.setItem(STORAGE_KEY, value)
  masterKeyRef.value = value
}

export function clearMasterKey(): void {
  sessionStorage.removeItem(STORAGE_KEY)
  masterKeyRef.value = ''
}

export const api = axios.create({ timeout: 30000 })

api.interceptors.request.use((config) => {
  const token = getMasterKey()
  if (token) {
    config.headers = config.headers ?? {}
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => {
    // Behind the Authelia SSO front, an expired SSO session makes API
    // calls land on the portal login page (HTML) instead of JSON. Detect
    // that and send the browser back through the login flow instead of
    // letting views fail silently on HTML payloads.
    const contentType = String(response.headers?.["content-type"] ?? "")
    const url = String(response.config?.url ?? "")
    if (url.startsWith("/api") && contentType.includes("text/html")) {
      window.location.href = "/"
      return new Promise(() => {})
    }
    return response
  },
  (error) => {
    if (error?.response?.status === 401) {
      clearMasterKey()
      window.dispatchEvent(new Event('auth-required'))
    }
    return Promise.reject(error)
  }
)
