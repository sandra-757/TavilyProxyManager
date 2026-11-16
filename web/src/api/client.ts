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

export const api = axios.create()

api.interceptors.request.use((config) => {
  const token = getMasterKey()
  if (token) {
    config.headers = config.headers ?? {}
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401) {
      clearMasterKey()
      window.dispatchEvent(new Event('auth-required'))
    }
    return Promise.reject(error)
  }
)
