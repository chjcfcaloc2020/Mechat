import { useAuthStore } from '@/stores/useAuthStore'
import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.MODE === "development" ? "http://localhost:3001/api" : "/api",
  withCredentials: true,
})

// attach access token at request header
api.interceptors.request.use((config) => {
  const { accessToken } = useAuthStore.getState()
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }

  return config
})

export default api