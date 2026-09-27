/**
 * Sessão segura no app mobile (Expo / React Native).
 *
 * - Token JWT guardado no expo-secure-store (Android Keystore / iOS Keychain),
 *   nunca no AsyncStorage (texto claro no aparelho) — OWASP Mobile M9.
 * - Todas as chamadas vão por HTTPS; o app não aceita http:// (M5).
 * - Token expirado ou revogado (401) limpa a sessão e volta para o login.
 * - Nada de token, CPF ou telefone no console/log (M6).
 */
import Constants from "expo-constants";
import * as SecureStore from "expo-secure-store";

const TOKEN_KEY = "vinshare.access_token";
const APP_VERSION = Constants.expoConfig?.version ?? "0.0.0"; // a API recusa versões antigas (426)
const API_URL = process.env.EXPO_PUBLIC_API_URL ?? "https://api.vinshare.example";

if (!API_URL.startsWith("https://")) {
  throw new Error("API_URL precisa usar HTTPS");
}

export async function saveToken(token: string): Promise<void> {
  await SecureStore.setItemAsync(TOKEN_KEY, token, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY, // não vai para backup/iCloud
  });
}

export async function clearSession(): Promise<void> {
  await SecureStore.deleteItemAsync(TOKEN_KEY);
}

export class SessionExpiredError extends Error {}
export class UpdateRequiredError extends Error {}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = await SecureStore.getItemAsync(TOKEN_KEY);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const response = await fetch(`${API_URL}${path}`, {
      ...init,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "X-App-Version": APP_VERSION,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init.headers,
      },
    });

    // 401 só significa "sessão expirada" se um token foi enviado; no login é senha errada
    if (response.status === 401 && token) {
      await clearSession();
      throw new SessionExpiredError("Sessão expirada. Faça login novamente.");
    }
    if (response.status === 426) {
      throw new UpdateRequiredError("Atualize o aplicativo para continuar.");
    }
    if (!response.ok) {
      const problem = await response.json().catch(() => ({}));
      // Mostra só a mensagem genérica + request_id para o suporte
      throw new Error(`${problem.detail ?? "Erro na requisição"} (ref: ${problem.request_id ?? "-"})`);
    }
    return (await response.json()) as T;
  } finally {
    clearTimeout(timeout);
  }
}

export async function login(username: string, password: string): Promise<string> {
  await clearSession(); // nunca envia token antigo junto com credenciais novas
  const data = await apiFetch<{ access_token: string; role: string }>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  await saveToken(data.access_token);
  return data.role; // usado só para montar o menu; a autorização real é feita na API
}
