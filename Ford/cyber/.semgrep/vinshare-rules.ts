// Casos de teste da regra asyncstorage-token
import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";

export async function bad(token: string) {
  // ruleid: asyncstorage-token
  await AsyncStorage.setItem("token", token);
}

export async function good(token: string) {
  // ok: asyncstorage-token
  await SecureStore.setItemAsync("token", token);
}
