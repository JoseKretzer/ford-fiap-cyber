// Configuração Expo com hardening do Android (OWASP Mobile M5, M7, M8, M9)
import type { ExpoConfig } from "expo/config";

const config: ExpoConfig = {
  name: "Ford VIN Share",
  slug: "ford-vinshare",
  version: "1.0.0",
  android: {
    package: "com.fiap.ford.vinshare",
    allowBackup: false,                 // impede extrair dados do app via adb backup
    permissions: [],                    // nenhuma permissão além do necessário (sem localização, câmera, contatos)
    blockedPermissions: [
      "android.permission.ACCESS_FINE_LOCATION",
      "android.permission.READ_CONTACTS",
    ],
  },
  plugins: [
    ["expo-build-properties", {
      android: {
        usesCleartextTraffic: false,    // bloqueia http:// no nível do sistema
        enableProguardInReleaseBuilds: true,   // ofuscação/minificação do release (M7)
        enableShrinkResourcesInReleaseBuilds: true,
      },
    }],
  ],
};

export default config;
