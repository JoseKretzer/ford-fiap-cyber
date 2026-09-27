# Gera a PKI de desenvolvimento do broker MQTT: CA própria, broker, serviço de ingestão,
# um dispositivo e a CRL (lista de revogação exigida pelo mosquitto.conf).
# Pré-requisito: openssl no PATH (vem com o Git for Windows: C:\Program Files\Git\usr\bin).
#
# Em produção: CA privada no Azure Key Vault / Azure IoT, chave do dispositivo gerada DENTRO
# do módulo telemático (TPM/secure element) e nunca exportada.
#
# Uso:  .\gerar_certificados.ps1                         (gera tudo)
#       .\gerar_certificados.ps1 -Revogar veh-XXXXXXXX    (playbook PB-04: revoga e regenera a CRL)
param(
    [string]$DeviceId = "veh-3f9a1c2b7d0e4a18",
    [string]$Revogar
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force certs | Out-Null
Push-Location certs
try {
    if (-not (Test-Path ca.cnf)) {
        # Base mínima de CA do openssl para emitir a CRL e registrar revogações
        [IO.File]::WriteAllText("$PWD\ca.cnf", @"
[ ca ]
default_ca = CA_default
[ CA_default ]
database         = index.txt
crlnumber        = crlnumber
default_md       = sha256
default_crl_days = 30
"@)
        [IO.File]::WriteAllText("$PWD\index.txt", "")
        [IO.File]::WriteAllText("$PWD\crlnumber", "1000`n")
    }

    if ($Revogar) {
        openssl ca -config ca.cnf -revoke "$Revogar.crt" -keyfile ca.key -cert ca.crt
        openssl ca -config ca.cnf -gencrl -keyfile ca.key -cert ca.crt -out crl.pem
        Write-Host "Certificado $Revogar revogado. Reinicie o broker para recarregar a CRL."
        return
    }

    openssl ecparam -name prime256v1 -genkey -noout -out ca.key
    openssl req -x509 -new -key ca.key -sha256 -days 365 -subj "/CN=VINShare-IoT-CA" `
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" `
        -addext "subjectKeyIdentifier=hash" -out ca.crt

    function New-LeafCert([string]$Name, [string]$Ext) {
        # SKI/AKI explícitos: clientes com verificação X.509 estrita (ex.: Python 3.13+) recusam certificado sem AKI
        $common = "basicConstraints=critical,CA:FALSE`nsubjectKeyIdentifier=hash`nauthorityKeyIdentifier=keyid,issuer`n"
        [IO.File]::WriteAllText("$PWD\$Name.ext", $common + $Ext)
        openssl ecparam -name prime256v1 -genkey -noout -out "$Name.key"
        openssl req -new -key "$Name.key" -subj "/CN=$Name" -out "$Name.csr"
        openssl x509 -req -in "$Name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 90 -sha256 `
            -extfile "$Name.ext" -out "$Name.crt"
        # a base da CA precisa conhecer o certificado para conseguir revogá-lo depois
        $serial = (openssl x509 -in "$Name.crt" -noout -serial).Split("=")[1]
        $expiry = (Get-Date).ToUniversalTime().AddDays(90).ToString("yyMMddHHmmss") + "Z"
        Add-Content -Path index.txt -Value "V`t$expiry`t`t$serial`tunknown`t/CN=$Name" -Encoding ascii
    }

    # Broker: SAN obrigatório (clientes verificam o hostname: localhost no host, mosquitto na rede do compose)
    New-LeafCert "broker" "subjectAltName=DNS:localhost,DNS:mosquitto`nextendedKeyUsage=serverAuth"
    New-LeafCert "ingestion-service" "extendedKeyUsage=clientAuth"
    New-LeafCert $DeviceId "extendedKeyUsage=clientAuth"

    openssl ca -config ca.cnf -gencrl -keyfile ca.key -cert ca.crt -out crl.pem
    Remove-Item *.csr
    Write-Host "PKI gerada em iot/certs (pasta ignorada pelo git)."
}
finally {
    Pop-Location
}
