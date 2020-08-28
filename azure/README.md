# FORTANIX SELF-DEFENDING KMS-AZURE BRING YOUR OWN KEY (BYOK) PLUGIN
---

## Short Description

This plugin implements the Bring your own key (BYOK) model for Azure cloud. Using this plugin you can keep your key inside Fortanix Self-Defending KMS and use BYOK features of Azure key vault.

## Introduction

The cloud services provide many advantages but the major disadvantage of cloud providers has been security because physically your data resides with the cloud provider. To keep data secure in a cloud provider environment, enterprises use encryption. So securing their encryption keys become significantly important. Bring Your Own Key (BYOK) allows enterprises to encrypt their data and retain control and management of their encryption keys. This plugin provides an implementation to use the Azure cloud BYOK model.

## Requirenment 

- Fortanix Self-Defending KMS Version >= 3.17.1330 

## Use cases

The plugin can be used to

- Push Fortanix Self-Defending KMS key in Azure key vault
- List Azure BYOK key
- Rotate key in Fortanix Self-Defending KMS and corresponding key in Azure key vault
- Delete key in Fortanix Self-Defending KMS and corresponding key in Azure key vault
- Backup Azure key vault key
- Recover Azure key vault key
- Restore Azure key vault key
- Purge Azure key vault key

## Setup

- Log in to https://portal.azure.com/
- Register an app in Azure cloud (Note down the Application (client) ID, Directory (tenant) ID, and client secret of this app). We will configure this information in Fortanix Self-Defending KMS.
- Create a Key vault in Azure
- Add the above app in the `Access Policy` of the above key vault

## Input/Output JSON object format

### Configure operation

This operation configures Azure app credential in Fortanix Self-Defending KMS and returns a UUID. You need to pass this UUID for other operations. This is a one time process.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `configure`.
* `tenant_id`: Azure tenant ID
* `client_id`: Azure app ID or client ID
* `client_secret`: Azure app secret

#### Example

Input JSON
```
{ 
   "operation": "configure",
   "tenant_id": "de7becae...88ae6",
   "client_id": "f8d7741...6abb6",
   "client_secret": "SvU...5"
}
```

Output JSON
```
{
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

### Create Key operation

This operation will create an RSA key in Fortanix Self-Defending KMS and in Azure key vault and return a key ID.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `create`.
* `key_name`: Name of the key
* `key_vault`: Azure key vault name
* `exp`: Key expiration time. Accepted format is Unix time.
* `secret_id`: The response of `configuration` operation. 

#### Example

Input JSON
```
{
  "operation": "create",
  "key_name": "test-key",
  "key_vault": "test-keyvault",
  "exp": 1596240000,
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON
```
{
  "result": {
    "attributes": {
      "recoveryLevel": "Recoverable+Purgeable",
      "updated": 1593587162,
      "exp": 1596240000,
      "enabled": true,
      "created": 1593587161
    },
    "tags": {
      "KMS": "SDKMS",
      "KeyType": "BYOK"
    },
    "key": {
      "kid": "https://test-keyvault.vault.azure.net/keys/test-key/12860b1156e448dda3a5a3fba9b19a4d",
      "key_ops": [
        "sign",
        "verify"
      ],
      "n": "AOWMCffn25U5JFX7M8zW-ncjOOaVuVPBFSI6Ae_N6Nl9Uzn_2Y_DfJX4gjaPRNcercZ8Fib7WzF_UwZPU486D7lqB8_YxP8F9WyM8cOYgT1KL4KdRh-6-dstQ9MmVp06FmvV2E8T7njY-Ds218gHW4eXA4UWeu2GXrClKmD7ADkD",
      "e": "AQAB",
      "kty": "RSA"
    }
  }
}
```

#### List Key operation

This operation will list all the BYOK keys from azure.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `list`.
* `key_name`: Name of the key
* `key_vault`: Azure key vault name
* `secret_id`: The response of `configuration` operation. 

#### Example

Input JSON
```
{
  "operation": "list",
  "key_vault": "test-keyvault",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON
```
{
  "result": {
    "value": [
      {
        "attributes": {
          "recoveryLevel": "Recoverable+Purgeable",
          "enabled": true,
          "updated": 1593587162,
          "created": 1593587161,
          "exp": 1596240000
        },
        "kid": "https://test-keyvault.vault.azure.net/keys/test-key",
        "tags": {
          "KMS": "SDKMS",
          "KeyType": "BYOK"
        }
      }
    ],
    "nextLink": null
  }
}
```

### Rotate Key operation

This operation will rotate a key in Fortanix Self-Defending KMS as well as Azure key vault.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `rotate`.
* `key_name`: Name of the key
* `key_vault`: Azure key vault name
* `secret_id`: The response of `configuration` operation. 

#### Example

Input JSON
```
{
  "operation": "rotate",
  "key_name": "test-key",
  "key_vault": "test-keyvault",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON
```
{
  "result": {
    "key": {
      "kid": "https://test-keyvault.vault.azure.net/keys/test-key/e71e5af81eaa4cbd85674d8b7a76d065",
      "e": "AQAB",
      "kty": "RSA",
      "n": "AL2b7tdZzZugFJI3mRS39h_6x9hh4XKJ3W3UrbwFtA9bZ7kEfGWIyE1IJWQX5KGkW26WkYiAABvx1bU4J7lO1TFkVjvHYRr5cC5eAySBGC1yaxrZ-3SguE7R33EF54ja3doeqapnkCM6GK2RuhIsT4Spz3cm9P0dfknz3DapON-7",
      "key_ops": [
        "encrypt",
        "decrypt",
        "sign",
        "verify",
        "wrapKey",
        "unwrapKey"
      ]
    },
    "attributes": {
      "enabled": true,
      "recoveryLevel": "Recoverable+Purgeable",
      "created": 1593587492,
      "updated": 1593587492
    },
    "tags": {
      "KMS": "SDKMS",
      "KeyType": "BYOK"
    }
  }
}
```


### Backup Key operation

This operation will return encrypted Azure key vault key.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `backup`.
* `key_name`: Name of the key
* `key_vault`: Azure key vault name
* `secret_id`: The response of `configuration` operation. 

#### Example

Input JSON
```
{
  "operation": "backup",
  "key_name": "test-key",
  "key_vault": "test-keyvault",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON
```
{
  "result": {
    "activation_date": "20200814T075259Z",
    "key_ops": [
      "EXPORT"
    ],
    "created_at": "20200814T075259Z",
    "acct_id": "d97b7540-052d-422b-a6a9-017517f221e9",
    "origin": "External",
    "key_size": 75000,
    "compliant_with_policies": true,
    "public_only": false,
    "enabled": true,
    "obj_type": "OPAQUE",
    "value": "JkF6dXJlS2V5VmF1bHRLZXlCYWNrdXBWMS5taWNyb3NvZnQuY29tZXlKcmFXUWlPaUkwTXpnMVlqQTNZaTFrTlRRM0xUUXlaVFV0WVdVNVpTMDJNVEJrWXpNNVpHWmhaamdpTENKaGJHY2lPaUpTVTBFdFQwRkZVQ0lzSW1WdVl5STZJa0V5TlRaRFFrTXRTRk0xTVRJaWZRLnVHUzdEaWtOa1BzZ3dqb1lmYnltYl9NVnM1elpOZERzR1E2STdJVEx1Uy1IbHd1UXpoYkw5NjBfRzV6a1o5MkY0NnppV1FSWVJDS2ZCY3IyRWpoXzFkRGlkOTFQN3M5QVdNNlZsNlVHSEk2bjJ0Q3R0djlDRkw1U2trSm5YeDNkZllHcEVBY1c4amlrYUlVendBMjc3OFVBa1NlZDY1S2VYUXhWR0poenlOX1hPZVgwRWZtSlZnaUZrSmRrM1k2SmFmRzBjWTdTZnItajZXZzd1UHVOT1NPZW1Lb25pTW1nWDRjeUNpSnRvQzFVNG96eDk0UUdQblhETXl4T2VYVlFOeXl6cUotZndyQldMUUZUdFN5bmNlYnJGRGdwc2plcGVuWVhQbnkxUU1qVXN6MXlEOUpqRjgxdXcxUDZnNVl3LThyckg5ckVhY3phQUNpUzRKNzVIQS5PbHhKakZTZDdIWXRtX0dUdnFPY1N3LkNQVThTRjZUZDI1Q0oxNnZEQ3dQOVdJczF1bTNKYkpadTQwRFdPZE1ibzJDdEM4aVVzdk9FSE9BemI3WHFkOXJTSThSNERuTG5maEVnSHRfMnZkcUV6OXBUY2pldlhuRnBkbGdfMDdsc2xScDdJNGZEcm94LVhlOU9nMXhWRjZkd3JqUjdpWE9URTVFZjVvYnk2Ums0NkJSZG1TNHV3S3U1Wk9KLWVKQnR0WmFNckgzVmdqbkowUFpnaThFQ1NWOEN1ZFE5R3dvX1Z3R1FhTHZjYVhnNWR6SkNYdlk4dkY0eU5wZnloYWY5RnVtLVFLYzNrYnNsTjhKR19vMFNjZFdKdWh2d2JIc0VRQW9zZ3JFQlJHQ2tjcG12U0xJd1Fja3pUTmVmemJOTGwzZXVXY3JJZzgwSmM1VkdfSFRGN3VDNXV1Ry13UnVfblhUZ0hPNFFWVnVPempZMmgwZ3djdjk3TVZSWjg5OXA0NFM2ZDhZNUJZNXJmbkhvUXh4U0Q2cGJtbThxcGdwdDV6cmd6VUtKaFNNRWZ1X2xpOE5nM0ctVXFLSlZ6alFmUmw5OHlLbGdPUi05VW5DbnZGUEtKYzN3RmFhWlVhV09hR01USEoyeXkyWGJJcEwycGJCUTEtRURHNmFkZERwYi1sNEU5Z0RpVlZvQkVGVVVwbzNwQWNES3N0bEloSWQxNzlBMUhjQ0h3cFFYeEVTb3E3aUpOUkJvbmg3cmtoU2hVQjFfR050U3RaemtBOXF1Q3B5U0twNXhOcEFZdlJaOXlod2JhZzZfSkJMZXRiT3ZIVmtQT1lqSTFheFlVWm9YMGhaRHZFc2lFcHVoNjJGUDNqc3ZDMGFQRUFNdjhhb0ZXQ1h0UF9VYlp6NE1xZC1mbnA2S09YYlNBeDVDTDR1emloTHI4RndUZkxCMXhxSlEwR0cxNG9qSnlCQ2M5WjhmN3NrcmFOWlpXNU5wRkRSdU0zTWZCUmQxU3N5Z0xuNXZkZnlRajFtXy0xTUtpY0lQSDJROWQ3eVhNWnE4N0lJMDBlNnczVVFIUGxUd25WUnNWSDFkRGg0TWhvdGdkakRqWC0tbGhGMmhCZTVFbHgycURkN3FEM05TTGNnVFRnSW9JRXhWMkg5OHNpUVBjeHc2RDIyYzZfTndtYlNtLU9XeGhaLUVZSkJ4c25NQjV0UFNWTkUxY2dGZnBRSE5KN1R3bVA0T2JCV1dmR2VDZjlEbU1DOXJuVi1GX2k1RTMzWUhpXzNVbWdEM29aZXhDOHJjVmFPbGdtc3pWQnUySVR2aEJabXc0S3ZKc2MzeTYwSDB3N1RSbzNFWXpTbnpmWVc0ajQtOU9GRmljMjU1SzFzdURVbmpkLU81alJkd3NaNk4yOU16MWFFeS1uTTdiTm1aNl9TQ0NxMFJLdi14MVhfVW5TQUNIVGJNVUFNTFhHNkhRaVlYZGtqUHNtMk9YTUF1cXB1VDBqWUJsTWVmMEIweEJQVE5QWXlxcG5DRXRxcmRIWTBxdER5TzRQTmU2dHpOYWxUSTBPVk1qN2NZTmhxQ3pqQW14OEk0QTd2TkcwMlR2TE9sSVlTZXVTN2R4dHFUemtPNVEwaVJxMVVwdUFJemJjOElwV1EzZkU4eDZva1ZJOHBWZFpocGcwbF8xakxCNE5FZExMMlFOVEVSZUtyUzc0SDlONE1hTFlEY0VtU2JScTFVM3JZQTNhZy1JNGxaQXEzVmNjdHp2WVZnY1l3MGM3U1E3NEo0eWd4OERYZDA5S00yMmpiZHdvYkRyWms4Y3I5aTJkd3lfRzlEU2d3XzZOSS1wbklDVGtkVU9IdlN3b0w4R01JYmd5LTl0UGtwSE9CRXBDaHFzaUpVRXU1VG05b0lwM0wtR0FzeTVjZ0ZHMmxUV1R3dGlzRUU4aXZsNlNXWjVVSHMzZ2JKTjcxUExMbkw5cUlneW5Zem1YckdvSkdkT1lkZnVqVWthT3RCNmJSWWpnZnVJSlZoN3lSUVlfOVpJVGczVEZTMTlFYzFNOVR1WVlaZzU3ZjhHWEJUXzFMSkZDd09JMmJ1SEh1cDNiYU9XbWhLWEswVm1NNGF0OXp5SzJiS21oSHRVLWNLb3VudEtUTVVtTmFNU05ObnJGRzlmZ0FiLVNMTjJROHBwZnpGOFJYajlTM0lIVmJfSldFNmY4dng0MDRvY1R2VEpUZFpvWGxwamtKdjd1d3Q0QVZldVhmZ1VqT0c0dkk2SmZMTnJMNEVhU0pEQmViR2Fnc0xXOHlkR2F0dnRnem9zYXpRUUhydWdKS2U2a2IxRWNtSEZCcDh2azlqWGtSY1JsekVZSktCMVdGejRvYmhPTllLbEp1YlF3Y3Z1Q0xqM1NmVDBVMldYSFhJWjNMQU5UczJkekFabWNXaEwtbTVUdWpsR1BQUXg3aVgtVXlSZWhPc1BEVXA5WnFYVmdQV1ZWOVdNOHlXeVpRTmx2MGxkdml3aHljd0hSTElEX25lcEg3NlBSeThiWUlGWUZGRHh0dXNadjlqRXA2d19YQWZiQzNRNzctaWRGQ24yaUxLbHZGbkdiVGxCajd3RlFJaDVLaWFEX0JDOW9hVGJTZE5jajVPNmRtMG5QVFB4T3pNTEt3clNxSHF3dWY4Um9SZVg5d1VDR3hmWE5jNkF3UjhheHJwWXlQUmhZZUJxdWtRSFFaYVFQclhMYkNWNUZxblRNM2tsUm8zNHJ5R1hHMnBweDFKNldBWmRFc084d2x2U3NUUjU5S3h4Q2FKMEExckJQblFxUUNsR1ZnZ0dsM3VjRjBDdTItdXBGTWtleGRTOWJ3T3gxZDN6SFJncmtWVks4eE9XRGNvMl80OWpHVnlGT1hQQkI2a0hPcWR2d28tYXRKTDFZUmFTSUEtbkxPbmF5bXBsMlZzZDhrd2lnQ21SV2R4a1FUME9kSFBSQUtZbFBKNkREU3RubVBIeWFpWDlCbUZ0TVh2cWNMeG1mdE4yTzBaZ09mdUV3bkRXZFNUdGhCVUxSNjd6czJkZExwXzYwSVlNSEpRZDFsSHQxbl93akV6TFlOU253T2NGdG1xQkQ0T05ib3lmWGNtVEhwc0c5T1l1SC1uODVNMWF3UEFRaGRZWURWY2lOdTJhRlRPYXcyM0FSbXNYQTNtQlpjNU1LcS1rZ2N6R1VnMlIyTjQzbUVVZFpoWXV6Y3NMSEhkdXA5Z092N19iZk5rcmxMWEl6Z3NoMERRMjZHTnhVNHd4aUZGRms3a09xYV8tR1NOcWRDejdfUUl1QUFiaXhZd29MZU1rRXllVHVzZnN2b2tjMURUTUJGT2otSkx3VGdiVzZFcHhZeldZTDVNZzFhc1ZjRTBncVhUSnlSSHJhWE85RjRMMTNNclQ3TThSTnJEQy1Td2pkLUhzdWVpamVYbmVLSTREOTlEUUhGUnpVVmFWNUNuT3BHSktYOUtELTR0T0g5eS1HdHIzQ3VTWkhXRjRxeFFPYURTWFBrYm1idTJ5NGoxcHQ0VnIyWERJd2IxeGphdVVtLXVvUDJickg0a0Rkbm9wS0MyZmNfdVpwR1VCcEpfMDJNM0NSajVGQ1F5UFpQUTMwdlpybFllaE9RZnNSOHJ0c0phSnUzWDRNUTFRX0JLeGotNWlXbGNjMHJEVDUwYWNkN096elZtREI4RDg0QlNKdmwxNjFQeUxUN0FjcURRODNOZUFoX2RCeE5MQV80WklPMUlTc2Z0d0VjMlRNNDlMWXJ3NDhia2hTTU1qWjF0T0lrMEs4R3JOYzVPM2V6VDYtTUVPWnZralctV2F5N215aHJ5V0Rxc2ZCaTc1bTQwbm1qUUFMeEVBZ3ZMRUs5M29GbmJpY1l3NlpNNmJ5V0ptUkpucmxjNldpOW9DbWkxTFhCTlRIQndhMFFJSURvcXFHSTlmdGE5Qld4WE81VWQ5RXVlZkE5blNNUWw5WVZQa0szejVJeTd4TEQtY2NReHZyYUFrYi0ybHNkUVpJbDVGYzJFRjBUTVlBT3RSMWJBMXZXU2tEblkxNXg4bnpoZVFLTmUzdk5FMHhvWXp2Nnh0TldrV0pjU3NzUkw3Mmp0UnAtajh4OEZIaGhGQ0VvVGRsVTB5RnUxcXdmQjdfXzkzeTMyWUhSZ1V3dTFVUWZIMklLYnZVbjhZN2pkTDNSX0xUUEQ2d1JIS3l4SzNQajFNbi1YaFEzTW9SZFJIQ09xN2w3djVoVllhZF95SnpjMUhVcGxjSTVvb0VBUkU1TW1rSl9abm9sbmZ3aEVPZFB6TTFXVXRYMl84SzFoNHlGRUNaNThWdHRyaG42NTVrXy1MTHNoYk1KUVNKT2tkLTd2YS1od1R1eFliRHd6NElwVTZqRUo5eU5fSHdYQy1wemdCTkRkbXNYOTJndnI2MjFtZ1p6UTgyQmRjWHM1MWhNMHhfWUl4WkkyUVctTk5nNVNWNG1KNVdsbWFjcEYwNUFxUnFST2JLbndpNEthMmhFUWg4TWhDcDB5VDVCc0Y1V1pCOVNRWW5vVERCcHEyamYtNGRIeUIzUkFFNktwODdKbE9STE5TaFFqcEwyVzgzRV93RWRuOVdDaGpyTG96bnhVbUttRXp1alE1VG9rNE1yZ1VwdjZHdlBVbm9PWVdHV2pEZ3BGZTlxYmtWcUpQZGpiUkNIUkczTEQ1OXZOMFVIaml5U0FxcXJzQ2RMSXVJdzRWcVZNa3ZjQS1ROEhfNjBwMDBfNWZld29EeWc4NHpkVlNqeW95cjZ1ZlZWa3kyMjBLQnhnQ3h0OFhRUlNONDN1Yk1ZV3lmUXFXTUN2MmxKQkhIMklJblZPQTY2QVAyX1ktZ2NwcTBqQzJNLUE0YUx0LWVDLU4wazRTdWRZQUFxejhHWDVvMUZnVkZXbjFLQXB6N1RwaTJQcnUzOEY5aFJGaHRacTRHVWpCeVp5M1E2QlpEVkxBNG5UN09Ka19DUFVOZ1pXY25RdTFIUW1za2JQczRiRkk5Mnh0Z2R4N1hfZlNQajB1RnAxNzBzYlBHTk1Db0NBQlRXSFBfRjNLMlJObjdrS3ZDRWVqMnRLMGZRcUZjWWVLa1piWGxpUzVGN2d3dWFkLWhxdFg4SmlNNmVqcnlTeEFGRGREYTNwWG8zX3NBbVhIaHZqUDlfbzBNNVNoV0k3OFVMUTY0V0pIVTAyZWhuTVFDdGlIUDg5RkZWRE5QaXhJRm9wdEdrY2FnNkl5QjFHbDZaMGVtOUdURVU0YndZODZ3Z2l0dThEaER0ZmhxemJUSXpKeENkTGxwTWVjQk9EVEFNTmZmUXR2am15STBSR3NXLTFzZDBKNzBKcmR4aldQSVNhN3h3V0E1cVZreEllMzZlQ3Jkb0JDQTlTeThDWEVIaFJXS3J4QXNwb2k5UWc5WjRnR0RsdDVlTGdpYk9UNnNDWTdpcFlZT29NVlI3RS15Vk9ydUJDemF1d1BBMXhqRFRsNTRwNGo2ZFhoTkZNVmJhQlRseGtyUmJUeGlYSkNEYlA0ZWpxWHpkTmEzOFU1LXRQdW5Bb3p4TFRwZnBrQ3pReUF0SnZfM3liZ19QeTV0d015MHhzLVE5c3pMUXpQS010VHZsNjc4VXJ5VUhwVFgxUmp5RFVKN2p3R3NNdEt5ZXVIdWlpaEx3N2VieDF1QUxNeUxQV2Zmc3FhcjBCRnpGdS1lMTlPM0d4R0ozMm9iNFBDd3VUVWROYVRtWUJmaTdqMmNHNGY1LWk0SlQ5UDQwNmd3cTUzcWdwSUtGSWlTME1SLTJ1MzRXXzRVdjNVVTUtSGNkekg5bjlIMVpxTGdINlVmSW5pTDU4b2RMX0dxc3dEUFE5SGdUZDRyemxHLWFqOWMyUHI3XzJYbGptSjdQcWlzck5TYklmVzBESFliZ05vY1ctRm00X3lUcUpMMkpJc0NCWFVwcV9nZUlObTFpalIyRW5mMmJUaThyUG1SVXk4cEtfcXdOTkhrVk9OWl9tQjBfYTBCOFpLOHcyZ1VwbTk0ZWxPTHloWFhKb1pmQ2hiM3I4QnNvZDRzc2twQVVlYXUtTGZMSDRFOVBzTjRNd1ZhWXpycHItTGtlYy1XUVlWLXpxOG1rN0xsd3dTdnVhNnliWHBJWGRmM0ZpVDVqT3c4WlVZN2ZSSG5nU1dBNGdPSC1jQ3pxdVRveS1SLVBZZnE4WktHWUZjWE1XVWlBVzRXbTZidkhZemFXMUN2RVlITkt5SVpfZGJzNjBRY2pTUmdDMzhfdmw4emNIU1I5NEJUYUlES3hBcm5ncy05RVUxVC1KaG9zODJMV3NsN0I2dlV2dGlsZXZEOXI5bnRpM2IzY3BlM3hHYXliWkxYLTRaa3BFSXJraWV2TC0zcnBNSzBhQk4wbWE2dGViOUJlNldWSVJqSFdRa0x4dkNFc2xSVlItWTVSR0VjUUdPN0h6bmRxT2dKSE1ncEZjUXI2QW4yMHZBc2FmZ1ltYVFNdi13REZlZWlNZWdGUFloNENpcU1STmcyUXRuSzJHdDlLTmFYZFQ0NnU2LTBBanlpLXlmLVg5Y1d0U0ZsSUVaU2JOcWJldHptUGZ0OHNXTEV1OWZoZzZLZzdwRDdiZlYzNVZxdE1McENGYndQZHoybHREZUQ1Yl9uMFdKYnozRUlXZ095ck5zNFptdTBlU3YxOXRoMklGVmlsZ0czZmtZNklYMlBQbkxKa2dWSHNpZTRrMDdpcUFteUI5SFM1WExzbnkzZmUtTzF0cmFFRU0tS1FoRTlrdkJaYlNmWnBmQ3B0aHIxYkdLaXZZdjg3R190WlB3R3ZySTJKTG9NaHJIcURzSmhNZjNma25aTFRoZTVUQzdPbnhOdTMtbkpRa0lrR3NJLVNJZFZzTDRyV25NYW4xNWowZ0Exbmd5Z0VPQkJqUU9hR2ZtLUxYOUREVVJFYnNjQmJheGNwZHBtOHZCMU5KRTRza3psbVI3NV9yb2wwMFdDeTJ1RXZscV9pTGF1dkp0RzZoYUhjbm5oVC1XSjdNMUJZZHdpbFp6VHdkUE5PVkhBMlRjQ3U4MEhrTkZPcVMwemhha29CU09VOTBPTDBfSkltbTdHcko2V3AyRmFGTDVvQWNYUVhOTEtKc2E4dXRpcHR2SG1IbGhNYkRQRHBiMDVEWGw4cXNKMGx4TmN0NUpwclpFdDgwaWMzdC1xYWNHR0U4UFd3ZENpczUwd2pHRXZCeVgwT1dXUmt1TE5hMVAyOW9KVl9FYlFZcEMzV0hkaFNxMnFBZnRtU1FmTDlzY2k1emdCZnBBdXRsQlpWS2xJQ0UxM0FoeVdnX1RGby05bTBLVVp2cmh3ZncxWlpobWZZNlJsTk9aUTJ1SWl3WFpRZ0t6bnpEZFY0UnZuSjhZM2sydjNFY2wxQnBPbllGZUpyT2ZJTVhoMnFVZEdZVmxCY1RkdGFaTDROeTNzY3k1dkhHN2l5bWI3N1Z5bjdUU3RscTg3U0c2c2ZvcXdqUVRqdFVHVzh1ODhfYUpTNmpsQ3loeTFnUVNZTU5keGhvUHowV0tJU29SUW1ZWG1aVDJVTGJtUjZZZ1RJUU9YZUpUMkEzZ2RLb3NOZjZqNERCYUVFTmdwODZGVk1DQ1c2Z2h5TS1VRmZuSU54WVhqZHZoQmZfOXJTRDI5bFRWRzNGeEktdkR4cHhKd094dmFxNUpMUjVrdmpuRXE1Z29zYzM2eGZKakFyU2NNTng0ajFmajUxNEdtNnZBcVhoMXBsb2lXS3NoVkNwaW1OSS1nQWxJVEJidGlDc2lINWFURVltdEp4U0ZrSUhhaHJzOG1GZWY4Nmhjc2tCc3N2UWhmazlRaFhPbGpJalpETzBJbm5EUUpEcnhnZzZqUzc3UlhGNUM4eGpZNGtEMVFiV2o2bUJweS1HMi1RU0pqcmtWZURYUkFHSDdsU3QxUHM5ajlLZGF1NWtfQ2ZPSEFvbkU0dFBadVV0ZDBxTzY3a2ZoNmozN1lweHV1MU16VnJQem9aS2tpenZuS2pTNmRZZThPZnExZlZHU01qbWd6R1hyRENFeDhjZEIwc1B2Qnh3VHVWczRPc3ZNNWlteEg5X0FyQnRNTGY0ckJoZUJkOVRiVkpjZ1Y3aVlWMlhDTi1wdVRSTVkwRzJmUDd0azR3a1J1OUdhLUkyd2JVcHFhcTdBdkhXSnpYa3FNZlM3N3B1ODM3RGJZWWtWODE2U2FIU2lnMEdPX0RhcEFrZG1PMzFrWHYxbTlYWExxMU4wMDN1NW9TTHAwSTJMcXI0NF9sLTJBZjJOQWFBbWhiYXllVzZLWms4MldpWTZnNUJGY3BPdl8ta0J6ZGJmSi1CeWU2X1lUcER3dkk0emtuZkp1M2J0RjNfckVQM3ROVFhkZ0xyMEFHay1SZklJejJ0SkR0bWE3NzNZSm9OQjJ0X1VEMGV6RXgtaTQ4QW9jbF9yLXVnOXlPbEp1bGFSVnNZQVIwOF9yMXdfVThVRjNrOXBJc3hVU1NsNUswWmEyS3FmYnJZVXlwVW40QkZuWlpQQl9QNGlWaXctTWVFTWt5c1cxR3BYamtOblhWVzc4SWFxd0ZPWWpybUJzdGszcDREM3ZUMS1MdE1hRDliUTBoTFExUWVvQ2kzQXF5amt5ejdXUlVJTmZRa2U0M2t1R09YQTBfbVhXWkFndHlwd01qY05lR3NZVDI1Y1N6cHFwMzR4eDktNnU3UjdoTGxOWElieTdZTHdoa2NlSTV1T3NmNlNpcFBwTVYtQVhQdmM3UTdQSjlZOXY3TEVUY2V6T2xyMldvdE43WHFfUjF2N0MtQjhlSFVhTjQxQTZVbkVNV2M3dEtza1gxSFBuaVNWblBFZ0dsYktRYkFibU4wdmxLZUVCQWdQQ0diZ0dCUlhQcG9kaEJpcUUtYkd0eFBkNURYMmRxakRpcnMxOFg2ZXlNanpaM3JGNU5xUFJ4aVp1TlQ3TEV0a2VaNFd3TjdRUWtrM3ZIQ1MzbkJiZUNjd1hlWHptZk4zRmVSWGxyWjBhRDVCdmNXZVllaG5aYXFQc0tEZHVxSDNhZ1F3Uk9qSXd4ckxkN2xwbkpKZk91OXFDRFl4VVhOaVdxS3BZcHk4NURrOGFqcUt5XzN3c1NRVGJQVmFmZng2R2o5cUVTc0g5QUd5dTNBVndSdXpSaElHVm5BQkF4VDBSY3lLNlVEWV8xd01vRnhyNHdVUjhPejVldUJUSTBycEtnQ1lUcG00NlhVTVA2OWFncDdXRU83QkZkNWNzOHd0SFJsbzhvVmtDN0FQTjJvak5GRXZ5NWpaX0tPbmdRYk5wUXZaZ0ZBcGFNZVI1MVRwMkRXRWp1UnZUTEVWc0xMbFV1ZVdVSVVwbTFuaDhBdkVVUkpUYzZaZjBxUExva0p5UVZ0TDFUXzRmRnlHTHlUaHphTDFiMUVkOWRqZE55YXV2WDdhT0IyMF9ONThlazNXakVfcEtaNk9paVY1bTBqMS1RenZrdDZNVWlxeXM2cnZYRlFIb2xodEYyc0JEMFRxSGhGMlE0Y3ZJWEZEdHo2dzZrNENaMmZyMVlCaThFS0xOZzRoUUIwNjZfWGtyUUM4bmE0T0VUakhxMlI5Z2xMZGVvNWZlZ2paTzk0eVJiUXpsQnRIM3Y0TG0tOS1TYXJ6Rm1fYVhlbmFZajFtTUhwMFNjZWlidy1oeHVkZkc4b0tJTk5EN2ViUG9RbnRNQ1dPbnR3LXZRWW5uUjRZQU55ZEk3aW5wY2NJNVJQUENtVmh1UFBuSVBoX2VUWFp0N1hORVY0bldyRUFmRlBGbUUzR2JYakwxV3RKZ3hxQ1E0Rk55dWFaa1ZtMnFXeVp6dlA1aUpVY3BpNExrLUhJTU1iZUQ2X25FaGJ0NHNYS096dFZ2ZDUwVUx1Wnp6M1Bsa1NBUktIUXVoQmI4US1NSzQwMFpaX1NhZkZKdEZ5QkpIckUxLVp1Z3JpbjYtX1pabk1zLUZWanJKTEtMUGNoOVg3Q2R6dGhLYXJqOEhKaTNNMTF5Z3BBU25TM3NndDRvMURtTDhCRGpnTUx6Ul9kekNPeHpRRFJhU192Nk5jbzRGbXZPUzliSS1xSHlIRWVEOGQ2cTZMbER3WlVkZFZhcE81ajl2RklHT3BSRWowLUZrbXFncVBMSkNESXBTQldQU18xVExPYkFLVnlBb1NzcXdvODlnY2ltTHhLQkFiN1EzaWNIalNrV3gwbDBGSDBwOU5hUDJoczZVT3pxUERJYXhDZjIwRFZLNGRQeVlhT3FFY2V2NVkwTmtXUU03dlNkTHJhVXVYZ2tiM3Y2NlRBZFV2cTAtZ2NGR2l6d2RrX2tldzN3am92MFloMy1PY0thdzJtTW5kSVJoWnBpRG9UcjdIX3ZQSWs5Q1Q5TlFyMDViVm5TOERaQU4xVHU3QzJORDU4ZzEwa21tTEFWZEhQT1FFMFYwLVFlOTNVNTdDX1hQSjZ5UlpwOV9UbTlaajlBWFRQNHZUN05sejY3clZ5SmlqUml1aVdib09VckdPWFRubjBHUmxrN0V2UlJvUHNuNXFmSU54OVNVczUybW1JaG9hTGVPWnduV3FYWjd4bmhoT0dxQldFRzNaQVpURm5kN1MzV3QtNjgwWGhoWVZCSHBIdUZfRFhrTVlkbXJhSDRUVXNaMDVJVUthOGxPbHVLWFVnT09TX2N5OWphN1F3VDUxNm1RQUFtcUI4NDdEc29ldUx6elBLdFFkckl0UkpxRHJNbHdWREtTYUV4eDItbzkwZU16RURDNTNFdzRJb1d0N3hOVks3MVEtbWpSQUY0d295WDh3TWJsWlZRSFVpSVNNNWRqdmRfTU5GeVhqTTUycDRNbDd3NlNlQndnSmxRYjdQRldiX19pZGhFRFNWY0FEdHNiLWt1UEZMOFE3T05adGc5ZkxZRzNxX3pROG4xWERIR2xjdjJDell0MnY0WUVDQ00yZ1lkelhyVktmdHJrRWxFRDZCZDNwWkdOb21lVjI1cG5VcnVxekxnamh3U1BmMmlhamgzeUd6X0NwdmRtQVEwdTY5eGNMZEhtNEpQdTZyaEh2eWRBb2lvUktOVkZqT1NwTDBRMXZPaWNuUVR0Wi1XN20xdm85N0tGZEN2OVZtS005cjRidUZLa2xvMjRac0JXaHRCYmxvQktkUmE0eE9sZTVMTHdiOUM1MnY4dm81cWxITkNKem9fTGNHcFBNM1JKNkVrdmlNRFA3cEJ3cE95ZHZRSzJDT1lSaDdBbmZYcEtMOEM0YTBKWHlueWpYRDJWdXNONWhSTVN2bDM0ZW55b09EVmRwam40bFFNRzMtZWtZOEFDV1ZnVUJLYVdueGx1SDBROHdKS19YVTJFdWZ4aDRGMEhucXN5R2oyTEphaU82dWRqdnRjTkFGTS0tN2hmQzNMMGstMFJmWVE0blNHcVpaclp6MzE0c0R2bmF1NV8wWXhPVXVBLThRZmJGZTZiWXFpeWxoU2Rza21kaGlBbzg3NW5DZXhjZnlrSVpCdnlIYXlaYVo0VXkwZDhvSE9RblNsR1p2Zm4wcVlHaV81TVhCMmFFZXp0ZmprUmYyVHVheHlYenhvYkh1LTJwT1JraTFZa2Q1TFAzX1ZTbzlnbXp3cERjdWdycHM5cHZPeFdZOGY0bU1KMThiWVM0TzBvQ0ZLa29ieFkxc0xnLWxCYmxFMU1zbllfR1cwSm14M2RLSzJUYlNoRmNGTUJPNUh1WURvcVdyM0JILUJIS0lPbHk5U0xnS25sTkZGSFUyTTFEV3pCTWhLb0pkM1hTSzZ0bndEWkpGby51dVRVYXZaQndQbHJ0VWNGWHc5LWdoZm9kaDE5b2pPbmJkX1gtUFlHMzBn",
    "lastused_at": "19700101T000000Z",
    "group_id": "929a4dab-363d-4f1c-a197-46fc8c0c1251",
    "kid": "037bef5e-9a2d-4820-b120-02b9b036996d",
    "never_exportable": false,
    "name": "B7E2D3C7D1041342",
    "state": "Active",
    "creator": {
      "plugin": "bef7866f-194b-452d-83c9-1c2bffe01a3b"
    }
  }
}
```

### Delete Key operation

This operation will delete a key in Fortanix Self-Defending KMS as well as Azure key vault.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `delete`.
* `key_name`: Name of the key
* `key_vault`: Azure key vault name
* `secret_id`: The response of `configuration` operation. 

Input JSON
```
{
  "operation": "delete",
  "key_name": "test-key",
  "key_vault": "test-keyvault",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON
```
{
  "result": {
    "scheduledPurgeDate": 1601363625,
    "tags": {
      "KMS": "SDKMS",
      "KeyType": "BYOK"
    },
    "deletedDate": 1593587625,
    "key": {
      "kid": "https://test-keyvault.vault.azure.net/keys/test-key/e71e5af81eaa4cbd85674d8b7a76d065",
      "n": "AL2b7tdZzZugFJI3mRS39h_6x9hh4XKJ3W3UrbwFtA9bZ7kEfGWIyE1IJWQX5KGkW26WkYiAABvx1bU4J7lO1TFkVjvHYRr5cC5eAySBGC1yaxrZ-3SguE7R33EF54ja3doeqapnkCM6GK2RuhIsT4Spz3cm9P0dfknz3DapON-7",
      "kty": "RSA",
      "e": "AQAB",
      "key_ops": [
        "encrypt",
        "decrypt",
        "sign",
        "verify",
        "wrapKey",
        "unwrapKey"
      ]
    },
    "attributes": {
      "enabled": true,
      "recoveryLevel": "Recoverable+Purgeable",
      "created": 1593587492,
      "updated": 1593587492
    },
    "recoveryId": "https://test-keyvault.vault.azure.net/deletedkeys/test-key"
  }
}
```

### Recover Key operation

This operation will recover a deleted key of Azure key vault.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `recover`.
* `key_name`: Name of the key
* `key_vault`: Azure key vault name
* `secret_id`: The response of `configuration` operation.

#### Example

Input JSON
```
{
  "operation": "recover",
  "key_name": "test-key",
  "key_vault": "test-keyvault",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON
```
[
  {
    "attributes": {
      "created": 1593587492,
      "recoveryLevel": "Recoverable+Purgeable",
      "enabled": true,
      "updated": 1593587492
    },
    "tags": {
      "KeyType": "BYOK",
      "KMS": "SDKMS"
    },
    "key": {
      "kty": "RSA",
      "e": "AQAB",
      "key_ops": [
        "encrypt",
        "decrypt",
        "sign",
        "verify",
        "wrapKey",
        "unwrapKey"
      ],
      "n": "AL2b7tdZzZugFJI3mRS39h_6x9hh4XKJ3W3UrbwFtA9bZ7kEfGWIyE1IJWQX5KGkW26WkYiAABvx1bU4J7lO1TFkVjvHYRr5cC5eAySBGC1yaxrZ-3SguE7R33EF54ja3doeqapnkCM6GK2RuhIsT4Spz3cm9P0dfknz3DapON-7",
      "kid": "https://test-keyvault.vault.azure.net/keys/test-key/e71e5af81eaa4cbd85674d8b7a76d065"
    }
  }
]
```

### Restore Key operation

This operation will restore a key in Azure key vault from its backup blob value.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `restore`.
* `kid`: Response `kid` of `backup` operation
* `key_vault`: Azure key vault name
* `secret_id`: The response of `configuration` operation.

#### Example

Input JSON
```
{
  "operation": "restore",
  "backup_key_name": "backup_key_name",
  "key_name": "key_name",
  "key_vault": "test-keyvault",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON
```
{
  "key": {
    "kid": "https://kv-sdk-test.vault-int.azure-int.net/keys/KeyBackupRestoreTest/d7a019f5da8843aea30722a7edcc37f7",
    "kty": "RSA",
    "key_ops": [
      "encrypt",
      "decrypt",
      "sign",
      "verify",
      "wrapKey",
      "unwrapKey"
    ],
    "n": "v6XXEveP0G4tVvtszozRrSSo6zYDOScH8YBVBBY1CR2MCXBk-iMnKgzUyePi9_ofP3AmOxXx-2AsLC8rxi6n3jQNbGtIvQ4oMdUEhWVcVkmwdl0XyOouofEmIHeSxRg6wXFG4tYAKLmKsO9HqmU5n7ebdDlYngcobc1xHsP0u8e0ltntlgWBlSthmY8AMKW9Sb_teEYhilbkvt_ALr00G_4XHmfq7hSOZePWbGSWQW6yC7__9MrlDfzaSlHyBIyLppPEB7u6Zewrl_eNJWoUVrouIGA32qNETIOr_wxXRVGKoerTt-wFC-CXPn30W_6CmKSxoFBNvnzijg5hAU9V0w",
    "e": "AQAB"
  },
  "attributes": {
    "enabled": false,
    "nbf": 1262332800,
    "exp": 1893484800,
    "created": 1493938217,
    "updated": 1493938217,
    "recoveryLevel": "Recoverable+Purgeable"
  }
}
```

### Purge Key operation

This operation will purge a key in Azure key vault.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `purge`.
* `key_name`: Name of the key
* `key_vault`: Azure key vault name
* `secret_id`: The response of `configuration` operation.

#### Example

Input JSON
```
{
  "operation": "purge",
  "key_name": "test-key",
  "key_vault": "test-keyvault",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON

```
{
  "body": "",
  "headers": {
    "X-Content-Type-Options": "nosniff",
    "Date": "Fri, 14 Aug 2020 08:01:39 GMT",
    "Strict-Transport-Security": "max-age=31536000;includeSubDomains",
    "x-ms-request-id": "e9851042-6210-474d-b9b0-706f600aa5d4",
    "Pragma": "no-cache",
    "x-ms-keyvault-service-version": "1.1.31.4",
    "Expires": "-1",
    "Cache-Control": "no-cache",
    "x-ms-keyvault-network-info": "conn_type=Ipv4;addr=216.218.139.205;act_addr_fam=InterNetwork;",
    "X-AspNet-Version": "4.0.30319",
    "X-Powered-By": "ASP.NET",
    "x-ms-keyvault-region": "eastus"
  },
  "status": 204
}
```

## References
- [Azure BYOK](https://docs.microsoft.com/en-us/azure/information-protection/byok-price-restrictions)

## Release Notes
 Initial release
