arpdespoof
==========

    Escuela Superior Politécnica del Litoral(ESPOL)
Facultad de Ingeniería en Electronica y Computación (FIEC)
                Redes de Computadores
          I Término, año lectivo 2014-2015
                  Proyecto Final
                    arpdespoof
                     antiscan
  Integrantes:
    Esteban Muñoz Guevara.
    Jose Vélez Gómez.
    Erick Varela Benavidez.
  Profesor:
    MSc. Carlos Mera Gómez. 
  Descripcion del proyecto:
    Parte 1
      Usted debe implementar una herramienta, la cual detecta ataques ARP spoofing. 
      La herramienta hace sniffing de la red (o lee desde un archivo pcap que contiene un tráfico de red) buscando el
      tráfico ARP. Detecta un ataque cuando identifica que una solicitud ARP, en un intervalo de tiempo dado
      (configurable por el usuario), recibe múltiples respuestas que son diferentes entre sí.
    Parte 2
      Usted debe implementar una herramienta, que impide un ICMP-based scanning. En particular,la herramienta debe simular 
      un host no existente, llamado target, tanto a nivel Ethernet como a nivel IP. Cuando el intruso envía un mensaje 
      ICMP echo request al target (para verificar si está arriba), la herramienta genera el respectivo ICMP echo reply, 
      de esta manera confunde al intruso en su intento de ataque.
      Note que usted deberá hacer spoofing tanto a mensajes ICMP, como a paquetes ARP que son necesarios para
      simular la presencia del host target.                
