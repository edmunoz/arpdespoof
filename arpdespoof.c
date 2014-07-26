//Librerias
#include <stdio.h>
#include <stdlib.h>
//Declaracion de funciones
void resumenTeorico();
void encabezado();
void arpdespoof();
void antiscan();

int main()
{
	int opcion;
	encabezado();
	printf(" MENÚ\n");
	printf("  1) ARP SPOOFING\n");
	printf("  2) ANTI SCAN\n");
	printf("  3) RESUMEN TEÓRICO\n");
	printf("  4) SALIR\n");	
	printf("  ELIJA UNA OPCIÓN :");
	scanf("%d",&opcion);
	switch(opcion){
		case 1:
			arpdespoof();
			break;
		case 2:			
			antiscan();
			break;
		case 3:
			resumenTeorico();
			break;
		case 4:
			return 0;
			break;			
		default:
			printf("Ha ingresado un numero no valido\n");
			break;
	}

	return 0;
}

int validacion(){

}

void arpdespoof(){

}

void antiscan(){

}


void encabezado(){
	printf("\n\n");
	printf("           ESCUELA SUPERIOR POLITÉCNICA DEL LITORAL (ESPOL)\n");
	printf("      FACULTAS DE INGENIERÍA EN ELECTRONICA Y COMPUTACIÓN (FIEC)\n");
	printf("                       REDES DE COMPUTADORES\n");
	printf("                 I TÉRMINO, AÑO LECTIVO 2014-2015\n");
	printf("                         PROYECTO FINAL\n");
	printf("-INTEGRANTES:\n");
	printf("  *ESTEBAN MUÑOZ GUEVARA.\n  *JOSE VÉLEZ GÓMEZ.\n  *ERICK VARELA BENAVIDEZ.\n");
	printf("-PROFESOR:\n");
	printf("  *MSC. CARLOS MERA GÓMEZ.\n");
}

void resumenTeorico(){
	//Paquete ARP
	printf("\n******************* PAQUETE ARP ***********************\n\n");
	printf("<------------------------32bits----------------------->\n");
	printf("<----8bits----><----8bits----><---------16bits-------->\n");
	printf("|______________|______________|_______________________|\n");
	printf("|     TIPO DE HARDWARE        |   TIPO DE PROTOCOLO   |\n");	
	printf("|_____________________________________________________|\n");
	printf("| LONGITUD     |   LONGITUD   |     OPERACIÓN         |\n");	
	printf("| HARDWARE     | DEL PROTOCOLO| PETICIÓN 1,RESPUESTA 2|\n");	
	printf("|______________|______________|_______________________|\n");
	printf("|      		DIRECCIÓN HARDWARE DEL EMISOR         |\n");	
	printf("| 	    (POR EJEMPLO, 6 BYTES PARA ETHERNET)      |\n");	
	printf("|_____________________________________________________|\n");
	printf("|      		DIRECCIÓN PROTOCOLO DEL EMISOR        |\n");	
	printf("| 		    (POR EJEMPLO, 4 BYTES PARA IP)    |\n");	
	printf("|_____________________________________________________|\n");
	printf("|      		DIRECCIÓN HARDWARE DEL DESTINO        |\n");	
	printf("| 	    (POR EJEMPLO, 6 BYTES PARA ETHERNET)      |\n");	
	printf("|_____________________________________________________|\n");
	printf("|      		DIRECCIÓN PROTOCOLO DEL DESTINO       |\n");	
	printf("| 		    (POR EJEMPLO, 6 BYTES PARA IP)    |\n");	
	printf("|_____________________________________________________|\n");	


	printf("ENCAPSULAMIENTO DE UN PAQUETE ARP\n");	
	printf("DATOS -> PAQUETE DE PETICIÓN O RESPUESTA ARP\n");
	printf(" _____________________________________________________________________________\n");
	printf("|            |           |           |          |                    |        |\n");
	printf("|  PREÁNGULO | DIRECCIÓN | DIRECCIÓN |   TIPO   |        DATOS       |  CRC   |\n");
	printf("|    Y SFD   |  DESTINO  |  ORIGEN   | (0x0806) |                    |        |\n");
	printf("|____________|___________|___________|__________|____________________|________|\n");
	

}



