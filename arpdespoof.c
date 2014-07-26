#include <stdio.h>
void resumenTeorico();

int main()
{
	int opcion;
	printf("\t\tRESDES DE COMPUTADORES\n");
	printf("I TÉRMINO, AÑO LECTIVO 2014-2015\n");
	printf("PROYECTO FINAL \n ARP SPOOFING\n");
	printf("INTEGRANTES:\n");
	printf("ESTEBAN MUÑOZ GUEVARA \nJOSE VELEZ GOMEZ \nERICK VARELA BENAVIDEZ \n");
	printf("Menu\n");
	printf("1. Sumar\n");
	printf("2. Restar\n");
	printf("3. RESUMEN TEORICO\n");
	scanf("%d",&opcion);
	switch(opcion){
		case 1:
			printf("\n");
			break;
		case 2:			
			printf("\n");
			break;
		case 3:
			resumenTeorico();
			break;
		default:
			printf("Ha ingresado un numero no valido\n");
			break;
	}

	return 0;


}
void menu(){

}

void resumenTeorico(){
	//Paquete ARP
	printf("******************* PAQUETE ARP ***********************\n\n");
	printf("<------------------------32bits----------------------->\n");
	printf("<----8bits----><----8bits----><---------16bits-------->\n");
	printf("|______________|______________|_______________________|\n");
	printf("|     TIPO DE HARDWARE        |   TIPO DE PROTOCOLO   |\n");	
	printf("|_____________________________________________________|\n");
	printf("| LONGITUD     |   LONGITUD   |     OPERACIÓN         |\n");	
	printf("| HARDWARE     | DEL PROTOCOLO| PETICIÓN 1,RESPUESTA 2|\n");	
	printf("|______________|______________|_______________________|\n");
	printf("|      		DIRECCIÓN HARDWARE DEL EMISOR             |\n");	
	printf("| 	    (POR EJEMPLO, 6 BYTES PARA ETHERNET)		  |\n");	
	printf("|_____________________________________________________|\n");
	printf("|      		DIRECCIÓN PROTOCOLO DEL EMISOR            |\n");	
	printf("| 		    (POR EJEMPLO, 4 BYTES PARA IP)      	  |\n");	
	printf("|_____________________________________________________|\n");
	printf("|      		DIRECCIÓN HARDWARE DEL DESTINO            |\n");	
	printf("| 	    (POR EJEMPLO, 6 BYTES PARA ETHERNET)     	  |\n");	
	printf("|_____________________________________________________|\n");
	printf("|      		DIRECCIÓN PROTOCOLO DEL DESTINO           |\n");	
	printf("| 		    (POR EJEMPLO, 6 BYTES PARA IP)     	      |\n");	
	printf("|_____________________________________________________|\n");	



	printf("ENCAPSULAMIENTO DE UN PAQUETE ARP\n");	
	printf(" _____________________________________________________________________________\n");
	printf("|            |           |           |          |                    |        |\n");
	printf("|  PREÁNGULO | DIRECCIÓN | DIRECCIÓN |   TIPO   |        DATOS       |  CRC   |\n");
	printf("|    Y SFD   |  DESTINO  |  ORIGEN   | (0x0806) |                    |        |\n");
	printf("|____________|___________|___________|__________|____________________|________|\n");
	printf("DATOS -> PAQUETE DE PETICIÓN O RESPUESTA ARP\n");

}



