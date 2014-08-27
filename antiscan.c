//Librerias
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
//Declaracion de funciones
void resumenTeorico();
void encabezado();
void antiscan();
void imprimirICMP(int count, const struct pcap_pkthdr* pkthdr,const u_char* packet);

pcap_t* descr;
int main()
{
	int opcion;
	do{
		system("clear");
		encabezado();
		printf("\t\t\t\t\t MENÚ\n");
		printf("\t\t\t\t  1) ANTI SCAN\n");
		printf("\t\t\t\t  2) RESUMEN TEÓRICO\n");
		printf("\t\t\t\t  3) SALIR\n");	
		printf("\t\t\t\t  ELIJA UNA OPCIÓN :");
		scanf("%d",&opcion);
	}while(opcion>3);
	
	switch(opcion){
		case 1:{
			system("clear");		
			antiscan();
		}
			break;
		case 2:{
			system("clear");
			resumenTeorico();
		}
			break;			
		default:
			return 0;
			break;
	}

	return 0;
}

void imprimirICMP(int count, const struct pcap_pkthdr* pkthdr,const u_char* packet){
	u_int i;
	printf("Paquete # %i\n", count); // Show the packet number
	printf("Tamaño del Paquete: %i bytes\n", pkthdr->len);		// Muestra el tamaño en Bytes del paquete.
	if (pkthdr->len != pkthdr->caplen)		// Muestra un ṕeligro si la longitud es diferente
	    printf("Warning! Capturo size different than packet size: %i bytes\n", pkthdr->len);
	printf("Epoch Time: %li:%li segundos\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);		 // Show Epoch Time
		// loop through the packet and print it as hexidecimal representations of octets
	// We also have a function that does this similarly below: PrintData()
	for (i=0; (i < pkthdr->caplen ) ; i++){
	    if ( (i % 16) == 0) 
	       	printf("\n"); // Start printing on the next after every 16 octets
	    printf("%.2x ", packet[i]);	// Print each octet as hex (x), make sure there is always two characters (.2).
	}
	printf("\n\n");		 // Add two lines between packets
}

void antiscan(){

	srand (time(NULL));
	struct bpf_program fp;
	int opcion;
	char option[10];
	char pingIP[100] = "ping -c 1 ";
	char targetIP[40];

	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];	
	pcap_if_t *alldevsp , *device;
	char devs[100][100];
	int count = 1;

	bpf_u_int32 maskp;// mascara de subred
	bpf_u_int32 netp;	// direccion de red
	int n;

	int compiler;
	int filter;

	printf("\n\t\tANTI-SCAN\n");
	do{
		system("clear");
		printf("\n\t\t\t\tANTISCAN\n");

		printf("\t\t-i DEV,     especifica la interface de red\n");
		printf("\t\t   con la cual hacer sniff.\n");
		printf("\n\tIngrese la opcion: ");
		scanf("%s",option);

		if(strcmp(option, "-i")==0){
			printf("\t\tINTERFACES DE LA RED\n");
		    if( pcap_findalldevs( &alldevsp , errbuf) ){
		        printf("Error al econtrar dispositivos : %s" , errbuf);
		        exit(1);
		    }
		    //Print the available devices
		    printf("\n  Dispositivos habilitados son: :\n");
		    for(device = alldevsp ; device != NULL ; device = device->next){
		    	printf("\t%d. %s - %s\n" , count , device->name , device->description);
		        if(device->name != NULL){
		            strcpy(devs[count] , device->name);
		        }
		        count++;
		    }

		    printf("\tIngrese el numero del dispositivo para hacer sniff:");
		    scanf("%d" , &n);
		    printf("\tEspecifique el target a simular:  " );
		    scanf("%s",targetIP );
		    strcat(pingIP, targetIP);
		    dev = devs[n]; // Device
		    pcap_lookupnet(dev,&netp,&maskp,errbuf); //Extraemos la direccion de red y la mascara

		    descr = pcap_open_live(dev,BUFSIZ,1,10,errbuf); //Comenzamos la captura en modo promiscuo

			if (descr == NULL){
				printf("pcap_open_live(): %s\n",errbuf); 
				exit(1); 
			}
			compiler = pcap_compile(descr,&fp,"icmp",0,netp);			
			if ( compiler < 0){ //Compilamos el programa
				fprintf(stderr,"Error compilando el filtro\n"); 
				exit(1);
			}

			filter = pcap_setfilter(descr,&fp);
			if ( filter < 0 ){ //aplicamos el filtro
				fprintf(stderr,"Error aplicando el filtro\n"); 
				exit(1);
			}

			struct pcap_pkthdr *header;
			const u_char *data;
			u_int packetCount = 0;
			int returnValue;
			int repetir=0;

			
			int rango = 99-10+1;
			int n1=rand() % (rango), n2=rand() % (rango);
			int time1=rand() % (rango), time2=rand() % (rango);
			
			if(system(pingIP)){
				system("clear");
				system("clear");
				system("clear");
				printf("\n\n\t\tINTERFACES DE LA RED\n");
				printf("Paquete SIMULADO\n");
				printf("PING %s (%s) %i(%i) bytes of data.\n",targetIP,targetIP, n1,n2  );
				printf("64 bytes from %s: icmp_req=1 ttl=64 time=%i.%i\n",targetIP,time1,time2 );

				printf("\n--- %s ping statistics ---\n", targetIP );
				printf("1 packets transmitted, 1 received, 0%% packet loss, time 0ms\n" );
				printf("rtt min/avg/max/mdev = %i.%i0/%i.%i0/%i.%i0/0.000 ms\n",time1,time2, time1,time2, time1,time2 );
			}else{
				system("clear");
				system("clear");
				system("clear");
				printf("\n\n\t\tINTERFACES DE LA RED\n");

				system(pingIP);
			}
			/*while (returnValue = pcap_next_ex(descr, &header, &data) >= 0){	
				if (data != NULL){
					const struct pcap_pkthdr* pkthdr= header;
					int count = packetCount;
					const u_char* packet = data;
					u_int i;

					if (repetir != header->ts.tv_usec){

						packetCount++; 
						printf("Paquete # %i\n", packetCount); // Show the packet number
						printf("Tamaño del Paquete: %i bytes\n", header->len);		// Muestra el tamaño en Bytes del paquete.
						if (header->len != header->caplen)		// Muestra un ṕeligro si la longitud es diferente
						    printf("Warning! Capturo size different than packet size: %i bytes\n", header->len);
						printf("Epoch Time: %li : %li segundos\n", header->ts.tv_sec, header->ts.tv_usec);

						// loop through the packet and print it as hexidecimal representations of octets
						// We also have a function that does this similarly below: PrintData()
						int coincidenciaMac =0;
						int coincidenciaIp =0;
						int spoofARP =0;
						int v = 0;

						for (i=0; (i <header->caplen) ; i++){
						    if ( (i % 16) == 0) 
						       	printf("\n"); // Start printing on the next after every 16 octets
						    printf("%.2x ", data[i]);	// Print each octet as hex (x), make sure there is always two characters (.2).   
						}
						printf("\n\n");		 // Add two lines between packets
						repetir=header->ts.tv_usec;
					}
				}
				break;
		    }*/
		}
	}while((strcmp(option,"-i")!=0));


	do{
		printf("\n\nDesea regresar al Menu Principal:\n1)SI\n2)NO");
		printf("\n  ELIJA UNA OPCIÓN :");
		scanf("%d",&opcion);
	}while(opcion>2);

	switch(opcion){
		case 1:{
			system("clear");
			main();
		}
			break;
	}
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
	int opcion;
	printf("\n\t\tRESUMEN TEÓRICO\n");
	//Paquete ARP
	printf("\n******************* PAQUETE ICMP***********************\n\n");
	printf("<------------------------32bits----------------------->\n");
	printf("<----8bits----><----8bits----><---------16bits-------->\n");
	printf("|______________|______________|_______________________|\n");
	printf("|     	       !              |                       |\n");	
	printf("| type(0 or 8) !   code(0)    !        checksum       |\n");
	printf("|______________!______________!_______________________|\n");
	printf("|                             |      sequence         |\n");	
	printf("|           identifier        |       number          |\n");	
	printf("|_____________________________|_______________________|\n");
	printf("|      		    			              |\n");	
	printf("| 	       optional data (ICMP payload)           |\n");	
	printf("|_____________________________________________________|\n");	

	do{
		printf("\n\nDesea regresar al Menu Principal:\n1)SI\n2)NO");
		printf("\n  ELIJA UNA OPCIÓN :");
		scanf("%d",&opcion);
	}while(opcion>2);

	switch(opcion){
		case 1:{
			system("clear");
			main();
		}
			break;
	}
}



