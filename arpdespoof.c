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
#include <unistd.h>

#define MAXPATHLEN 200
//Declaracion de funciones
void resumenTeorico();
void encabezado();
void arpdespoof();

struct arp_struct{
    u_char  arp_mac[6];
    u_char  arp_ip[4];
    long int arp_time[2];
};

pcap_t* descr;

int main(){
	int opcion;
	do{
		system("clear");
		encabezado();
		printf("\t\t\t\t\t MENÚ\n");
		printf("\t\t\t\t  1) ARP SPOOFING\n");
		printf("\t\t\t\t  2) RESUMEN TEÓRICO\n");
		printf("\t\t\t\t  3) SALIR\n");	
		printf("\t\t\t\t  ELIJA UNA OPCIÓN :");
		scanf("%d",&opcion);
	}while(opcion>3);
	
	switch(opcion){
		case 1:{system("clear"); arpdespoof();}
		break;
		case 2:{system("clear"); resumenTeorico();}
		break;			
		default:{return 0;}
		break;
	}
	return 0;
}

void arpdespoof(){
	char *net, *mask, *dev, errbuf[PCAP_ERRBUF_SIZE];
	const u_char *packet;
	struct bpf_program fp; // contenedor con el programa compilado
	bpf_u_int32 maskp;// mascara de subred
	bpf_u_int32 netp;	// direccion de red
	int compiler, filter, count = 1,n, j=0, i, opcionARP;
	char nameFile[MAXPATHLEN], option[10], *extension = ".pcap", file[MAXPATHLEN], errbufDEV[100], devs[100][100], resp = (char )2;;
	pcap_if_t *alldevsp , *device;
    struct arp_struct tablaDatos[100];
    clock_t start_t;
    double total_t=0.0;
    float tiempoD;

	do{
		system("clear");
		printf("\n\t\t\t\tARP SPOOFING\n");
		printf("-i DEV,     especifica la interface de red con la cual hacer sniff.\n");
		printf("-r FILE,    lee  el   tráfico  de  red   desde  un  archivo   pcap.\n");
		printf("\n\tIngrese la opcion: ");
		scanf("%s",option);

		if(strcmp(option, "-i")==0){
			printf("\t\tINTERFACES DE LA RED\n");
		    if( pcap_findalldevs( &alldevsp , errbuf) ){ printf("Error al econtrar dispositivos : %s" , errbuf); exit(1); }
		     
		    printf("\n  Dispositivos habilitados son: :\n");
		    for(device = alldevsp ; device != NULL ; device = device->next){
		    	printf("\t%d. %s - %s\n" , count , device->name , device->description);
		        if(device->name != NULL){ strcpy(devs[count] , device->name); }
		        count++;
		    }
		    printf("  Ingrese el numero del dispositivo para hacer sniff : ");
		    scanf("%d" , &n);
		    printf("  Ingrese la ventana de tiempo: ");
		    scanf("%f", &tiempoD);

	    	dev = devs[n]; // Device
			pcap_lookupnet(dev,&netp,&maskp,errbuf); //Extraemos la direccion de red y la mascara
			descr = pcap_open_live(dev,BUFSIZ,1,10,errbuf); //Comenzamos la captura en modo promiscuo //Open the device for sniffing
			if (descr == NULL){	printf("pcap_open_live(): %s\n",errbuf); exit(1); }

			compiler = pcap_compile(descr,&fp,"arp",0,netp);			
			if ( compiler < 0){ fprintf(stderr,"Error compilando el filtro\n"); exit(1); }//Compilamos el programa

			filter = pcap_setfilter(descr,&fp);
			if ( filter < 0 ){ fprintf(stderr,"Error aplicando el filtro\n"); exit(1); }//aplicamos el filtro

			struct pcap_pkthdr *header;
			const u_char *data;
			int packetCount = 0, returnValue, repetir=0, i;

			start_t = clock();
			while ((returnValue = pcap_next_ex(descr, &header, &data) >= 0) || total_t < 5.0) {
				clock_t end_t;
				end_t = clock();
				total_t = (((double)(end_t - start_t) / (double)CLOCKS_PER_SEC)) *400 ;
				if (total_t > tiempoD){	break;}
				
				if (data != NULL){
					if (repetir != header->ts.tv_usec){
						packetCount++; 
						printf("Paquete # %i\n", packetCount); 
						printf("Tamaño del Paquete: %i bytes\n", header->len);
						if (header->len != header->caplen)		// Muestra un ṕeligro si la longitud es diferente
						    printf("Warning! Capturo size different than packet size: %i bytes\n", header->len);
						printf("Epoch Time: %li : %li segundos\n", header->ts.tv_sec, header->ts.tv_usec);		
						int coincidenciaMac =0,coincidenciaIp =0, spoofARP =0, v = 0;
						for (i=0; (i <header->caplen) ; i++){
							if(i==21 && (data[i]==resp)){
								if (j==0){
									for(n=0; n<6;n++){tablaDatos[j].arp_mac[n]=data[22+n];}
									for(n=0; n<4;n++){tablaDatos[j].arp_ip[n]=data[28+n];}
									tablaDatos[j].arp_time[0] = header->ts.tv_sec;
									tablaDatos[j].arp_time[1] = header->ts.tv_usec;
								}else{
									int banderaIp=0, banderaMac=0, ipX, ipY;
									for (ipX = 0; ipX < j; ipX++){
										for (ipY = 0; ipY < 4; ipY++){ if (data[28+ipY] == tablaDatos[ipX].arp_ip[ipY]){ coincidenciaIp++;} }
										if (coincidenciaIp == 4){ banderaIp =1;	break; }
										else{ banderaIp =0;}
										coincidenciaIp=0;
									}
									if (banderaIp == 0){banderaMac = 0;}
									else{banderaMac = 1;}

									if (banderaMac == 1){
										int macX, macY;
											for (macY = 0; macY  < 6; macY++){ if (data[22+macY] == tablaDatos[ipX].arp_mac[macY]){coincidenciaMac++;} }
											if (coincidenciaMac != 6){ spoofARP = 1; v = macX; }
											else{spoofARP = 0;}
											coincidenciaMac = 0;
										j--;
									}else{
										for(n=0; n<6;n++){tablaDatos[j].arp_mac[n]=data[22+n];}
										for(n=0; n<4;n++){tablaDatos[j].arp_ip[n]=data[28+n];}
										tablaDatos[j].arp_time[0] = header->ts.tv_sec;
										tablaDatos[j].arp_time[1] = header->ts.tv_usec;	
									}
								}
								j++;
							}
						    if ( (i % 16) == 0){printf("\n");} 
						    printf("%.2x ", data[i]);  
						}
						if (spoofARP == 1){
							printf("\n\tDETECT: Who-has %i.%i.%i.%i, R1: %x:%x:%x:%x:%x:%x,  R2:  %x:%x:%x:%x:%x:%x, TS: %li . %li \n"
								,data[28],data[29],data[30],data[31]
								,tablaDatos[v].arp_mac[0], tablaDatos[v].arp_mac[1], tablaDatos[v].arp_mac[2], tablaDatos[v].arp_mac[3], tablaDatos[v].arp_mac[4], tablaDatos[v].arp_mac[5]
								,data[22],data[23],data[24],data[25],data[26], data[27]
								,header->ts.tv_sec, header->ts.tv_usec);
						}
						printf("\n\n");
						repetir=header->ts.tv_usec;	
					}
				}
		    }
		}else if (strcmp(option,"-r")==0){
			printf("\nTráfico de red desde un archivo PCAP");
			printf("\nIngrese el nombre del archivo (sin .pcap):  ");
			scanf("%s",nameFile);
			file[MAXPATHLEN] = nameFile[MAXPATHLEN];
			getcwd(file, MAXPATHLEN);//Obtenemos el path del archivo
			char filen[MAXPATHLEN]="/";
			strcat(filen, nameFile);
			strcat(file, filen);
			strcat(file,extension);
		    pcap_t * pcap = pcap_open_offline(file, errbuf);
		    struct pcap_pkthdr *header;
		    const u_char *data;
			int packetCount = 0, returnValue,  c=0;
			
			while (returnValue = pcap_next_ex(pcap, &header, &data) >= 0){	
				packetCount++;
				int  i, coincidenciaMac =0,coincidenciaIp =0, spoofARP =0, v = 0;
				
				for (i=0; (i <header->caplen) ; i++){
					if(i==21 && (data[i] == resp)){
						if (j==0){
							for(n=0; n<6;n++){tablaDatos[j].arp_mac[n]=data[22+n];}
							for(n=0; n<4;n++){tablaDatos[j].arp_ip[n]=data[28+n];}
							tablaDatos[j].arp_time[0] = header->ts.tv_sec;
							tablaDatos[j].arp_time[1] = header->ts.tv_usec;	
						}else{
							int banderaIp=0, banderaMac=0, ipX, ipY, macX, macY;;
							for (ipX = 0; ipX < j; ipX++){
								for (ipY = 0; ipY < 4; ipY++){	if (data[28+ipY] == tablaDatos[ipX].arp_ip[ipY]){coincidenciaIp++;}	}
								if (coincidenciaIp == 4){ banderaIp =1;	break; }
								else{banderaIp =0;}
								coincidenciaIp=0;
							}
							if (banderaIp == 0){banderaMac = 0;}
							else{banderaMac = 1;}

							if (banderaMac == 1){
									for (macY = 0; macY  < 6; macY++){if (data[22+macY] == tablaDatos[ipX].arp_mac[macY]){coincidenciaMac++;} }
									if (coincidenciaMac != 6){ spoofARP = 1;	v = macX; }
									else{ 
										spoofARP = 0; 
										tablaDatos[ipX].arp_time[0] = header->ts.tv_sec;
										tablaDatos[ipX].arp_time[1] = header->ts.tv_usec;
									}
									coincidenciaMac = 0;
								j--;
							}else{
								for(n=0; n<6;n++){tablaDatos[j].arp_mac[n]=data[22+n];}
								for(n=0; n<4;n++){tablaDatos[j].arp_ip[n]=data[28+n];}	
								tablaDatos[j].arp_time[0] = header->ts.tv_sec;
								tablaDatos[j].arp_time[1] = header->ts.tv_usec;	
							}
						}
						j++;
					}   
				}
				if (spoofARP == 1){
					printf("\n DETECT: Who-has %i.%i.%i.%i, R1: %x:%x:%x:%x:%x:%x,  R2:  %x:%x:%x:%x:%x:%x, TS: %li . %li \n"
						,data[28],data[29],data[30],data[31]
						,tablaDatos[v].arp_mac[0], tablaDatos[v].arp_mac[1], tablaDatos[v].arp_mac[2], tablaDatos[v].arp_mac[3], tablaDatos[v].arp_mac[4], tablaDatos[v].arp_mac[5]
						,data[22],data[23],data[24],data[25],data[26], data[27]
						,header->ts.tv_sec, header->ts.tv_usec);
				}
		    }
		}
	}while((strcmp(option,"-i")!=0) && (strcmp(option,"-r")!=0));

	do{
		printf("\n  Desea regresar al Menu Principal:\n\t1)SI\n\t2)NO");
		printf("\n\tELIJA UNA OPCIÓN :");
		scanf("%d",&opcionARP);
	}while(opcionARP>2);

	switch(opcionARP){
		case 1:{ system("clear"); main();}
		break;
	}
}

void encabezado(){
	printf("\n\n           ESCUELA SUPERIOR POLITÉCNICA DEL LITORAL (ESPOL)\n");
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
	printf("\n\t\tRESUMEN TEÓRICO\n");	//Paquete ARP
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
	
	do{
		printf("\n\nDesea regresar al Menu Principal:\n1)SI\n2)NO");
		printf("\n  ELIJA UNA OPCIÓN :");
		scanf("%d",&opcion);
	}while(opcion>2);

	switch(opcion){
		case 1:{system("clear");main();}
		break;
	}
}
