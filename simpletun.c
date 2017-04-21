/*SHATADIYA SAHA
PROJECT : MINIVPN*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFFSIZE 520000 
#define CLIENT 0
#define SERVER 1
#define PORT 55555
#define HMAC_LENGTH 32

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;


/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

int do_crypt(unsigned char *KEY,unsigned char *IV,char *buffer,int *length,int option)
{
	unsigned char outbuff[BUFFSIZE + EVP_MAX_BLOCK_LENGTH];
	unsigned char inbuff[BUFFSIZE];
	int outlen =0,tmplen=0;
	int inputlen=*length;
	memcpy(inbuff,buffer,inputlen);
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	int l = strlen(KEY);
	EVP_CipherInit_ex(&ctx,EVP_aes_128_cbc(),NULL,KEY,IV,option);
	if(!EVP_CipherUpdate(&ctx,outbuff,&outlen,inbuff,inputlen))
		return 0;
	if(!EVP_CipherFinal_ex(&ctx,outbuff+outlen,&tmplen))
		return 0;
	outlen+=tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	
	memcpy(buffer,outbuff,outlen);
	*length = outlen;
	return 1;
	
		
}

void getHash(unsigned char *KEY,unsigned char *buffer,int length,char *hash)
{
	HMAC_CTX mdctx;
	unsigned char *outhash = (char*)malloc(HMAC_LENGTH);
	int md_len;

	HMAC_CTX_init(&mdctx);
	HMAC_Init_ex(&mdctx,KEY,strlen(KEY),EVP_sha256(),NULL);
	HMAC_Update(&mdctx,buffer,length);
	HMAC_Final(&mdctx,outhash,&md_len);
	HMAC_CTX_cleanup(&mdctx);

	memcpy(hash,outhash,HMAC_LENGTH);
}

void do_HMAC(unsigned char *KEY,unsigned char *buffer,int *length)
{
	char hash[HMAC_LENGTH],inbuff[BUFFSIZE];
	int i=0,inputlen=*length;
	memcpy(inbuff,buffer,inputlen);
	getHash(KEY,inbuff,inputlen,hash);
	
	/**********Append MAC to message***********/
	
	for(i=0;i<HMAC_LENGTH;i++)
		*(buffer+inputlen+i) = hash[i];
	inputlen += HMAC_LENGTH;
	*length = inputlen;
}

int do_hashcheck(unsigned char *KEY,unsigned char *buffer,int *length)
{
	char hash1[HMAC_LENGTH],hash2[HMAC_LENGTH],inbuff[BUFFSIZE];
	int inputlen = *length,i=0;
	inputlen-=HMAC_LENGTH;
	if(inputlen<=0) return 1;
	
	memcpy(inbuff,buffer,inputlen);
	memcpy(hash1,buffer+inputlen,HMAC_LENGTH);
	getHash(KEY,buffer,inputlen,hash2);
	*length = inputlen;

	return strncmp(hash1,hash2,HMAC_LENGTH);
}

int check_pwdhash(char *password,char *spassword)
{
	EVP_MD_CTX *mdctx;
	char *hashname ="sha256";
	const EVP_MD *md;
	int md_len,i=0;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	
	OpenSSL_add_all_digests();
	md=EVP_get_digestbyname(hashname);
	if (md == NULL) 
	{
        	printf("Unknown message digest %s\n", hashname);
        	exit(1);
 	}
	

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, password, strlen(password));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);


	char *hash_hex=(char*)malloc(2*md_len + 1);
	char *hex_buff = hash_hex;
	for(i=0;i<md_len;i++)
		hex_buff+=sprintf(hex_buff,"%02x",md_value[i]);
	*(hex_buff+1)='\0';
	
	fflush(stdout);
	//printf("Hash of password :");
	/*for(i=0;hash_hex[i]!='\0';i++)
	{
		printf("%c",hash_hex[i]);
   	}*/
	fflush(stdout);
	return strcmp(hash_hex,spassword);
	
}

int main(int argc, char *argv[]) 
{
  
  int tap_fd, option, maxfd;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  size_t length;
  uint16_t nread, nwrite, plength;
  char buffer[BUFFSIZE];
  socklen_t dest_len =0;
  
  
  struct sockaddr_in server, dest,sout;
  size_t soutlen = sizeof(sout);
  
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd,net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  unsigned char username[50];
   char password[50];
  unsigned char credentials[100];

  char susername[50];
  char spassword[64];

  progname = argv[0];

  FILE *fp;


  /*************Encryption Parameters***************/
  unsigned char KEY[16]="abcdefghijklmnop",IV[16]={0};

  /*************Hashing Parameters******************/
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len=0;
  int flag =0;


  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uad")) > 0){
    switch(option) {
	case 'd':
         debug = 1;
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        break;
    }
  }

  argv += optind;
  argc -= optind;

  if(*if_name == '\0'){
   perror("Must specify interface name!\n");
   
  }else if(cliserv < 0){
    perror("Must specify dest or server mode!\n");
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    perror("Must specify server address!\n");
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

do_debug("Successfully connected to interface %s\n", if_name);

if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) 
 {
    perror("socket()");
    exit(1);
  }

if(cliserv==CLIENT)
{
	
	
    printf("ENTER USERNAME :");
   fflush(stdout);
   scanf("%s",username);
   username[strlen(username)]='\0';

   
   printf("ENTER PASSWORD :");
   fflush(stdout);
   scanf("%s",password);
   password[strlen(password)]='\0';
 
  fflush(stdout);
   int i=0;
   for(i=0;username[i] != '\0';i++)
         credentials[i]=username[i];
 
    credentials[i]='@';
   int ptr = i+1;

   for(i=0;password[i]!='\0';i++)
	credentials[ptr+i] = password[i];

   credentials[ptr+i]='\0';

	printf("CREDENTIALS: ");
   for(i=0;credentials[i]!='\0';i++){
	printf("%c",credentials[i]);
   }


   fflush(stdout);

   memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_aton(remote_ip,&dest.sin_addr);   
   dest.sin_port = htons(port);
 
  /***************ASK CLIENT FOR VERIFICATION *****************/

 int l = sendto(sock_fd,credentials,sizeof(credentials),0,(struct sockaddr *)&dest,sizeof(dest));
  if( l < 0) perror("sendto");

   

}
else if (cliserv == SERVER)
{

 	if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
	{
      		perror("setsockopt()");
      		exit(1);
	}
 	memset(&server, 0, sizeof(server));
    	server.sin_family = AF_INET;
    	server.sin_addr.s_addr = htonl(INADDR_ANY);
    	server.sin_port = htons(port);
    	if (bind(sock_fd, (struct sockaddr*) &server, sizeof(server)) < 0)
	{
      		perror("bind()");
      		exit(1);
    	}
		int readl = recvfrom(sock_fd,buffer,sizeof(buffer),0,(struct sockaddr*)&dest_len,&dest_len);
		  fflush(stdout);
		if(readl<0) perror("recvfrom");
		printf("Got Packet :%s\n",buffer);
		
		char *p;
		
		p = strtok(buffer,"@");
		strcpy(username,p);
		p = strtok(NULL,"@");
		strcpy(password,p);
		
		if((fp = fopen("userdb.txt","r")) == NULL)
		{
			printf("\nError opening file");
			exit(1);
		}
		
		while(!feof(fp))
		{
			if(fscanf(fp,"%s %s",susername,spassword)<0)
			   perror("fscanf");
			fflush(stdout);
			if(strcmp(username,susername)==0)
			{
				//Verify password
				//Hash received password
				
				int check = check_pwdhash(password,spassword);
				
				
				if(check==0)
				{
					fflush(stdout);
					flag = 1;
					fflush(stdout);
				}
				else
				{
					printf("Incorrect Password\n.PLease check the password.\n");
					exit(1);
				}
				
				
				
			}
		}
		fclose(fp);
		printf("%d\n",flag);
		if(flag == 0)
		{
			printf("User is not present\n");
			exit(1);
		}
		do_debug("SERVER: Client authenticated.\n");

}

if(cliserv==CLIENT && flag == 1)
	do_debug("\nCLIENT: Connected to server %s\n", inet_ntoa(dest.sin_addr));

net_fd=sock_fd;

/* use select() to handle two descriptors at once */
maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
dest_len = sizeof(dest);
while(1) 
{
	int ret;
    	fd_set rd_set;
	FD_ZERO(&rd_set);
    	FD_SET(tap_fd, &rd_set); 
    	FD_SET(net_fd, &rd_set);

    	ret = select(maxfd+1, &rd_set, NULL, NULL, NULL);
  	if (ret < 0 && errno == EINTR){continue;}
	if (ret < 0) {
      	perror("select()");
      	exit(1);}
	if(FD_ISSET(tap_fd, &rd_set)) //Tunnel is selected
    	{
		/* data from tun/tap: just read it and write it to the network */
		length = read(tap_fd,buffer,sizeof(buffer));
	 	do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, length);
		tap2net++;
		if(length<=0)
			perror("read()");

/************************Encrypt before write to UDP Socket****************************/
		if(do_crypt(KEY,IV,buffer,&length,1))
		{
			printf("\n");
		}
		else
			printf("Encryption Failed\n");

/*************************Hashing the encrypted packet*******************************/

		do_HMAC(KEY,buffer,&length);


		if((sendto(sock_fd,buffer,length,0,(struct sockaddr *)&dest,sizeof(dest)))<0){
			perror("sendto()");
			exit(1);}
		do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, length);
    	}
	if(FD_ISSET(net_fd, &rd_set))
	{/* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      		if((length=recvfrom(sock_fd,buffer,BUFFSIZE,0,(struct sockaddr *)&dest,&dest_len))<=0){	
			perror("recvfrom()");
			exit(1);}  
		do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, length);



/*****************************Check the Hash*******************************************/

		if(do_hashcheck(KEY,buffer,&length))
			printf("HASH mismatch.\n");

/******************Decrypt before write to Tun0 interface****************************/		

		if(do_crypt(KEY,IV,buffer,&length,0))
		{
			printf("\n");
		}
		else
			printf("Decryption Failed\n");
	
		if(write(tap_fd,buffer,length)<=0){
			perror("write()");
			exit(1);} 
		do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, length);
		net2tap++;
      }
  }
  return(0);
}
