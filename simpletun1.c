    /*SHATADIYA SAHA
    PROJECT : MINIVPN*/

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <signal.h>


    #include <errno.h>
    #include <unistd.h>
    #include <memory.h>

    #include <sys/socket.h>
    #include <sys/types.h>
    #include <sys/ioctl.h>
    #include <sys/stat.h>
    #include <sys/select.h>
    #include <sys/time.h>
    #include <stdarg.h>

    #include <linux/if.h>
    #include <linux/if_tun.h>
    #include <fcntl.h>
    #include <arpa/inet.h> 
    #include <netdb.h>


    #include <openssl/evp.h>
    #include <openssl/hmac.h>
    #include <openssl/crypto.h>
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/x509.h>
    #include <openssl/pem.h>


    /* buffer for reading from tun/tap interface, must be >= 1500 */
    #define BUFFSIZE 520000 
    #define CLIENT 0
    #define SERVER 1
    #define PORT 55555
    #define TPORT 55556
    #define HMAC_LENGTH 32

    /* some common lengths */
    #define IP_HDR_LEN 20
    #define ETH_HDR_LEN 14
    #define ARP_PKT_LEN 28

    /* Certificates */
    #define CCERT "client.crt"
    #define CKEY "client.key"
    #define CACERT "ca.crt"

    #define HOME "./"
    #define SCERT HOME "server.crt"
    #define SKEY HOME "server.key"
    #define SCACERT "ca.crt"


    #define CHK_NULL(x) if ((x)==NULL) { printf("NULL!!\n"); exit(1); }
    #define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
    #define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

    int debug;
    char *progname;
    int val_client;

    /*************Encryption Parameters***************/
      unsigned char KEY[16],IV[16];
      

    /**************************************************************************
    * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
    *            needs to reserve enough space in *dev.                      *
    **************************************************************************/
    int tun_alloc(char *dev, int flags) {
      //printf("OPENING TUNNEL.\n");

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

    void gen_key(unsigned char *key)
    {
      
      int i;
	FILE *urand = fopen("/dev/urandom","r");   //using urandom to generate key
	fread(key, sizeof(char)*16,1, urand);
	fclose(urand);
  }

    void gen_iv(unsigned char *iv)
    {
     int i;
	FILE *urand = fopen("/dev/urandom","r");   //using urandom to generate iv 
	fread(iv, sizeof(char)*16,1, urand);
	fclose(urand);

    }

    void showKeyOrIV(unsigned char* chrs) {
	int i;
	for (i=0; i<16; i++)
	    printf("%c", chrs[i]);
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
	    return strcmp(hash_hex,spassword);
	    
    }

    void Start_VPN(int host,unsigned short int listen_port,char *remote_ip,unsigned short int remote_port,int pipefd)
    {
      int flags = IFF_TUN;
      char if_name[IFNAMSIZ] = "tun0";
      int header_len = IP_HDR_LEN;
      int length=0;
      uint16_t nread, nwrite, plength;
      char buffer[BUFFSIZE];
      socklen_t dest_len =0;
      
      int sock_fd,net_fd, tap_fd,maxfd,optval = 1,i=0,keycount=0;
      socklen_t remotelen;
      
      unsigned long int tap2net = 0, net2tap = 0;
      
      struct sockaddr_in server, dest,sout;
      size_t soutlen = sizeof(sout);

      /*************Hashing Parameters******************/
      unsigned char md_value[EVP_MAX_MD_SIZE];
      int md_len=0;
      int flag =0;
      
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

      

    if(host==CLIENT)
    {
      memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	inet_aton(remote_ip,&dest.sin_addr);   
      dest.sin_port = htons(remote_port);
    }
    else if (host == SERVER)
    {

	    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
	    {
		    perror("setsockopt()");
		    exit(1);
	    }
	    memset(&server, 0, sizeof(server));
	    server.sin_family = AF_INET;
	    server.sin_addr.s_addr = htonl(INADDR_ANY);
	    server.sin_port = htons(listen_port);
	    if (bind(sock_fd, (struct sockaddr*) &server, sizeof(server)) < 0)
	    {
		    perror("bind()");
		    exit(1);
	    }
		    
    }		

    net_fd=sock_fd;

    /* use select() to handle two descriptors at once */
    maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
    dest_len = sizeof(dest);
    while(1) 
    {
	    // Get data from the parent process
	    length = read(pipefd,buffer,sizeof(buffer));
	    if(length>0)
	    {
	      if(buffer[0] =='q')
	      {
		exit(0);
	      }
	      else if(buffer[0]=='k')
	      {
		for(i=0;i<16;i++)
		{
		  KEY[i]=buffer[i+1];
		  IV[i] = buffer[i+16+1];
		}
		keycount++;
	      }
	      
	    }
	    
	    if(!keycount)
	    {
	      sleep(1);
	      continue;
	    }
	      
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
    

    }

    int verify_upwd(char *buffer)
    {
      char *p;
      char user[50];
      char password[50];
      char susername[50];
      char spassword[70];
      FILE *fp;
      int flag =0,i=0;
      
      p = strtok(buffer,"@");
      strcpy(user,p);
      user[strlen(user)]='\0';
      
      p = strtok(NULL,"@");
      strcpy(password,p);
	    
      if((fp = fopen("userdb.txt","r")) == NULL)
      {
	    printf("\nError opening file");
	    exit(1);
      }
		    
      while(!feof(fp))
      {
	    fscanf(fp,"%s %s",susername,spassword);
	    fflush(stdout);

	    if(strcmp(user,susername)==0)
	    {
		    //Verify password
		    //Hash received password
		    int check = check_pwdhash(password,spassword);
		    if(check==0)
		    {
			    flag = 1;
		    }
		    else
		    {
			    return 0;
			    //exit(1);
		    }
				    
				    
				    
	    }
      }
      fclose(fp);
      if(flag == 0)
      {
	    return 0;
	    //exit(1);
	
      }
    do_debug("\nSERVER: Client authenticated.\n");
    return 1;
      
    }

    int receivekey(SSL *s_ssl,char *buffer,size_t err,unsigned char *key)
    {
      int i;
      if(err!=16+1 || buffer[0]!='k') return 0;
      for(i=1;i<err;i++)
	key[i-1] = buffer[i];
      i = SSL_write(s_ssl,"l",1);
      CHK_SSL(i);
      showKeyOrIV(key);
      printf("\n");return 1;
    }

    int receiveiv(SSL *s_ssl,char *buffer,size_t err,unsigned char *iv)
    {
      int i;
      if(err!=16+1 || buffer[0]!='i') return 0;
      for(i=1;i<err;i++)
	iv[i-1] = buffer[i];
      i = SSL_write(s_ssl,"j",1);
      CHK_SSL(i);
      showKeyOrIV(iv);
      printf("\n");
      return 1;
    }

    void keyexchange_server(unsigned short int listen_port,int pipefd,int pid,unsigned char *key,unsigned char *iv)
    {
	/**************OPENSSL Parameters for server********/
      int err,i;
      int listen_sd;
      int sd;
      int keyready =0,ivready=0;
      struct sockaddr_in sa_serv;
      struct sockaddr_in sa_cli;
      size_t client_len;
      SSL_CTX* s_ctx;
      SSL*     s_ssl;
      X509*    client_cert;
      char*    str;
      const SSL_METHOD *s_meth;
      char buffer[BUFFSIZE];
      char buf[BUFFSIZE];
      
      //while(1){
      SSL_load_error_strings();
      SSL_library_init();
      
      s_meth = SSLv23_server_method();
      s_ctx = SSL_CTX_new(s_meth);
      if(!s_ctx)
      {
	perror("SSL_CTX_new");
      exit(2);
      }
      
      //Will not verify the client
      SSL_CTX_set_default_passwd_cb_userdata(s_ctx, "1234");
      SSL_CTX_set_verify(s_ctx,SSL_VERIFY_NONE,NULL);
      
      SSL_CTX_load_verify_locations(s_ctx,SCACERT,NULL);
      
      if(SSL_CTX_use_certificate_file(s_ctx,SCERT,SSL_FILETYPE_PEM)<=0)
      {
	ERR_print_errors_fp(stderr);
	exit(3);
      }
      
      if(SSL_CTX_use_PrivateKey_file(s_ctx,SKEY,SSL_FILETYPE_PEM)<=0)
      {
	ERR_print_errors_fp(stderr);
	exit(4);
      }
      
      if(!SSL_CTX_check_private_key(s_ctx))
      {
	fprintf(stderr,"\nPrivate key doesnot match certificate public key\n");
	exit(5);
      }
      
      listen_sd = socket(AF_INET,SOCK_STREAM,0);
      CHK_ERR(listen_sd,"socket");
      
      memset(&sa_serv,'\0',sizeof(sa_serv));
      sa_serv.sin_family=AF_INET;
      sa_serv.sin_addr.s_addr = htonl(INADDR_ANY);
      sa_serv.sin_port = htons(listen_port);
      
      err = bind(listen_sd,(struct sockaddr*)&sa_serv,sizeof(sa_serv));
      CHK_ERR(err,"bind");
      
      /*Receive TCP connection */
      printf("\nListening on port %d\n", listen_port);
      err = listen(listen_sd,5);
      CHK_ERR(err,"listen");
      
      client_len = sizeof(sa_cli);
      sd = accept(listen_sd,(struct sockaddr*)&sa_cli,&client_len);
      CHK_ERR(sd,"accept");
      close(listen_sd);
      
    
      /*TCP Connection is ready.Server Side SSL */
      
      s_ssl = SSL_new(s_ctx);
      CHK_NULL(s_ssl);
      SSL_set_fd(s_ssl,sd);
      err = SSL_accept(s_ssl);
      CHK_SSL(err);
      
      /*Data exchange*/
      err = SSL_read(s_ssl,buffer,sizeof(buffer)-1);
      CHK_SSL(err);
      buffer[err]='\0';
      
      /****Verify CLient***/
      
    int check = verify_upwd(buffer);
    if(check == 1)
      SSL_write(s_ssl,"r",1);
    else
      SSL_write(s_ssl,"w",1);
    
	
    /***Key Exchange***/
    if(check == 1){
      
	printf("\nConnection from %s:%i\n", inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));
      while(1){
	keyready=0;
	ivready =0;
	while(!keyready || !ivready)
	{
	  err = SSL_read(s_ssl,buf,sizeof(buf)-1);
	  CHK_SSL(err);
	  buf[err]='\0';
	  keyready = keyready || receivekey(s_ssl,buf,err,KEY);
	  ivready = ivready || receiveiv(s_ssl,buf,err,IV);
	}
	
	//Notify the child process
	buf[0]='k';
	
	//Send key and iv to child process

	for(i=0;i<16;i++)
	{
	  buf[i+1]=KEY[i];
	  buf[i+16+1] = IV[i];
	  
	}
	buf[16*2+1]='\0';
	// check if this is a disconnect signal
	keyready =0; ivready=0;
	for(i=0;i<16;i++)
	{
	  keyready = keyready || (int)KEY[i];
	  ivready = ivready || (int)IV[i];
	}
	
	if(!keyready && !ivready)
	{
	  printf("Disconnect signal from client received\n");
	  kill(pid,SIGTERM);
	  wait();
	  break;
	}
	write(pipefd,buf,16*2+2);
      }  
      printf("Closing connection\n");
      close(sd);
      SSL_free(s_ssl);
      SSL_CTX_free(s_ctx);
    }
    else
    {
      printf("Client not authenticated!\n");
      kill(pid,SIGTERM);
      wait();
    }
      
 }
      
      


    int verify_client(SSL *c_ssl)
    {
      unsigned char username[50];
      char password[50];
      char *password1;
      unsigned char credentials[100];
      int err;
      char buffer[BUFFSIZE];
      
      /* DATA EXCHANGE - Send a message and receive a reply. */
      printf("ENTER USERNAME :");
      fflush(stdout);
      scanf("%s",username);
      username[strlen(username)]='\0';
      
      password1 = (char*)getpass("ENTER PASSWORD :");
      strcpy(password,password1);
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
      
      err = SSL_write (c_ssl, credentials, strlen(credentials)); 
      CHK_SSL(err);
      SSL_read(c_ssl,buffer,sizeof(buffer));
      if(buffer[0] == 'r')
	return 1;
      else
	return 0;
      

    }


    void send_key(SSL *c_ssl,unsigned char *key)
    {
      int i;
      //printf("\nSENDING KEY\n");
      char buffer[BUFFSIZE];
      buffer[0]='k';
      for(i=0;i<16;i++)
	buffer[i+1] = key[i];
      i = SSL_write(c_ssl,buffer,16+1);
      CHK_SSL(i);

      i = SSL_read(c_ssl,buffer,sizeof(buffer)-1);
      CHK_SSL(i);
      buffer[i]='\0';
      if(buffer[0]=='l')
      {
	printf("\nKey confirmed by server : \n");
	showKeyOrIV(key);
	printf("\n");
      }
      else
	perror("\nKey exchange failed\n");
    }

    void send_iv(SSL *c_ssl,unsigned char *iv)
    {
      int i;
      //printf("\nSENDING IV\n");
      char buffer[BUFFSIZE];
      buffer[0]='i';
      for(i=0;i<16;i++)
	buffer[i+1] = iv[i];
      i = SSL_write(c_ssl,buffer,16+1);
      CHK_SSL(i);
      
      i = SSL_read(c_ssl,buffer,sizeof(buffer)-1);
      CHK_SSL(i);
      buffer[i]='\0';
      if(buffer[0]=='j')
      {
	printf("IV confirmed by server : \n");
	showKeyOrIV(iv);
	printf("\n");
	
      }
      else
	perror("IV exchange failed\n");
    }


    void keyexchange_client(char *remote_ip,char *remote_host,unsigned short int remote_port,int pipefd,int pid)
    {
      char buffer[BUFFSIZE]; char buf[BUFFSIZE];
      char *check_ip;
      /*************OPENSSL Parameters for client********/
      int c_sd;int err,i;
      struct sockaddr_in sa_client;
      SSL_CTX* c_ctx;
      SSL* c_ssl;
      X509* server_cert;
      char* str;
      const SSL_METHOD *c_meth;
      
      SSLeay_add_ssl_algorithms();
      c_meth = SSLv23_client_method();
      SSL_load_error_strings();
      c_ctx = SSL_CTX_new (c_meth);
      CHK_NULL(c_ctx);
      CHK_SSL(err);
      
      //SSL_CTX_set_default_passwd_cb_userdata(c_ctx, "1234");
      SSL_CTX_set_verify(c_ctx,SSL_VERIFY_PEER,NULL);
      SSL_CTX_load_verify_locations(c_ctx,CACERT,NULL);
      
      
      /****Socket creation to create to the socket****/
      c_sd = socket(AF_INET,SOCK_STREAM,0);
      CHK_ERR(c_sd,"socket");
      memset (&sa_client,'\0',sizeof(sa_client));
      sa_client.sin_family = AF_INET;
      sa_client.sin_addr.s_addr = inet_addr(remote_ip); //server ip
      sa_client.sin_port = htons(remote_port); //server port
      
      printf("\n Connecting to server on port %d",remote_port);
      
      err = connect(c_sd,(struct sockaddr*)&sa_client,sizeof(sa_client));
    CHK_ERR(err,"connect");
      
      /******SSL negotiation ******/
      
      c_ssl = SSL_new (c_ctx); 
      CHK_NULL(c_ssl);    
      SSL_set_fd (c_ssl, c_sd);
      err = SSL_connect (c_ssl);
      /* Get the cipher - opt */

      printf ("\nSSL connection using %s\n", SSL_get_cipher (c_ssl));
      
      /* Get server's certificate (note: beware of dynamic allocation) - opt */
      
      /***********Server Authentication**************/

      server_cert = SSL_get_peer_certificate (c_ssl); 
      
      CHK_NULL(server_cert);
      printf ("\nServer certificate:\n");
      
      /*****Get subject from the certificate******/
      X509_NAME *subject =X509_get_subject_name(server_cert);
      CHK_NULL(subject);
      str = X509_NAME_oneline(subject,0,0);
      CHK_NULL(str);
      printf ("Subject: %s\n", str);
      OPENSSL_free (str);

      /******Get issuer name from the certificate*****/
      str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
      CHK_NULL(str);
      printf ("Issuer: %s\n", str);
      OPENSSL_free (str);
      
      
      /****Get common name from the certificate****/
      int nid_cn = OBJ_txt2nid("CN");
      char common_name[256];
      X509_NAME_get_text_by_NID(subject,nid_cn,common_name,256);
      printf("CN : %s\n",common_name);
      
      /****CN validation******/
      if(strcmp(common_name,remote_host)==0)
	    printf("CName Validated.\n");
      
      X509_free (server_cert);
      
  int check = verify_client(c_ssl);
      
  if(check ==1){    
      while(1)
      {
	printf("Please input :\n");
	printf("1. 'q' to abort the vpn\n2. 'c' to generate key and iv\n");
	scanf("%s",buffer);
	if(strlen(buffer) == 1)
	{
	  if(buffer[0]=='q')
	  {
	    kill(pid,SIGTERM);
	    wait();
	    break;
	  }
	  else if(buffer[0]=='c')
	  {
	    gen_key(KEY);
	    gen_iv(IV);
	  }
	}
	else if(strlen(buffer)>0)
	{
	  printf("Invalid Input.Try Again.\n");
	  continue;
	}
	send_key(c_ssl,KEY);
	send_iv(c_ssl,IV);
	
	
	/******Key Exchange ends********/
	//Notify the child process
	
	buffer[0]='k';
	
	for(i=0;i<16;i++)
	{
	  buffer[i+1]=KEY[i];
	  buffer[i+16+1]=IV[i];
	}
	buffer[16*2+1]='\0';
	write(pipefd,buffer,16*2+2);
      }
	for(i=0;i<16;i++)
	{
	  KEY[i]=0;
	  IV[i]=0;
	}
      
	send_key(c_ssl,KEY);
	send_iv(c_ssl,IV);
	
	buffer[0]='q';
	
	for(i=0;i<16;i++)
	{
	  buffer[i+1]=KEY[i];
	  buffer[i+16+1]=IV[i];
	}
	buffer[16*2+1]='\0';
	write(pipefd,buffer,16*2+2);  
  
      /* Clean up. */
      SSL_shutdown(c_ssl);
      close (c_sd);
      SSL_free (c_ssl);
      SSL_CTX_free (c_ctx);
  }
  else
  {
    printf("PLease enter correct credentials\n");
    kill(pid,SIGTERM);
  }
      
}

    void hosttoip(char *remote_host,char *remote_ip)
    {
      struct hostent *serverhost;
      struct in_addr **addr_list;
      int i=0;
      serverhost = gethostbyname(remote_host);
      if(serverhost == NULL)
	printf("Hostname Failed\n");
      else
      {
	addr_list = (struct in_addr **)serverhost->h_addr_list;
	for(i=0;addr_list[i]!=NULL;i++)
	{
	  strcpy(remote_ip,inet_ntoa(*addr_list[i]));
	}
      }
      
    }
    int main(int argc, char *argv[]) 
    {
      
      int option;
      int fd[2];
      int i=0;
      pid_t pid;char *p;
      char *remote_host; char remote_ip[100];
      unsigned short int listen_port;
      unsigned short int remote_port;
      int host = -1;    /* must be specified on cmd line */
      
      while((option = getopt(argc, argv, "s:c:d")) > 0){
	switch(option) {
	    case 'd':
	    debug = 1;
	    break;
	  case 's':
	    host = SERVER;
	    listen_port = atoi(optarg);
	    break;
	  case 'c':
	    host = CLIENT;
	    p = (char *)memchr(optarg,':',16);
	    if (!p) perror("invalid argument : [%s]\n");
		    *p = 0;
	    listen_port = 0;
	    remote_port = atoi(p+1);
	    remote_host = optarg;
	    hosttoip(remote_host,remote_ip);
	    break;
	  default:
	    break;
	}
      }


      if(host < 0){
	perror("Must sp	ecify dest or server mode!\n");
      }else if((host == CLIENT)&&(*remote_ip == '\0')){
	perror("Must specify server address!\n");
      }
    
      
      pipe(fd);
	fcntl(fd[0], F_SETFL, O_NONBLOCK);
      
      if((pid = fork()) < 0)
	perror("fork");
      
      else if(pid>0)
      {
	//Parent process for PKI
	close(fd[0]); // Parent process wants to send data
	switch(host)
	{
	  case SERVER :
	    keyexchange_server(listen_port,fd[1],pid,KEY,IV);
	    break;
	  case CLIENT :
	    keyexchange_client(remote_ip,remote_host,remote_port,fd[1],pid);
	    break;
	}
      }
      
      
      else
      {
	close(fd[1]); //Child process wants to send data
	Start_VPN(host,listen_port,remote_ip,remote_port,fd[0]);
      }
    }