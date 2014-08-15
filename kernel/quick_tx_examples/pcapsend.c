#include <fcntl.h> 
#include <stdlib.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <sys/uio.h> 
#include <unistd.h> 
#include <stdio.h>

#define DEVICE "/dev/net/quick_tx_eth1"
 
int main (int argc, char* argv[]) 
{
  if (argc != 2) {
    printf("Usage: ./pcapsend <path-to-pcap> \n");
  }

  /* declare a file pointer */
  FILE    *infile;
  char    *buffer;
  long    numbytes;
   
  /* open an existing file for reading */
  infile = fopen(argv[1], "r");
   
  /* quit if the file does not exist */
  if(infile == NULL) {
      printf("File does not exist! \n");
      return 1;
  }
   
  /* Get the number of bytes */
  fseek(infile, 0L, SEEK_END);
  numbytes = ftell(infile);
   
  /* reset the file position indicator to 
  the beginning of the file */
  fseek(infile, 0L, SEEK_SET);	
   
  /* grab sufficient memory for the 
  buffer to hold the text */
  buffer = (char*)calloc(numbytes, sizeof(char));	
   
  /* memory error */
  if(buffer == NULL) {
      printf("Could not allocate %ld bytes of memory! \n", numbytes);
      return 1;
  }
   
  /* copy all the text into the buffer */
  fread(buffer, sizeof(char), numbytes, infile);
  fclose(infile);

  int fd; 
  struct iovec* vec; 
  int i; 
  /* We'll need a "buffer" containing a newline character. Use an 
     ordinary char variable for this.  */ 
  char newline = '\n'; 

  vec = (struct iovec*) malloc (sizeof (struct iovec)); 

  vec->iov_base = buffer; 
  vec->iov_len = numbytes; 
 
  /* Write the arguments to a file.  */ 
  fd = open (DEVICE, O_WRONLY | O_CREAT); 
  if (fd < 0) {
	  printf("Error occurred while opening device! \n");
  }

  if (-1 == writev (fd, vec, 1)) {
	  printf("Error occurred while writing! \n");
  }
  close (fd); 
  free (vec);

  /* free the memory we used for the buffer */
  free(buffer);
  return 0; 
} 
