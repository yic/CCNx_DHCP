#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/keystore.h>
#include <time.h>
#include <sys/time.h>

/* A simple test program to benchmark signing (e.g. as done for RTP)
   performance on different machines */

#define FRESHNESS 10 
#define COUNT 3000
#define PAYLOAD_SIZE 32

int
main(int argc, char **argv)
{

  struct ccn_keystore *keystore = NULL;
  int res = 0;
  struct ccn_charbuf *signed_info = ccn_charbuf_create();
  int i;
  char msgbuf[PAYLOAD_SIZE];
  struct timeval start, end;
  struct timeval duration;
  struct ccn_charbuf *message = ccn_charbuf_create();
  struct ccn_charbuf *path = ccn_charbuf_create();
  struct ccn_charbuf *seq = ccn_charbuf_create();

  struct ccn_charbuf *temp = ccn_charbuf_create();
  keystore = ccn_keystore_create();
  ccn_charbuf_putf(temp, "%s/.ccn/.ccn_keystore", getenv("HOME"));
  res = ccn_keystore_init(keystore,
			  ccn_charbuf_as_string(temp),
			  "Th1s1sn0t8g00dp8ssw0rd.");
  if (res != 0) {
    printf("Failed to initialize keystore %s\n", ccn_charbuf_as_string(temp));
    exit(1);
  }
  ccn_charbuf_destroy(&temp);
  
  res = ccn_signed_info_create(signed_info,
			       /* pubkeyid */ ccn_keystore_public_key_digest(keystore),
			       /* publisher_key_id_size */ ccn_keystore_public_key_digest_length(keystore),
			       /* datetime */ NULL,
			       /* type */ CCN_CONTENT_LEAF,
			       /* freshness */ FRESHNESS,
			       /* keylocator */ NULL);

  srandom(time(NULL));
  for (i=0; i<PAYLOAD_SIZE; i++) {
    msgbuf[i] = random();
  }

  printf("Generating %d signed ContentObjects (one . per 100)\n", COUNT);
  gettimeofday(&start, NULL);

  for (i=0; i<COUNT; i++) {
    
    if (i>0 && (i%100) == 0) {
      printf(".");
      fflush(stdout);
    }
    ccn_name_init(path);
    ccn_name_append_str(path, "test");
    ccn_name_append_str(path, "benchmark");
    ccn_charbuf_putf(seq, "%u", i);
    ccn_name_append(path, seq->buf, seq->length);
  
    res = ccn_encode_ContentObject(/* out */ message,
				   path, signed_info, 
				   msgbuf, PAYLOAD_SIZE,
				   /* digest_algorithm */ NULL, 
				   ccn_keystore_private_key(keystore));

    ccn_charbuf_reset(message);
    ccn_charbuf_reset(path);
    ccn_charbuf_reset(seq);
  }
  gettimeofday(&end, NULL);
  timersub(&end, &start, &duration);

  printf("\nComplete in %d.%06u secs\n", (int)duration.tv_sec, (unsigned)duration.tv_usec);

  return(0);
}