/* vt-cli - A simple VirusTotal-Client written in C
 *
 * Copyright (c) 2014 by Christian Rebischke <echo Q2hyaXMuUmViaXNjaGtlQGdtYWlsLmNvbQo= | base64 -d>
 *
 * Copyright (c) 2014 by Klassiker <echo a2xhc3Npa2Vya2xhc3Npa2VyQGxpdmUuZGUK | base64 -d>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/
 *
 *======================================================================
 * Author: Klassiker
 * Email : echo a2xhc3Npa2Vya2xhc3Npa2VyQGxpdmUuZGUK | base64 -d
 * Github: www.github.com/Klassiker
 *
 * Author: Christian Rebischke
 * Email : echo Q2hyaXMuUmViaXNjaGtlQGdtYWlsLmNvbQo= | base64 -d
 * Github: www.github.com/Shibumi
 *
 *
 * vim: set ts=2 sts=2 sw=2 et
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <jansson.h>

#include <VtComments.h>
#include <VtDomain.h>
#include <VtFileDist.h>
#include <VtIpAddr.h>
#include <VtUrl.h>
#include <VtUrlDist.h>
#include <VtFile.h>
#include <VtResponse.h>

static bool no_error = true; // Developer did this, interrupts eveything when signals are received

void print_usage(const char *program_name){
  printf("%s\n", program_name);
  printf("    scandomain <DOMAIN>			get a report on DOMAIN\n");
  printf("    scanip <IP>				get a report on IP\n");
  printf("    scanfile <FILE>			FILE to scan, auto gets the report and parses it\n");
  printf("    scanurl <URL> <allinfo>		url to scan, allinfo is boolean\n");
  printf("    commentsget <HASH> <before>		before is a timestamp with YYYYMMDDHHSS, optional\n");
  printf("    commentsput <HASH> 'comments'	add comment to resource by hash\n");
  printf("    search <STRING> <offset>		search for a report\n");
}

void sighand_callback(int sig){
  printf("signal caught %d\n", sig);
  no_error = false;
}

// Returns 1 (True) if file doesn't exists or isn't readable, else 0
int filecheck(const char *fname){
  FILE *f;
  if (f = fopen(fname, "r")){
    fclose(f);
    return 0;
  }
  return 1;
}

int main(int argc, char * const *argv){
  char apikey[65]; //the apikey need a way to prevent buffer overflows?
  const char *fname = strcat(getenv("HOME"),"/.vtconfig"); //location of config file TODO Check if HOME exists
  struct VtResponse *response;
  struct VtDomain *domain_report;
  struct VtIpAddr *ip_report;
  struct VtUrl *url_report;
  struct VtFile *file_scan;
  struct VtComments *comments;

  // Check if vtconfig exists
  if(filecheck(fname)){
    printf("No vtconfig found!\n");
    printf("First start? Enter apikey here: ");

    // fgets puts his own nullterminator, so the char array is 65 bytes long, so the first 64 bytes are filled with the apikey
    fgets(apikey, sizeof(apikey), stdin);
    FILE *f = fopen(fname, "w"); // Write apikey to config for next start
      fprintf(f, apikey);
    fclose(f);
  }
  else{
    FILE *f = fopen(fname, "r"); // Read out key if file already exists
      fgets(apikey, sizeof(apikey), f);
    fclose(f);
  }

  printf("%s\n", apikey);

  // Print Usage if no parameter is given
  if(argc < 2){
    print_usage(argv[0]); // argv[0] is the programs name
    return 0;
  }

  //signals for c-vtapi dunno why
  signal(SIGHUP, sighand_callback);
  signal(SIGTERM, sighand_callback);

  // Here comes the Wrapper!
  // Don't know, ideas how to parse the options and do callbacks on the functions?

  return 0;
}
