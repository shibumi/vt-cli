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
#include <pwd.h>

#include <VtResponse.h>
#include <VtDomain.h>
#include <VtIpAddr.h>
#include <VtUrl.h>
#include <VtFileDist.h>
#include <VtUrlDist.h>
#include <VtFile.h>
#include <VtComments.h>
#define APIKEY_SIZE 65

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

/* Return the user's home directory.  We use $HOME, and if that fails,
 * we fall back on the home directory of the effective user ID. */
char* get_homedir(){
  static char* fname= NULL;
  fname = getenv("HOME"); // Try get $HOME
  if (fname == NULL) {
    const struct passwd *pw = getpwuid(geteuid()); // if it failed, try get home from passwd
    if (pw != NULL){
      fname = pw->pw_dir;
    } // if
  } // if
  fname = strcat(fname, "/.vtconfig"); // add path for config to $HOME
  return fname;
}

// Returns 1 (True) if file  exists , else 0 when doesn't exist or not readable
int filecheck(char *fname){
  FILE *f;
  if (f = fopen(fname, "r")){
    fclose(f);
    return 1;
  } // if
  return 0;
}

int getapikey(char* apikey, char* fname){
  // Check if vtconfig exists
  if(!filecheck(fname)){
    printf("No vtconfig found!\n");
    printf("First start? Enter apikey here: ");

    // fgets puts his own nullterminator, so the char array is 65 bytes long, so the first 64 bytes are filled with the apikey
    fgets(apikey, APIKEY_SIZE, stdin);
    
    // checking if the API-key is valid
    int i;
    for(i = 0; i < 65; i++){
      if(!isxdigit(apikey[i])){
        printf("Error, the API-Key is not valid!\n");
        printf("The API-Key must contain hexdigits\n");
        return 0;
        }
    }

    FILE *f = fopen(fname, "w"); // Write apikey to config for next start
    if(f == NULL){
      printf("Fehler beim Öffnen der Datei. Überprüfen sie, ob sie Schreibrechte in %s haben.\n", fname); //why not english here?
      return 0;
    } // if

    fprintf(f, apikey);
    fclose(f);

  } // if
  else{
    FILE *f = fopen(fname, "r"); // Read out key if file already exists
    if(f == NULL){
      printf("Fehler beim Öffnen der Datei. Überprüfen sie, ob sie Schreibrechte für %s haben.\n", fname); //why not english here?
      return 0;
    } // if

    fgets(apikey, APIKEY_SIZE, f);
    fclose(f);
    return 1;
  } // else
} // getapikey

int free_variables(char* apikey){
  free(apikey);
  apikey = NULL;
  return 0;
} // free_variables


int main(int argc, char * const *argv){
  //VirusTotal-Structs
  struct VtResponse *response;
  struct VtDomain *domain_report;
  struct VtIpAddr *ip_report;
  struct VtUrl *url_report;
  struct VtFile *file_scan;
  struct VtComments *comments;

  char* apikey = (char*)calloc(APIKEY_SIZE, APIKEY_SIZE*sizeof(char)); // TODO must be free'd
  int c; //see switch-case 
  char* fname = NULL;
  fname = get_homedir(); 
  if(!getapikey(apikey, fname)) return 1;

  // Print Usage if no parameter is given
  if(argc < 2){
    print_usage(argv[0]); // argv[0] is the programs name
    free_variables(apikey);
    return 0;
  } // if

  //signals for c-vtapi dunno why
  signal(SIGHUP, sighand_callback);
  signal(SIGTERM, sighand_callback);

  while(1){
    int option_index = 0;
    static struct option long_options[] = {
      {"scandomain",  required_argument, 0, 'd'},
      {"scanip",      required_argument, 0, 'i'},
      {"scanfile",    required_argument, 0, 'f'},
      {"scanurl",     required_argument, 0, 'u'},
      {"commentsget", required_argument, 0, 'g'},
      {"commentsput", required_argument, 0, 'p'},
      {"search",      required_argument, 0, 's'},
      {0,             0,                 0,  0 }
    }; // static struct option

    c = getopt_long_only(argc, argv, "", long_options, &option_index);

    if(c == -1){
      break;
    } // if

    switch(c){
      case 'd':
        // scandomain wrapper
        break; // case d - scandomain
      case 'i':
        // scanip  wrapper
        break; // case i - scanip
      case 'f':
        // scanfile wrapper
        break; // case f - scanfile
      case 'u':
        // scanurl wrapper
        break; // case u - scanurl
      case 'g':
        // commentsget wrapper
        break; // case g - commentsget
      case 'p':
        // commentsput wrapper
        break; // case p - commentsput
      case 's':
        // search function
        break; // case s - search
      default:
        printf("?? getopt returned character code 0%o ??\n", c);
    } // switch
  } // While

  if (optind < argc) {
    printf("non-option ARGV-elements: ");
    while (optind < argc){
      printf("%s ", argv[optind++]);
    } // while
    printf("\n");
  } // if
  free_variables(apikey);
  return 0;
} // int main
