/*
vt-cli
Copyright (C) 2014 by lupia
Authors:
  shibumi:
    Christian Rebischke <echo Q2hyaXMuUmViaXNjaGtlQGdtYWlsLmNvbQo= | base64 -d>

  klassiker:
    klassiker <echo a2xhc3Npa2Vya2xhc3Npa2VyQGxpdmUuZGUK | base64 -d>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <jansson.h>
#include <VtFile.h>
#include <VtResponse.h>

static bool no_error = true;

/*
comments       . --resource HASH --get FLAG --put COMMENT --before YYYYMMDDHHSS
domain_report  . --report DOMAIN
file_dist      . --reports WHATEVER --before TIMESTAMP --after TIMESTAMP --limit RATE --repeat TIMES --sleep SECONDS
ip_report      . --report IP
scan           . --filescan FILE --report HASH --cluster YYYY-MM-DD --download HASH --out FILE
search         . --query STRING --offset VALUE
url            . --all-info FLAG --report-scan FLAG --scan URL --report URL
url_dist       . --all-info FLAG --before TIMESTAMP --after TIMESTAMP --limit RATE --repeat TIMES --sleep SECONDS
*/

void print_usage(const char *program_name){
  printf("%s", program_name);
  printf("    scandomain <DOMAIN>        get a report on DOMAIN\n");
  printf("    scanip <IP>        get a report on IP\n");
  printf("    scanfile <FILE>        FILE to scan, auto gets the report and parses it\n");
  printf("    scanurl <URL> <allinfo>        url to scan, allinfo is boolean\n");
  printf("    commentsget <HASH> <before>        before is a timestamp with YYYYMMDDHHSS, optional\n");
  printf("    commentsput <HASH> 'comments'        add comment to resource by hash\n");
  printf("    search <STRING> <offset>        search for a report\n");
  printf("    filedist <HASH> <before/after> <TIMESTAMP> <limit> <repeat> <sleep>        filedist for hash, before/after is required\n");
  printf("    urldist <allinfo> <before/after> <TIMESTAMP> <limit> <repeat> <sleep>        urldist for timestamp, before/after is required, allinfo is boolean\n");
}

int main(int argc, char * const *argv){
  char* api_key = NULL;
  char buffer[64];

  // Get apikey from ~/.vt-cli
  FILE *f = fopen(strcat(getenv("HOME"),"/.vt-cli"), "w+");
  if(f == NULL){
    printf("Error opening file.\n");
    exit(1);
  }
  api_key = fgets(buffer, sizeof(buffer), f);
  if(api_key == NULL){
    printf("First start, enter apikey here:\n");
    scanf("%s", api_key);
  }
  printf("%s", api_key);
  fclose(f);

  // Print Usage if no parameter is given
  if(argc < 2){
    print_usage(argv[0]);
    return 0;
  }

}
