/*
BANER
v.0.1 from Jan 7, 2020

Was inspired by fail2ban, but python does not work on my box. Also suitable for 
embedded devices. Very small, does not produce much load on system.

The app bans forever (or until exit) up to 10000 intruders detected by SSH it its 
/var/log/secure or /var/log/auth.log. Log format must be like this:

Jan  7 03:58:00 vps sshd[3018]: Failed password for invalid user ebs from 31.222.195.30 port 51327 ssh2

Baner polls log file once a second, reading its tail line by line. It is triggered by 
"Failed password". It extracts intruder's IP from the line 
and stores internally. If this IP is found more than 3 times (regardless of time 
interval between them), command to iptables is issued that will drop incoming 
packets from this IP. 

Baner must be run as root to be able to send commands to iptables.

If terminated by SIGHUP (kill -HUP `pidof baner`) baner will unblock all previously
blocked IPs. If terminated by SIGKILL these IPs will stay locked until reboot.

So far baner is very primitive: no fork, no logging, nothing. Will probably improve 
it in future.


BUILD:
gcc -o baner baner.c

INSTALL:
Add into your /etc/rc.local:
/path/to/baner >/dev/null &

TEST:
Run /path/to/baner from console and watch what happens.


Do what the fuck you want to with this code  (WTFPL license).

https://github.com/dkorobkov/baner
*/


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>

int gPortToBan = 22;
int gTimeToBan = 600;
int gVerbose = 0;
char szLogfile[257] = "/var/log/secure";

#define BLOCK_AFTER_NUM_ATTACKS 3

typedef struct
{
//	char szIp[20];
	uint32_t Ip;
	int LastTimeSeen; // hrs*3600+mins*60+secs - it is quicker to compare ints than strings
	time_t timeBlockedAt;
	int nMet;
}ENTRY;
ENTRY* pEntries = NULL;
int nEntries = 0;

void Help(const char* name)
{
	fprintf(stdout, "Usage: %s [OPTIONS...]\n"
			"Reads tail from SSH log file and bans IPs met more than given number of times\n"
			"Searches strings like \"Jan  2 15:24:04 vps sshd[25017]: Failed password for invalid user lym from 132.232.42.33 port 40490 ssh2\""
			"and issues command \"iptables -I INPUT 1 -s 132.232.42.33 -p 6 --dport 22222 -j DROP\"\n"
			"Must be run as root.\n"
			"\n"
			"Available options are:\n"
			"-h: print this help and exit\n"
			"-l <logfile>: read from this log file. Default is /var/log/secure.log. \n"
			"-v: increase verbosity\n\n"
			"-t <sec>: ban for this number of seconds [30-86400]. Default is 600.\n\n"
			"-p <port>: port to ban [1-65535]. Default is 22222\n"
			"\n", name
			);

}

// Parses command line, returns 0 on success.
int ParseCmdLine(int argc, char **argv)
{
//    char* endptr = NULL;
	int c;
    int ret = 0;
    opterr = 0; //If the value of this variable is nonzero, then getopt prints an error message to the standard error stream if it encounters an unknown option character or an option with a missing required argument. This is the default behavior. If you set this variable to zero, getopt does not print any messages, but it still returns the character ? to indicate an error.
    // int optopt: When getopt encounters an unknown option character or an option with a missing required argument, it stores that option character in this variable. You can use this for providing your own diagnostic messages.
    // int optind: This variable is set by getopt to the index of the next element of the argv array to be processed. Once getopt has found all of the option arguments, you can use this variable to determine where the remaining non-option arguments begin. The initial value of this variable is 1.
    // char * optarg       This variable is set by getopt to point at the value of the option argument, for those options that accept arguments.
    // "abc:" The 3rd "options" argument is a string that specifies the option characters that are valid for this program. An option character in this string can be followed by a colon (‘:’) to indicate that it takes a required argument. If an option character is followed by two colons (‘::’), its argument is optional; this is a GNU extension.

    int temp;

    while ((c = getopt (argc, argv, "hl:vt:p:")) != -1)
    {
      switch (c)
        {
        case 'v':
          gVerbose = 1;
          break;
        case 'h':
          Help(argv[0]);
          return -2;
        case 'l': // read  file name
       		strncpy(szLogfile, optarg, sizeof(szLogfile) - 1);
          break;
        case 't':
        	temp = strtol(optarg, NULL, 10);
        	if(temp >= 30 && temp <= 86400)
        		gTimeToBan = temp;
        	else
        	{
        		printf("Bad time-to-ban=%d, use -h\n", temp);
        		return -1;
        	}
        	break;
        case 'p':
        	temp = strtol(optarg, NULL, 10);
        	if(temp >= 1 && temp <= 65535)
        		gPortToBan = temp;
        	else
        	{
        		printf("Bad port-to-ban=%d, use -h\n", temp);
        		return -1;
        	}
        	break;
        default:
        	printf("Unknown argument, use -h\n");
        	return -1;
        }
    }

    return ret;
}

void CtrlChandler(int s)
{
	printf("Ctrl+C caught, exiting\n");
	//TODO: unblock all items from list
	int i;
	for(i=0; i<nEntries; i++)
	{
		if(pEntries[i].timeBlockedAt != 0)
		{
			char szCmd[256];
			sprintf(szCmd, "/sbin/iptables -D INPUT -s %d.%d.%d.%d -p 6 --dport %d -j DROP",
					pEntries[i].Ip>>24, (pEntries[i].Ip>>16)&0xff, (pEntries[i].Ip>>8) & 0xff, pEntries[i].Ip & 0xff, gPortToBan);
			int ret_syst = system(szCmd);
			printf("Sending command: %s, result = %d\n", szCmd, ret_syst);
			pEntries[i].timeBlockedAt = 0;
		}
	}

	exit(1);
}

void InstallHupHandler()
{
	struct sigaction sigIntHandler;

	sigIntHandler.sa_handler = CtrlChandler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGHUP, &sigIntHandler, NULL);
}


int main(int argc, char* argv[])
{
	int ret = ParseCmdLine(argc, argv);
	if(ret < 0)
		return 1;

	FILE* f = fopen(szLogfile, "rt");
	if(f == NULL)
	{
		printf("Could not open log file %s for reading, error %d\n", szLogfile, errno);
		return 2;
	}
	else
		fclose(f);

	pEntries = (ENTRY*)malloc(10000 * sizeof(ENTRY));
	nEntries = 10000;
	memset(pEntries, 0, 10000 * sizeof(ENTRY));

	while(1)
	{
		sleep(1);

		f = fopen(szLogfile, "rt");
		if(f == NULL)
		{
			printf("Could not open log file %s for reading, error %d\n", szLogfile, errno);
		}
		else
		{
			// Read some last records
			int ret = fseek(f, 0, SEEK_END);
			if(ret == 0)
			{
				int size = ftell(f);
				if(size < 10000)
					printf("Log file is too small (%d)\n", size);
				else
				{
					ret = fseek(f, -10000, SEEK_END);
					char s[1025];
					fgets(s, sizeof(s)-1, f); // read half of string
					while(fgets(s, sizeof(s)-1, f) != NULL)
					{
						// Look for "Failed password"
						char* fpwd = strstr(s, "Failed password");
						if(fpwd != NULL)
						{
//							printf("Found string: \"%s\"", s);
							char szDate[24];
							char szIp[17]; // "255.255.255.255 " followed by "port xxxx"
							strncpy(szDate, s, 15);
							if(szDate[9] == ':' && szDate[12] == ':')
							{
//								printf("Date/time: \"%s\"\n", szDate);
								int hrs = strtol(szDate+7, NULL, 10);
								int min = strtol(szDate+10, NULL, 10);
								int sec = strtol(szDate+13, NULL, 10);
								int TimeAt = hrs*3600 + min*60 + sec; // Time of message

								char* szFrom = strstr(s, " from ");
								if(szFrom != NULL)
								{
									szFrom += 6; // skip " from " - note spaces!!!
									strncpy(szIp, szFrom, sizeof(szIp) - 1);
//									printf("szIp: \"%s\"", szIp);
									int nPoints = 0;
									int i;
									for(i=0; i<sizeof(szIp); i++)
									{
//										printf("szIp[%d]: \"%c\"=%d", i, szIp[i], szIp[i]);
										if(szIp[i] == '.')
											nPoints++;
										if(szIp[i] == ' ')
										{
											szIp[i] = 0;
											break;
										}
									}
									if(nPoints == 3)
									{
										// valid IP address
//										printf("Attack from IP address: \"%s\"\n", szIp);
										int i;
										int idxUnused = -1; // Find first unused storage
										int bNewAttack = 1;
										int octet1 = 0, octet2 = 0, octet3 = 0, octet4 = 0;
										int nScanned = sscanf(szIp, "%d.%d.%d.%d", &octet1, &octet2, &octet3, &octet4);
										uint32_t Ip = octet1 & 0xff; Ip <<= 8;
										Ip += octet2 & 0xff; Ip <<= 8;
										Ip += octet3 & 0xff; Ip <<= 8;
										Ip += octet4 & 0xff;

										// Find this IP in the list of blocked IPs
										for(i=0; i<nEntries; i++)
										{
											ENTRY* p = pEntries + i;
											// Compare entry with found IP
											if(p->nMet != 0) // Entry is not empty
											{
												if(Ip == p->Ip) // We met this IP
												{
													bNewAttack = 0;
													if(p->timeBlockedAt != 0) // If already blocked
														break; // Skip it
													// We did not block it yet. Did we see this entry before?
													if(TimeAt > p->LastTimeSeen || // Time is newer
															p->LastTimeSeen - TimeAt > 60000) // or wraparound at midnight, use some big value around 86400
													{
														p->LastTimeSeen = TimeAt;
														p->nMet++;
														printf("Attack #%d from IP %d.%d.%d.%d\n", p->nMet, p->Ip>>24, (p->Ip>>16)&0xff,
																(p->Ip>>8) & 0xff, p->Ip & 0xff);

														if(p->nMet >= BLOCK_AFTER_NUM_ATTACKS)
														{
															printf("Blocking this bastard from %d.%d.%d.%d (TODO)\n", p->Ip>>24, (p->Ip>>16)&0xff,
																	(p->Ip>>8) & 0xff, p->Ip & 0xff);

															// Blocking
															char szCmd[256];
															sprintf(szCmd, "/sbin/iptables -I INPUT 1 -s %d.%d.%d.%d -p 6 --dport %d -j DROP",
																	p->Ip>>24, (p->Ip>>16)&0xff, (p->Ip>>8) & 0xff, p->Ip & 0xff, gPortToBan);
															int ret_syst = system(szCmd);
															printf("Sending command: %s, result = %d\n", szCmd, ret_syst);
															p->timeBlockedAt = time(NULL);
														}
													}
													// otherwise we already saw this line so ignoring it.

													break; // Processed the line
												}
											}
											else
											{
												// This entry is empty, remember its index
												if(idxUnused < 0)
													idxUnused = i;
											}
										}

										if(bNewAttack != 0)
										{
											// Add it into list
											if(idxUnused >= 0) // we have spare unit
											{
												pEntries[idxUnused].LastTimeSeen = TimeAt;
												pEntries[idxUnused].nMet = 1;
												pEntries[idxUnused].Ip = Ip;
												pEntries[idxUnused].timeBlockedAt = 0;
												printf("Added bastard from %d.%d.%d.%d into entry %d\n", Ip>>24, (Ip>>16)&0xff,
														(Ip>>8) & 0xff, Ip & 0xff, idxUnused);
											}
											else
												printf("No spare entry to add attacker from %s\n", szIp);
										}

									}
									else
										printf("Could not extract IP from: \"%s\"", s);

								}
							}
							else
							{
								printf("Could not extract date/time from \"%s\"\n", s);
							}
						}
					}
				}
			}
			else
				printf("Log file seek error %d\n", errno);

			fclose(f);
		}

	}

	return 0;
}
