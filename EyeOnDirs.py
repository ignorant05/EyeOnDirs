#Tool made by oussama baccara aka ignorant05.
#Copyright disclaimer : This tool runs under my name, so please don't be silly and copy the code and act like it's yours...If you do then idc.
#Usage only for ethical purposes and i don't recognise any unethical usage.

##############################################################################################################################################################################

#! /usr/bin/env python3

##############################################################################################################################################################################

import requests 
from requests.exceptions import RequestException, ConnectionError, Timeout

import urllib3
from urllib3.exceptions import NewConnectionError

import threading
import resource

import logging 
from prettytable import PrettyTable
from tqdm import tqdm

import re 
import os

import argparse

##############################################################################################################################################################################

class ParsingArgs:
    
    @staticmethod
    def Parse():
        
        tool_description = "A directory enumerating tool to discover hidden directories and files on a web server."

        parser= argparse.ArgumentParser(
            description=tool_description,
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument(
            "-url", type=str, required=True, help="IP or link : example : http://IP_address or http://example.com."
        )
        parser.add_argument(
            "-wordlist", type=str, required=True, help="Path to wordlist."
        )
        parser.add_argument(
            "-t", type=int, default=10, help="Set timeout for each line (default value = 10)."
        )
        parser.add_argument(
            "-threads", type=int, default=100, help="Set the number of threads as you wish (default value = 100)."
        )
        parser.add_argument(
            "--recursive","-r",action="store_true", help="Search recursively in the dir and stops when a file is found."
        )
        parser.add_argument(
            "-e","--extention", nargs='+', dest="e", type=str,help="Look for a file(s) with specific extention(s)."
        )
        parser.add_argument(
            "-sd","--sub-domains", action="store_true",help="Enumerate Sub-Domains of a given URL."
        )
        return parser.parse_args()

    @staticmethod
    def ParseArgs(extensions) :
        exts = set()
        for ext in extensions :
            for i in ext.split(","): 
                exts.add(i.strip())
        return exts

##############################################################################################################################################################################

class Display: 

    @staticmethod
    def DisplayOutputs(Available, Unauthorized, Forbidden, MovedPermenantly, InternalServerError):
        
        outputs = PrettyTable()
        outputs.field_names=["Available", "Unauthorized", "Forbidden", "Moved Permenantly", "Internal Server Error"]

        max_len = max(len(Available), len(Unauthorized), len(Forbidden), len(MovedPermenantly), len(InternalServerError))

        for i in range(max_len):

            Ok = Available[i] if i < len(Available) else "-"
            NotAuth = Unauthorized[i] if i < len(Unauthorized) else "-"
            NotAllowed = Forbidden[i] if i < len(Forbidden) else "-"
            NotHere = MovedPermenantly[i] if i < len(MovedPermenantly) else "-"
            Error = InternalServerError[i] if i < len(InternalServerError) else "-"

            outputs.add_row([Ok, NotAuth, NotAllowed, NotHere, Error])

        print(outputs)
        logging.info("Scan complete")

    @staticmethod
    def DisplayInputs():

        args = ParsingArgs.Parse()
        url = args.url 
        path=args.wordlist
        threads=args.threads
        timeout=args.t
        rec=args.recursive
        if (not args.sub_domains) and args.e :
    
            extensions = set()
            exts=args.e
            for e in exts :
                extensions.add(e.strip(","))
        else :  
            pass

        max_os_threads = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        max_threads = max(threads, max_os_threads)

        os.system('clear') 
        print(f"[&] Enumerating                        : {url}")
        print(f"[&] Wordlist                           : {path}")
        print(f"[&] Threads number selected            : {threads}/{max_threads} ")
        print(f"[&] Time-out chosen                    : {timeout}")
        if (not args.sub_domains) and args.e :
            print(f"[&] Extensions specification for files : {', '.join(ext for ext in extensions)}")
        print(f"[&] Recursive option                   : {'Enabled' if rec else 'Disabled'}\n")

##############################################################################################################################################################################

class Check : 

    def CheckURL(target):

        pattern1 =  r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        
        pattern2 = r"https?:\/\/[a-zA-Z\.\-]+\.[a-zA-z]{2,}(:[0-9]{1,5})?(\/.*)?$"

        if re.match(pattern1, target) or re.match(pattern2, target):
            return True 
        else : 
            return False
        
    def CheckWordlistPath (path):

        if os.path.exists(path):
            return True 
        else : 
            ErrorHandling.CheckWordlist()
            return False 

##############################################################################################################################################################################

class ErrorHandling : 

    @staticmethod
    def CheckWordlist (path):

        try :
            with open(path, 'r'):
                pass

        except FileNotFoundError :
            logging.error("[-] File not found, please provide a valid path for the wordlist.")
        except (PermissionError, Exception) as e : 
            logging.error("[-] Permission error for file.")

##############################################################################################################################################################################

class Multithreading : 

    def __init__(self, target, path2wordlist, threads_number, time_out):

        self.target=target
        self.path2wordlist = path2wordlist
        self.threads_number=threads_number
        self.time_out=time_out
        self.lock = threading.Lock()

        self.Available = []
        self.Unauthorized = []
        self.Forbidden = []
        self.MovedPermanently = []
        self.InternalServerError = []

        max_os_threads = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        self.max_threads = min(self.threads_number, max_os_threads)

    def SplitTheWork(self):

        threads=[]

        with open(self.path2wordlist,'r') as wordlist :
            wordlist_lines=wordlist.readlines()
            progress_bar = tqdm(total=len(wordlist_lines), desc="Enumerating directories", unit="dir")

            for line in wordlist_lines : 

                line = line.strip()
                thread = threading.Thread(target=self.Start, args=(line,))
                threads.append(thread)
                thread.start()

                progress_bar.update(1)

                if len(threads) >= self.max_threads:
                    for t in threads:
                        t.join()  
                        
                    threads = []

            progress_bar.close()    

            for t in threads:
                t.join() 

        logging.info("All threads have completed.")

    def Start (self):
        if self.stop_event.is_set():
            return
        raise NotImplementedError("Subclasses must implement this method.")
    
##############################################################################################################################################################################

class Enumerate (Multithreading): 

    def __init__(self, target, path2wordlist, threads_number, time_out, recursive , Available, Unauthorized, Forbidden, MovedPermanently, InternalServerError):
        
        super().__init__(target, path2wordlist, threads_number, time_out)
        self.lock = threading.Lock()

        self.Available= Available
        self.Unauthorized=Unauthorized
        self.Forbidden=Forbidden
        self.MovedPermanently=MovedPermanently
        self.InternalServerError=InternalServerError
        self.recursive = recursive
        
    def Start(self, dir):

        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            path = self.target +dir
            response = requests.get(path, timeout=self.time_out, verify=False)

            with self.lock:
                if response.status_code == 200 :
                    if dir.endswith("/") or not re.search(r"\.[a-zA-Z]{2,}$", dir): 
                        if args.recursive : 
                            self.Start(path)
                    else : 
                        self.Available.append(dir)
                elif response.status_code==301 :
                    self.MovedPermanently.append(dir)
                elif response.status_code==401 :
                    self.Unauthorized.append(dir)
                elif response.status_code==403 :
                    self.Forbidden.append(dir)
                elif response.status_code==500 :
                    self.InternalServerError.append(dir)
                else :
                    pass

        except (ConnectionError, Timeout) as e:
            pass
        except NewConnectionError as e:
            logging.error(f"[-] DNS resolution failed for {path}: {e}")
        except RequestException as e:
            logging.error(f"[-] HTTP request failed: {e}")

##############################################################################################################################################################################

class EnumerateFilesWithSpecifiedExtention (Multithreading): 

    def __init__(self, target, path2wordlist, threads_number, time_out,recursive, e, Available, Unauthorized, Forbidden, MovedPermanently, InternalServerError):
        
        super().__init__(target, path2wordlist, threads_number, time_out)
        self.lock = threading.Lock()

        self.Available= Available
        self.Unauthorized=Unauthorized
        self.Forbidden=Forbidden
        self.MovedPermanently=MovedPermanently
        self.InternalServerError=InternalServerError
        self.recursive = recursive

        self.e = e
    
    def Start(self, dir):

        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            path = self.target +dir
            response = requests.get(path, timeout=self.time_out, verify=False)

            with self.lock:
                if response.status_code == 200 :
                    if dir.endswith("/") or not re.search(r"\.[a-zA-Z]{2,}$", dir): 
                        if args.recursive : 
                            self.Start(path)
                    else : 
                        for ext in self.extention:
                            if dir[dir.index(".")+1:] == ext:
                                self.Available.append(dir)
                            else : 
                                break
                elif response.status_code==301 :
                    self.MovedPermanently.append(dir)
                elif response.status_code==401 :
                    self.Unauthorized.append(dir)
                elif response.status_code==403 :
                    self.Forbidden.append(dir)
                elif response.status_code==500 :
                    self.InternalServerError.append(dir)
                else :
                    pass

        except (ConnectionError, Timeout) as e:
            pass
        except NewConnectionError as e:
            logging.error(f"[-] DNS resolution failed for {path}: {e}")
        except RequestException as e:
            logging.error(f"[-] HTTP request failed: {e}")

##############################################################################################################################################################################

class EnumerateSubDomains (Multithreading):

    def __init__(self, target, path2wordlist, threads_number, time_out, sub_domains, Available, Unauthorized, Forbidden, MovedPermanently, InternalServerError):
        
        super().__init__(target, path2wordlist, threads_number, time_out)
        self.lock = threading.Lock()

        self.Available= Available
        self.Unauthorized=Unauthorized
        self.Forbidden=Forbidden
        self.MovedPermanently=MovedPermanently
        self.InternalServerError=InternalServerError

        self.sub_domains=sub_domains

    def Start(self,subdomain):
        try :
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            path = self.target.split("//")[0] + "//" + subdomain + "." + self.target.split("//")[1]
            response = requests.get(path, timeout=self.time_out, verify=False)

            with self.lock:
                if response.status_code == 200 :
                    self.Available.append(subdomain)
                elif response.status_code==301 :
                    self.MovedPermanently.append(dir)
                elif response.status_code==401 :
                    self.Unauthorized.append(dir)
                elif response.status_code==403 :
                    self.Forbidden.append(dir)
                elif response.status_code==500 :
                    self.InternalServerError.append(dir)
                else :
                    pass

        except (ConnectionError, Timeout) as e:
            pass
        except NewConnectionError as e:
            logging.error(f"[-] DNS resolution failed for {path}: {e}")
        except RequestException as e:
            logging.error(f"[-] HTTP request failed: {e}")

##############################################################################################################################################################################

if __name__ =="__main__":
    
    try:
        args=ParsingArgs.Parse()
        if not Check.CheckURL(args.url):
            logging.error("[-] Invalid URL")
            exit(1)

        if not Check.CheckWordlistPath(args.wordlist):
            logging.error("[-] Invalid path to wordlist")
            exit(1)

        display = Display()
        display.DisplayInputs()

        if args.sub_domains :
            enumerator = EnumerateSubDomains(
                    target=args.url,
                    path2wordlist=args.wordlist,
                    threads_number=args.threads,
                    time_out=args.t,
                    sub_domains=args.sub_domains,
                    Available=[],
                    Unauthorized=[],
                    Forbidden=[],
                    MovedPermanently=[],
                    InternalServerError=[]
                )

        else :    
            if args.e: 
                ext = ParsingArgs.ParseArgs(args.e)

                enumerator = EnumerateFilesWithSpecifiedExtention(
                    target=args.url,
                    path2wordlist=args.wordlist,
                    threads_number=args.threads,
                    time_out=args.t,
                    recursive=args.recursive,
                    e=ext,
                    Available=[],
                    Unauthorized=[],
                    Forbidden=[],
                    MovedPermanently=[],
                    InternalServerError=[]
                )
            else : 
                
                enumerator = Enumerate(
                    target=args.url,
                    path2wordlist=args.wordlist,
                    threads_number=args.threads,
                    time_out=args.t,
                    recursive=args.recursive,
                    Available=[],
                    Unauthorized=[],
                    Forbidden=[],
                    MovedPermanently=[],
                    InternalServerError=[]
                )

        enumerator.SplitTheWork()

        display.DisplayOutputs(
            enumerator.Available,
            enumerator.Unauthorized,
            enumerator.Forbidden,
            enumerator.MovedPermanently,
            enumerator.InternalServerError
        )
        
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Stopping the scan...")
    except Exception as e:
        logging.error(f"[-] An unexpected error occurred: {e}")
    finally:
        print("Exiting the program.")

##############################################################################################################################################################################
