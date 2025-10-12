"""Interactive console for Link-Chat (basic).

Features:
- List network interfaces and detect MAC for a chosen interface (Linux-only).
- Start receiver in background and print incoming frames/payloads.
- Send text messages to a given destination MAC.

Notes: Requires root for raw sockets. Uses only Python stdlib.
"""
import sys
import threading
import socket
import fcntl
import struct
import time
# remove: from .discovery import send_text, ETH_DISCOVERY, DISCOVER, peer_table
from .discovery import ETH_DISCOVERY, send_discover_broadcast, peer_table
from .sender import send_text  # sender's send_text is the packet sender
import json


from .frame import mac_bytes_to_str
from .receiver import receive_frames, print_handler
from .sender import send_text, send_file


def get_interfaces():
    # Minimal implementation: parse /sys/class/net
    try:
        import os
        ifs = [name for name in os.listdir('/sys/class/net')]
        return ifs
    except Exception:
        return []


def get_iface_mac(ifname):
    # Linux ioctl SIOCGIFHWADDR
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname.encode('utf-8')[:15]))
        mac = info[18:24]
        return mac_bytes_to_str(mac)
    finally:
        s.close()


class CLI:
    def __init__(self):
        self.iface = None
        self.iface_mac = None
        self.receiver_thread = None
        self.running = False

    def choose_interface(self):
        ifs = get_interfaces()
        if not ifs:
            print('No interfaces found')
            return
        print('Available interfaces:')
        for i, itf in enumerate(ifs):
            print(f'  {i}) {itf}')
        sel = input('Choose interface number (default 0): ').strip()
        if sel == '':
            sel = '0'
        try:
            idx = int(sel)
            self.iface = ifs[idx]
            self.iface_mac = get_iface_mac(self.iface)
            print(f'Using interface {self.iface} with MAC {self.iface_mac}')
        except Exception as e:
            print('Invalid selection:', e)

    def start_receiver(self):
        if not self.iface:
            print('Select interface first')
            return

        def runner():
            try:
                receive_frames(interface=self.iface, handler=print_handler)
            except Exception as e:
                print('Receiver stopped:', e)

        self.receiver_thread = threading.Thread(target=runner, daemon=True)
        self.receiver_thread.start()
        print('Receiver started in background')

    def send(self, dst_mac, message):
        if not self.iface:
            print('Select interface first')
            return
        ETH_CHAT = 0x88b5
        try:
            send_text(dst_mac, self.iface_mac, ETH_CHAT, message, interface=self.iface)
            print('Message sent')
        except PermissionError:
            print('Permission denied: running as root is required to send raw frames')
        except Exception as e:
            print('Send error:', e)

    def repl(self):
        print('Link-Chat CLI. type "help" for commands')
        while True:
            cmd = input('> ').strip()
            if not cmd:
                continue
            parts = cmd.split(' ', 2)
            c = parts[0].lower()
            if c in ('q', 'quit', 'exit'):
                print('Exiting')
                return
            if c == 'help':
                print('Commands:')
                print('  iface       - choose interface')
                print('  start       - start receiver in background')
                print('  send <mac> <message> - send text message')
                print('  info        - show chosen interface and MAC')
                print('  quit        - exit')
                continue
            if c == 'iface':
                self.choose_interface()
                continue
            if c == 'start':
                self.start_receiver()
                continue
            if c == 'info':
                print('iface=', self.iface, 'mac=', self.iface_mac)
                continue
            if c == 'send':
                if len(parts) < 3:
                    print('Usage: send <mac> <message>')
                    continue
                dst = parts[1]
                msg = parts[2]
                self.send(dst, msg)
                continue
            if c == 'send-file':
                # usage: send-file <mac> <path>
                if len(parts) < 3:
                    print('Usage: send-file <mac> <path>')
                    continue
                dst = parts[1]
                path = parts[2]
                try:
                    send_file(dst, self.iface_mac, path, interface=self.iface)
                    print('File sent (best-effort)')
                except Exception as e:
                    print('send-file error:', e)
                continue
            if c == "discover":
                if not self.iface:
                    print("Select interface first")
                    continue
                # send a single broadcast discovery; peers will reply with HELLO
                try:
                    send_discover_broadcast(self.iface)
                except Exception as e:
                    print("Discovery send failed:", e)
                    continue
                print("Discovery broadcast sent. Waiting for replies...")
                # wait a short time to collect replies (non-busy; sleep in main thread is OK here)
                time.sleep(2.0)
                peers = peer_table.get_active(timeout=10)
                if not peers:
                    print("No peers found.")
                else:
                    print("Peers discovered:")
                    for mac, (name, seen) in peers.items():
                        age = int(time.time() - seen)
                        print(f"  {name} ({mac}) - seen {age}s ago")
                continue


def main():
    cli = CLI()
    cli.repl()


if __name__ == '__main__':
    main()
