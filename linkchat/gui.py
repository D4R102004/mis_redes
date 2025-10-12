# linkchat/gui.py
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import os
import queue
import time
import socket

# Package imports
from linkchat.sender import send_text, send_file, ETH_CHAT
from linkchat.discovery import send_discover_broadcast, peer_table
from linkchat.receiver import receive_frames
from linkchat.frame import mac_bytes_to_str

# --- Shared event queue between threads ---
event_queue = queue.Queue()


def list_interfaces():
    """Return list of (index, name) network interfaces."""
    try:
        return [name for idx, name in socket.if_nameindex()]
    except Exception:
        return []


def receiver_thread(interface, callback_queue):
    """Run receive_frames and forward useful events into callback_queue."""
    def handler(frame, raw, addr):
        if frame is None:
            return
        try:
            eth = frame.ethertype_int()
        except Exception:
            return

        if eth != ETH_CHAT:
            return

        payload = frame.payload or b""
        if not payload:
            return

        first = payload[0]
        if first in (1, 2, 3, 4):
            src = frame.src_mac_str()
            callback_queue.put(("file", {"src": src, "info": f"file frame type {first} received"}))
            return

        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            text = repr(payload)
        callback_queue.put(("message", {"src": frame.src_mac_str(), "text": text}))

    try:
        receive_frames(interface=interface, handler=handler)
    except Exception as e:
        callback_queue.put(("system", {"text": f"Receiver stopped: {e}"}))


class InterfaceSelector(tk.Toplevel):
    """Small popup to choose a network interface before starting the app."""
    def __init__(self, master, on_select):
        super().__init__(master)
        self.title("Select Interface")
        self.geometry("300x150")
        self.on_select = on_select

        tk.Label(self, text="Select a network interface:").pack(pady=10)
        self.iface_listbox = tk.Listbox(self, height=6)
        self.iface_listbox.pack(fill=tk.BOTH, expand=True, padx=10)

        for iface in list_interfaces():
            self.iface_listbox.insert(tk.END, iface)

        tk.Button(self, text="OK", command=self.confirm).pack(pady=8)

    def confirm(self):
        sel = self.iface_listbox.curselection()
        if not sel:
            messagebox.showerror("Error", "Please select an interface.")
            return
        iface = self.iface_listbox.get(sel[0])
        self.on_select(iface)
        self.destroy()


class LinkChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Link-Chat GUI")
        self.master.geometry("760x520")
        self.interface = None
        self.devices = {}

        # UI placeholders (built after iface selection)
        self.chat_area = None
        self.device_list = None
        self.entry_msg = None

        # Show interface selector first
        self.select_interface()

    def select_interface(self):
        """Show the interface selector popup before initializing main UI."""
        self.master.withdraw()  # hide main window until interface chosen

        def on_iface_selected(iface):
            self.interface = iface
            self.master.deiconify()
            self.build_ui()
            self.start_receiver()

        InterfaceSelector(self.master, on_iface_selected)

    def build_ui(self):
        """Build main GUI layout after interface is chosen."""
        frame_top = tk.Frame(self.master)
        frame_top.pack(fill=tk.X, padx=10, pady=6)
        tk.Label(frame_top, text=f"Discovered Devices (Interface: {self.interface})").pack(side=tk.LEFT)
        tk.Button(frame_top, text="🔄 Refresh", command=self.refresh_devices).pack(side=tk.RIGHT, padx=6)

        self.device_list = tk.Listbox(self.master, height=5)
        self.device_list.pack(fill=tk.X, padx=10, pady=4)

        self.chat_area = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, state='disabled', height=20)
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        frame_bottom = tk.Frame(self.master)
        frame_bottom.pack(fill=tk.X, padx=10, pady=6)
        self.entry_msg = tk.Entry(frame_bottom)
        self.entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        tk.Button(frame_bottom, text="Send", command=self.send_message).pack(side=tk.LEFT, padx=6)
        tk.Button(frame_bottom, text="📁 File", command=self.send_file_folder).pack(side=tk.LEFT, padx=6)
        tk.Button(frame_bottom, text="📂 Folder", command=self.send_folder).pack(side=tk.LEFT, padx=6)

        self.master.after(250, self.process_events)

    def start_receiver(self):
        """Launch receiver thread for the chosen interface."""
        t = threading.Thread(target=receiver_thread, args=(self.interface, event_queue), daemon=True)
        t.start()

    def refresh_devices(self):
        try:
            send_discover_broadcast(self.interface)
        except Exception as e:
            self.append_chat(f"[System] Discovery send failed: {e}")
            return
        time.sleep(1.0)
        peers = peer_table.get_active(timeout=10)
        self.device_list.delete(0, tk.END)
        self.devices = {}
        for mac, (name, seen) in peers.items():
            age = int(time.time() - seen)
            self.devices[mac] = (name, seen)
            self.device_list.insert(tk.END, f"{name} ({mac}) - {age}s")

        if not peers:
            self.append_chat("[System] No peers discovered (try Refresh again).")

    def append_chat(self, text):
        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, text + "\n")
        self.chat_area.configure(state='disabled')
        self.chat_area.see(tk.END)

    def process_events(self):
        try:
            while True:
                event_type, data = event_queue.get_nowait()
                if event_type == "message":
                    self.append_chat(f"[{data['src']}] {data['text']}")
                elif event_type == "file":
                    self.append_chat(f"[File from {data['src']}] {data.get('info','')}")
                elif event_type == "system":
                    self.append_chat(f"[System] {data.get('text')}")
        except queue.Empty:
            pass
        self.master.after(250, self.process_events)

    def get_selected_mac(self):
        sel = self.device_list.curselection()
        if not sel:
            return None
        return list(self.devices.keys())[sel[0]]

    def send_message(self):
        mac = self.get_selected_mac()
        if not mac:
            self.append_chat("[System] No device selected.")
            return
        msg = self.entry_msg.get().strip()
        if not msg:
            return
        try:
            send_text(mac, None, ETH_CHAT, msg, interface=self.interface)
            self.append_chat(f"[You → {mac}] {msg}")
            self.entry_msg.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send error", str(e))

    def send_file_folder(self):
        mac = self.get_selected_mac()
        if not mac:
            self.append_chat("[System] No device selected.")
            return
        path = filedialog.askopenfilename(title="Select file to send")
        if not path:
            return
        try:
            send_file(mac, None, path, interface=self.interface)
            self.append_chat(f"[You → {mac}] Sent file {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Send error", str(e))

    def send_folder(self):
        mac = self.get_selected_mac()
        if not mac:
            self.append_chat("[System] No device selected.")
            return
        folder = filedialog.askdirectory(title="Select folder to send")
        if not folder:
            return
        try:
            import tempfile, tarfile
            tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
            tmp.close()
            with tarfile.open(tmp.name, "w") as tf:
                tf.add(folder, arcname=os.path.basename(folder))
            send_file(mac, None, tmp.name, interface=self.interface)
            self.append_chat(f"[You → {mac}] Sent folder {os.path.basename(folder)} (as tar)")
            os.unlink(tmp.name)
        except Exception as e:
            messagebox.showerror("Send folder error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = LinkChatApp(root)
    root.mainloop()
