# linkchat/gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import queue
import time
import socket
import tarfile
import tempfile

# Internal imports
from linkchat.discovery import handle_discovery_frame, ETH_DISCOVERY, send_discover_broadcast, peer_table
from linkchat.sender import send_text, send_file, get_iface_mac, ETH_CHAT


from linkchat.frame import mac_bytes_to_str



event_queue = queue.Queue()


def list_interfaces():
    try:
        return [name for idx, name in socket.if_nameindex()]
    except Exception:
        return []


def receiver_thread(interface, callback_queue):
    """
    Background thread for receiving frames and pushing structured events to the GUI.
    Same logic as CLI receiver, but minimal output.
    """
    from linkchat.receiver import receive_frames
    from linkchat.receiver import print_handler
    from linkchat.discovery import ETH_DISCOVERY, handle_discovery_frame
    from linkchat.sender import get_iface_mac

    local_mac = get_iface_mac(interface).lower()
    ETH_CHAT = 0x88b5

    def gui_handler(frame, raw, addr):
        try:
            if frame is None or not frame.payload:
                return

            eth = frame.ethertype_int()
            src_mac = frame.src_mac_str().lower()

            # Ignore our own frames
            if src_mac == local_mac:
                return

            # Discovery frame
            if eth == ETH_DISCOVERY:
                try:
                    handle_discovery_frame(frame, interface)
                    callback_queue.put(("system", f"Discovery from {src_mac}"))
                except Exception as e:
                    callback_queue.put(("system", f"Discovery error: {e}"))
                return

            if eth != ETH_CHAT:
                return

            msg_type = frame.payload[0]

            # Handle file transfers — only announce when complete
            if msg_type == 3:  # FILE_END
                callback_queue.put(("file", {"src": src_mac, "info": "File/folder received successfully."}))
                return

            # Regular text message
            try:
                text = frame.payload.decode("utf-8", errors="replace")
                callback_queue.put(("message", {"src": src_mac, "text": text}))
            except Exception:
                callback_queue.put(("system", f"Decode error from {src_mac}"))

        except Exception as e:
            callback_queue.put(("system", f"Receiver handler error: {e}"))

    try:
        receive_frames(interface=interface, handler=gui_handler)
    except Exception as e:
        callback_queue.put(("system", f"Receiver stopped: {e}"))




class InterfaceSelector(tk.Toplevel):
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
        self.master.geometry("820x560")

        self.interface = None
        self.devices = {}
        self.chat_tabs = {}
        self.broadcast_mac = "ff:ff:ff:ff:ff:ff"

        self.select_interface()

    # --- Interface selection ---
    def select_interface(self):
        self.master.withdraw()
        InterfaceSelector(self.master, self.after_interface_selected)

    def after_interface_selected(self, iface):
        self.interface = iface
        self.master.deiconify()
        self.build_ui()
        self.start_receiver()

    # --- GUI setup ---
    def build_ui(self):
        frame_top = tk.Frame(self.master)
        frame_top.pack(fill=tk.X, padx=10, pady=6)
        tk.Label(frame_top, text=f"Discovered Devices (Interface: {self.interface})").pack(side=tk.LEFT)
        tk.Button(frame_top, text="🔄 Refresh", command=self.refresh_devices).pack(side=tk.RIGHT)

        self.device_list = tk.Listbox(self.master, height=6)
        self.device_list.pack(fill=tk.X, padx=10, pady=5)
        self.device_list.bind("<Double-Button-1>", self.open_selected_chat)

        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        # Broadcast tab
        self.create_chat_tab(self.broadcast_mac, "Broadcast")

        frame_bottom = tk.Frame(self.master)
        frame_bottom.pack(fill=tk.X, padx=10, pady=6)
        self.entry_msg = tk.Entry(frame_bottom)
        self.entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        tk.Button(frame_bottom, text="Send", command=self.send_message).pack(side=tk.LEFT, padx=6)
        tk.Button(frame_bottom, text="📁 File", command=self.send_file_cmd).pack(side=tk.LEFT, padx=6)
        tk.Button(frame_bottom, text="📂 Folder", command=self.send_folder_cmd).pack(side=tk.LEFT, padx=6)

        self.master.after(250, self.process_events)

    # --- Core logic ---
    def create_chat_tab(self, mac, title):
        if mac in self.chat_tabs:
            return
        frame = ttk.Frame(self.notebook)
        text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, state='disabled', height=20)
        text.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(frame, text=title)
        self.chat_tabs[mac] = text

    def append_chat(self, mac, text):
        if mac not in self.chat_tabs:
            name = self.devices.get(mac, (mac, 0))[0]
            self.create_chat_tab(mac, name)
        widget = self.chat_tabs[mac]
        widget.configure(state='normal')
        widget.insert(tk.END, text + "\n")
        widget.configure(state='disabled')
        widget.see(tk.END)

    def get_active_mac(self):
        idx = self.notebook.index(self.notebook.select())
        title = self.notebook.tab(idx, "text")
        if title == "Broadcast":
            return self.broadcast_mac
        for mac, (name, _) in self.devices.items():
            if name == title:
                return mac
        return None

    def refresh_devices(self):
        try:
            send_discover_broadcast(self.interface)
        except Exception as e:
            self.append_chat(self.broadcast_mac, f"[System] Discovery send failed: {e}")
            return
        time.sleep(1.0)
        peers = peer_table.get_active(timeout=10)
        self.device_list.delete(0, tk.END)
        self.devices = {}
        for mac, (name, seen) in peers.items():
            age = int(time.time() - seen)
            self.devices[mac] = (name, seen)
            self.device_list.insert(tk.END, f"{name} ({mac}) - {age}s")
            self.create_chat_tab(mac, name)
        if not peers:
            self.append_chat(self.broadcast_mac, "[System] No peers discovered (try again).")

    def start_receiver(self):
        t = threading.Thread(target=receiver_thread, args=(self.interface, event_queue), daemon=True)
        t.start()

    def process_events(self):
        try:
            while True:
                event_type, data = event_queue.get_nowait()
                if event_type == "message":
                    mac = data["src"]
                    self.append_chat(mac, f"[{mac}] {data['text']}")
                elif event_type == "file":
                    mac = data["src"]
                    self.append_chat(mac, f"[File from {mac}] {data['info']}")
                elif event_type == "system":
                    self.append_chat(self.broadcast_mac, f"[System] {data}")
        except queue.Empty:
            pass
        self.master.after(250, self.process_events)

    # --- Chat actions ---
    def open_selected_chat(self, _):
        sel = self.device_list.curselection()
        if not sel:
            return
        mac = list(self.devices.keys())[sel[0]]
        name = self.devices[mac][0]
        self.create_chat_tab(mac, name)
        for i in range(self.notebook.index("end")):
            if self.notebook.tab(i, "text") == name:
                self.notebook.select(i)
                break

    def send_message(self):
        mac = self.get_active_mac()
        msg = self.entry_msg.get().strip()
        if not msg:
            return

        try:
            send_text(mac, None, ETH_CHAT, msg, interface=self.interface)
            if mac == self.broadcast_mac:
                # Only append to the Broadcast tab
                self.append_chat(self.broadcast_mac, f"[You → BROADCAST] {msg}")
            else:
                self.append_chat(mac, f"[You → {mac}] {msg}")
        except Exception as e:
            self.append_chat(self.broadcast_mac, f"[System] Send error: {e}")
        self.entry_msg.delete(0, tk.END)

    def send_file_cmd(self):
        mac = self.get_active_mac()
        if not mac:
            self.append_chat(self.broadcast_mac, "[System] No device selected.")
            return
        path = filedialog.askopenfilename(title="Select file to send")
        if not path:
            return
        try:
            send_file(mac, None, path, interface=self.interface)
            self.append_chat(mac, f"[You → {mac}] Sent file: {os.path.basename(path)}")
        except Exception as e:
            self.append_chat(mac, f"[System] File send error: {e}")

    def send_folder_cmd(self):
        mac = self.get_active_mac()
        if not mac:
            self.append_chat(self.broadcast_mac, "[System] No device selected.")
            return

        folder = filedialog.askdirectory(title="Select folder to send")
        if not folder:
            return

        try:
            from linkchat.sender import send_folder
            send_folder(mac, None, folder, interface=self.interface)
            folder_name = os.path.basename(os.path.abspath(folder))
            self.append_chat(mac, f"[You → {mac}] Sent folder: {folder_name}")
        except Exception as e:
            self.append_chat(self.broadcast_mac, f"[System] Folder send error: {e}")



if __name__ == "__main__":
    root = tk.Tk()
    app = LinkChatApp(root)
    root.mainloop()
