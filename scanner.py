import tkinter as tk
from tkinter import ttk, messagebox
import ctypes
from ctypes import wintypes
import struct
import psutil

# Настройка WinAPI
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
OpenProcess = kernel32.OpenProcess
ReadProcessMemory = kernel32.ReadProcessMemory
WriteProcessMemory = kernel32.WriteProcessMemory
CloseHandle = kernel32.CloseHandle

PROCESS_ALL_ACCESS = 0x1F0FFF
MAX_VALUE_LENGTH = 4096

class MemoryScanner:
    def __init__(self):
        self.process_id = None
        self.process_handle = None
        self.last_scan_results = []
        self.value_type = 'int'
        self.current_value = None

    def open_process(self, pid):
        self.process_id = pid
        self.process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return self.process_handle is not None

    def scan_memory(self, value, value_type='int', first_scan=True):
        self.value_type = value_type
        self.current_value = value
        matches = []

        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            if proc.pid != self.process_id:
                continue

            try:
                mem_info = proc.memory_info()
                regions = self.get_memory_regions(mem_info.vms)
                
                for addr, size in regions:
                    buffer = ctypes.create_string_buffer(size)
                    bytes_read = wintypes.SIZE_T()
                    
                    if ReadProcessMemory(self.process_handle, addr, buffer, size, ctypes.byref(bytes_read)):
                        data = buffer.raw
                        for i in range(len(data) - 4):
                            self.check_value(data[i:i+4], addr + i, matches)
            except Exception as e:
                continue

        if first_scan:
            self.last_scan_results = matches
        else:
            self.last_scan_results = [m for m in self.last_scan_results if m in matches]
        
        return self.last_scan_results

    def check_value(self, data, address, matches):
        try:
            if self.value_type == 'int':
                value = struct.unpack('i', data)[0]
                if value == int(self.current_value):
                    matches.append(address)
            elif self.value_type == 'float':
                value = struct.unpack('f', data)[0]
                if abs(value - float(self.current_value)) < 0.0001:
                    matches.append(address)
            elif self.value_type == 'string':
                if data.decode('utf-8', errors='ignore').startswith(self.current_value):
                    matches.append(address)
        except:
            pass

    def get_memory_regions(self, vms):
        regions = []
        address = 0
        while address < vms:
            mbi = self.query_memory(address)
            if mbi.RegionSize == 0:
                break
            if mbi.State == 0x1000 and mbi.Protect in (0x04, 0x20, 0x40):
                regions.append((address, mbi.RegionSize))
            address += mbi.RegionSize
        return regions

    def query_memory(self, address):
        mbi = wintypes.MEMORY_BASIC_INFORMATION()
        kernel32.VirtualQueryEx(self.process_handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi))
        return mbi

class GameCheatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PyMemory Scanner")
        self.root.geometry("800x600")
        self.scanner = MemoryScanner()
        self.selected_process = None
        self.setup_ui()
        self.update_process_list()

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', padding=6, relief='flat', background='#4a7a8c')
        style.configure('TLabel', background='#333333', foreground='white')
        style.configure('TEntry', fieldbackground='#555555', foreground='white')
        style.configure('TCombobox', fieldbackground='#555555', foreground='white')

        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Список процессов
        self.process_list = ttk.Treeview(main_frame, columns=('pid', 'name'), show='headings')
        self.process_list.heading('pid', text='PID')
        self.process_list.heading('name', text='Process Name')
        self.process_list.column('pid', width=100)
        self.process_list.column('name', width=300)
        self.process_list.pack(fill=tk.X, pady=5)
        self.process_list.bind('<<TreeviewSelect>>', self.on_process_select)

        # Параметры сканирования
        scan_frame = ttk.Frame(main_frame)
        scan_frame.pack(fill=tk.X, pady=5)

        self.value_entry = ttk.Entry(scan_frame)
        self.value_entry.pack(side=tk.LEFT, padx=5)

        self.type_combo = ttk.Combobox(scan_frame, values=['int', 'float', 'string'])
        self.type_combo.current(0)
        self.type_combo.pack(side=tk.LEFT, padx=5)

        ttk.Button(scan_frame, text="First Scan", command=self.first_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(scan_frame, text="Next Scan", command=self.next_scan).pack(side=tk.LEFT, padx=5)

        # Результаты
        self.results_list = ttk.Treeview(main_frame, columns=('address', 'value'), show='headings')
        self.results_list.heading('address', text='Address')
        self.results_list.heading('value', text='Value')
        self.results_list.pack(fill=tk.BOTH, expand=True, pady=5)

        # Изменение значения
        edit_frame = ttk.Frame(main_frame)
        edit_frame.pack(fill=tk.X, pady=5)

        ttk.Label(edit_frame, text="New Value:").pack(side=tk.LEFT)
        self.new_value_entry = ttk.Entry(edit_frame)
        self.new_value_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(edit_frame, text="Write Value", command=self.write_value).pack(side=tk.LEFT)

    def update_process_list(self):
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                self.process_list.insert('', 'end', values=(proc.pid, proc.name()))
            except:
                pass

    def on_process_select(self, event):
        selected = self.process_list.selection()
        if selected:
            self.selected_process = self.process_list.item(selected[0], 'values')[0]
            if self.scanner.open_process(int(self.selected_process)):
                messagebox.showinfo("Success", f"Attached to process {self.selected_process}")

    def first_scan(self):
        value = self.value_entry.get()
        value_type = self.type_combo.get()
        if self.selected_process and value:
            results = self.scanner.scan_memory(value, value_type)
            self.update_results(results)

    def next_scan(self):
        if self.selected_process and self.scanner.last_scan_results:
            results = self.scanner.scan_memory(self.scanner.current_value, self.scanner.value_type, False)
            self.update_results(results)

    def update_results(self, results):
        self.results_list.delete(*self.results_list.get_children())
        for addr in results:
            self.results_list.insert('', 'end', values=(hex(addr), self.scanner.current_value))

    def write_value(self):
        selected = self.results_list.selection()
        new_value = self.new_value_entry.get()
        if selected and new_value:
            address = int(self.results_list.item(selected[0], 'values')[0], 16)
            self.write_memory(address, new_value)

    def write_memory(self, address, value):
        try:
            if self.scanner.value_type == 'int':
                data = struct.pack('i', int(value))
            elif self.scanner.value_type == 'float':
                data = struct.pack('f', float(value))
            elif self.scanner.value_type == 'string':
                data = value.encode('utf-8') + b'\x00'
            
            written = wintypes.SIZE_T()
            WriteProcessMemory(self.scanner.process_handle, address, data, len(data), ctypes.byref(written))
            return written.value == len(data)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return False

if __name__ == "__main__":
    root = tk.Tk()
    app = GameCheatGUI(root)
    root.mainloop()