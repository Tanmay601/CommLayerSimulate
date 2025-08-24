import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx
import heapq
import time
import random
import re

class NetworkPacket:
    def __init__(self, data=""):
        self.original_data=data; self.application_data=None; self.transport_data=None; self.network_data=None
        self.datalink_frame=None; self.physical_stream=None; self.stuffing_overhead=0; self.hamming_parity_bits=0
        self.binary_views={}; self.frame_explanations={}; self.hamming_encoding_calcs=[]; self.bit_stuffing_examples=[]

    def to_binary(self, data): return ''.join(format(ord(c), '08b') for c in data)

    def apply_bit_stuffing(self, data):
        stuffed, ones_count = "", 0; self.bit_stuffing_examples = []
        for i, bit in enumerate(data):
            stuffed += bit
            if bit == '1': ones_count += 1
            else: ones_count = 0
            if ones_count == 5:
                stuffed += '0'; self.stuffing_overhead += 1; ones_count = 0
                if len(self.bit_stuffing_examples) < 5: self.bit_stuffing_examples.append(i + 1)
        return stuffed

    def apply_hamming_code(self, data):
        encoded = ""; self.hamming_parity_bits = 0; self.hamming_encoding_calcs = []
        padded_data = data + '0' * ((4 - len(data) % 4) % 4)
        for i in range(0, len(padded_data), 4):
            data_block = padded_data[i:i+4]; d = [int(b) for b in data_block]
            p1=d[0]^d[1]^d[3]; p2=d[0]^d[2]^d[3]; p3=d[1]^d[2]^d[3]
            self.hamming_parity_bits += 3; final_codeword = f"{p1}{p2}{d[0]}{p3}{d[1]}{d[2]}{d[3]}"; encoded += final_codeword
            if len(self.hamming_encoding_calcs) < 5:
                self.hamming_encoding_calcs.append({"data_block":data_block,"p1_calc":f"p1=d1⊕d2⊕d4={d[0]}⊕{d[1]}⊕{d[3]}={p1}","p2_calc":f"p2=d1⊕d3⊕d4={d[0]}⊕{d[2]}⊕{d[3]}={p2}","p3_calc":f"p3=d2⊕d3⊕d4={d[1]}⊕{d[2]}⊕{d[3]}={p3}","codeword":final_codeword})
        return encoded

    def run_dijkstra(self, graph, start, end):
        distances={n:float('inf') for n in graph};distances[start]=0;predecessors={n:None for n in graph};pq=[(0,start)]
        while pq:
            dist,curr=heapq.heappop(pq)
            if curr==end:break
            if dist>distances[curr]:continue
            for neighbor,weight in graph[curr].items():
                distance=dist+weight
                if distance<distances[neighbor]:distances[neighbor]=distance;predecessors[neighbor]=curr;heapq.heappush(pq,(distance,neighbor))
        path=[];final_dist=distances[end]
        if final_dist==float('inf'):return [],0
        while end is not None:path.insert(0,end);end=predecessors[end]
        return path,final_dist

    def process_application_layer(self):
        header = "[HTTP/1.1|...]"
        self.application_data = f"{header} {self.original_data}"
        self.binary_views['application'] = self.to_binary(self.application_data)
        self.frame_explanations['application'] = f"Header: {header}\n\nPayload:\n{self.original_data}"

    def process_transport_layer(self):
        header = "[TCP|SRC_PORT:8080|...]"
        self.transport_data = f"{header} {self.application_data}"
        self.binary_views['transport'] = self.to_binary(self.transport_data)
        self.frame_explanations['transport'] = f"Header: {header}\n\nPayload:\n{self.application_data}"

    def process_network_layer(self, graph, source, target):
        path, _ = self.run_dijkstra(graph, source, target)
        if not path: raise ValueError(f"No path found between {source} and {target}.")
        path_str = "->".join(path)
        num_hops=len(path)-1
        
        packet_size_bits=len(self.to_binary(self.transport_data)); bandwidth_bps=1_000_000; distance_km=150; prop_speed_mps=2*10**8; proc_delay_ms_per_hop=0.02
        trans_delay_s=(packet_size_bits/bandwidth_bps); prop_delay_s=(distance_km*1000/prop_speed_mps); proc_delay_s=(proc_delay_ms_per_hop/1000) * num_hops
        queuing_delay_s=sum(random.uniform(0.0001, 0.0015) for _ in range(num_hops))
        total_delay_s = (trans_delay_s * num_hops) + (prop_delay_s * num_hops) + proc_delay_s + queuing_delay_s

        delay_explanation=(f"Path (Dijkstra): {path_str} ({num_hops} hops)\n" + "----------------------------------------------------\nNETWORK DELAY CALCULATION:\n" + "----------------------------------------------------\n" +
                           f"1. Transmission Delay (L/R) per Hop:\n   ({packet_size_bits} bits / {bandwidth_bps/1e6:.1f} Mbps) * {num_hops} hops = {trans_delay_s*num_hops*1000:.4f} ms\n\n" +
                           f"2. Propagation Delay (d/s) per Hop:\n   ({distance_km} km / {prop_speed_mps:.1e} m/s) * {num_hops} hops = {prop_delay_s*num_hops*1000:.4f} ms\n\n" +
                           f"3. Processing Delay (per Hop):\n   {proc_delay_ms_per_hop} ms/hop * {num_hops} hops = {proc_delay_s*1000:.4f} ms\n\n" +
                           f"4. Queuing Delay (Randomized Total):\n   Simulated over {num_hops} hops = {queuing_delay_s*1000:.4f} ms\n\n" +
                           "----------------------------------------------------\n" + f"TOTAL ESTIMATED DELAY = {total_delay_s*1000:.4f} ms")

        header = f"[IP|SRC:192...|DST:10...|PATH:{path_str}]"
        self.network_data = f"{header} {self.transport_data}"
        self.binary_views['network'] = self.to_binary(self.network_data)
        self.frame_explanations['network'] = f"Header: {header}\n\nPayload:\n{self.transport_data}\n\n{delay_explanation}"
        return path

    def process_datalink_layer(self):
        header="[ETH:SRC_MAC=...|DST_MAC=...|TYPE=IPV4]"
        trailer=f"[CRC32:0x...]"
        payload_text = f"{header} {self.network_data} {trailer}"
        binary_payload = self.to_binary(payload_text)
        stuffed_payload = self.apply_bit_stuffing(binary_payload)
        FRAME_FLAG = '01111110'
        self.datalink_frame = FRAME_FLAG + stuffed_payload + FRAME_FLAG
        self.binary_views['datalink'] = ' '.join(self.datalink_frame[i:i+8] for i in range(0, len(self.datalink_frame), 8))
        self.frame_explanations['datalink'] = f"1. Encapsulation: Adds MAC header and trailer.\n2. Bit Stuffing: Inserts {self.stuffing_overhead} '0's.\n3. Framing: Wraps with Start/End Flags."

    def process_physical_layer(self):
        self.physical_stream = self.apply_hamming_code(self.datalink_frame)
        self.binary_views['physical'] = ' '.join(self.physical_stream[i:i+8] for i in range(0, len(self.physical_stream), 8))
        
        exp = (f"Applied Hamming(7,4) code, adding {self.hamming_parity_bits} parity bits.\n\n" +
               "----------------------------------------------------\nHAMMING(7,4) ENCODING EXAMPLES:\n" + "----------------------------------------------------")
        for i, calc in enumerate(self.hamming_encoding_calcs):
            exp += (f"\n\nExample Block #{i+1} (Data: {calc['data_block']}):\n" + f"  - {calc['p1_calc']}\n  - {calc['p2_calc']}\n  - {calc['p3_calc']}\n" +
                    f"  - Resulting Codeword (p1p2d1p3d2d3d4): {calc['codeword']}")
        self.frame_explanations['physical'] = exp


class NetworkPacketReceiver:
    def __init__(self):
        self.reset()

    def reset(self):
        self.physical_data=None; self.datalink_input=None; self.network_input=None; self.transport_input=None
        self.application_input=None; self.final_data=None; self.original_payload=None; self.hamming_calculations=[]; self.destuffing_positions=[]
        self.was_correction_performed = False

    def to_binary(self, data): return ''.join(format(ord(c), '08b') for c in data)
    def binary_to_text(self, binary_data):
        try:
            return bytearray(int(binary_data[i:i+8],2) for i in range(0,len(binary_data),8)).decode('utf-8',errors='ignore')
        except Exception: return "[DECODING ERROR]"

    def decode_and_correct_hamming_code(self, encoded_data):
        decoded = ""; self.hamming_calculations = []; self.was_correction_performed = False
        padded_data = encoded_data + '0' * ((7 - len(encoded_data) % 7) % 7)
        for i in range(0, len(padded_data), 7):
            original_block = padded_data[i:i+7]; p1,p2,d1,p3,d2,d3,d4=[int(b) for b in original_block]
            c1=(p1^d1^d2^d4); c2=(p2^d1^d3^d4); c3=(p3^d2^d3^d4); syndrome=c3*4+c2*2+c1*1
            corrected_list=list(original_block)
            if syndrome != 0:
                self.was_correction_performed = True; error_pos=syndrome-1
                if error_pos < 7: corrected_list[error_pos]='1' if corrected_list[error_pos]=='0' else '0'
                self.hamming_calculations.append({"block_index":i,"original_block":original_block, "syndrome":f"{c3}{c2}{c1}", "error_pos":syndrome,
                                                  "c1_calc":f"c1=p1⊕d1⊕d2⊕d4={p1}⊕{d1}⊕{d2}⊕{d4}={c1}","c2_calc":f"c2=p2⊕d1⊕d3⊕d4={p2}⊕{d1}⊕{d3}⊕{d4}={c2}",
                                                  "c3_calc":f"c3=p3⊕d2⊕d3⊕d4={p3}⊕{d2}⊕{d3}⊕{d4}={c3}","corrected_block":"".join(corrected_list)})
            corrected_data = "".join(corrected_list)
            decoded += corrected_data[2] + corrected_data[4] + corrected_data[5] + corrected_data[6]
        return decoded

    def remove_bit_stuffing(self, stuffed_data):
        destuffed, ones_count, i = "", 0, 0; self.destuffing_positions = []
        while i < len(stuffed_data):
            bit = stuffed_data[i]; destuffed += bit
            if bit=='1': ones_count+=1
            else: ones_count=0
            if ones_count==5 and (i+1)<len(stuffed_data) and stuffed_data[i+1]=='0': self.destuffing_positions.append(i+1); i+=1; ones_count=0
            i+=1
        return destuffed

    def process_physical_layer(self, physical_data):
        self.physical_data = physical_data.replace(' ', '')
        self.datalink_input = self.decode_and_correct_hamming_code(self.physical_data)

    def process_datalink_layer(self):
        FRAME_FLAG = '01111110'
        start_pos = self.datalink_input.find(FRAME_FLAG)
        end_pos = self.datalink_input.rfind(FRAME_FLAG)
        if start_pos == -1 or end_pos == -1 or start_pos == end_pos: raise ValueError("Framing Error: Invalid flags.")
        stuffed_payload = self.datalink_input[start_pos + len(FRAME_FLAG):end_pos]
        destuffed_binary=self.remove_bit_stuffing(stuffed_payload)
        self.network_input=self.binary_to_text(destuffed_binary)

    def _strip_header(self, data, pattern):
        match = re.match(pattern, data, re.DOTALL)
        if not match: raise ValueError(f"Header Parse Error for pattern: {pattern}")
        return data[match.end():], match.group(1)

    def process_network_layer(self): self.transport_input, _ = self._strip_header(self.network_input, r'^\s*(\[ETH.*?\])')
    def process_transport_layer(self): self.application_input, _ = self._strip_header(self.transport_input, r'^\s*(\[IP.*?\])')
    def process_application_layer(self): self.final_data, _ = self._strip_header(self.application_input, r'^\s*(\[TCP.*?\])')
    def get_original_data(self): self.original_payload, _ = self._strip_header(self.final_data, r'^\s*(\[HTTP.*?\])')

# ========================================================================================
# GUI HELPER CLASSES
# ========================================================================================
class LayerWindow(tk.Toplevel):
    def __init__(self, parent, title, text_data, binary_data, explanation_text, graph_data=None, path=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("800x700")
        notebook=ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH,expand=True,padx=10,pady=10)
        details_tab=ttk.Frame(notebook)
        notebook.add(details_tab,text="Frame Details")
        self.setup_details_view(details_tab,text_data,binary_data,explanation_text)
        if graph_data:
            algo_tab=ttk.Frame(notebook)
            notebook.add(algo_tab,text="Dijkstra Visualization")
            self.setup_algorithm_view(algo_tab,graph_data,path)

    def setup_details_view(self, parent, text_data, binary_data, explanation_text):
        frame=ttk.Frame(parent,padding="10")
        frame.pack(fill=tk.BOTH,expand=True)
        ttk.Label(frame,text="Data:",font=("Arial",10,"bold")).pack(anchor="w")
        data_widget=tk.Text(frame,height=6,wrap=tk.WORD,font=("Courier",10))
        data_widget.pack(fill=tk.X,pady=5)
        data_widget.insert(tk.END,text_data)
        data_widget.config(state=tk.DISABLED)
        binary_len=len(binary_data.replace(' ',''))
        ttk.Label(frame,text=f"Binary Representation ({binary_len} bits):",font=("Arial",10,"bold")).pack(anchor="w",pady=(10,0))
        binary_widget=tk.Text(frame,height=6,wrap=tk.WORD,font=("Courier",9))
        binary_widget.pack(fill=tk.BOTH,expand=True,pady=5)
        binary_widget.insert(tk.END,binary_data)
        binary_widget.config(state=tk.DISABLED)
        ttk.Label(frame,text="Explanation:",font=("Arial",10,"bold")).pack(anchor="w",pady=(10,0))
        exp_widget=tk.Text(frame,wrap=tk.WORD,font=("Consolas",10))
        exp_widget.pack(fill=tk.BOTH,expand=True,pady=5)
        exp_widget.insert(tk.END,explanation_text)
        exp_widget.config(state=tk.DISABLED)

    def setup_algorithm_view(self, parent, graph_data, path):
        fig=plt.Figure(figsize=(8,6));canvas=FigureCanvasTkAgg(fig,parent);canvas.get_tk_widget().pack(fill=tk.BOTH,expand=True);ax=fig.add_subplot(111);G=nx.Graph()
        for node,neighbors in graph_data.items():
            for neighbor,weight in neighbors.items():G.add_edge(node,neighbor,weight=weight)
        pos=nx.spring_layout(G,seed=42);nx.draw_networkx(G,pos,ax=ax,node_color='skyblue',node_size=700,with_labels=True,font_size=12);nx.draw_networkx_edge_labels(G,pos,edge_labels=nx.get_edge_attributes(G,'weight'),ax=ax)
        if path:
            path_edges=list(zip(path,path[1:]));
            nx.draw_networkx_nodes(G,pos,nodelist=path,node_color='tomato',node_size=700,ax=ax)
            nx.draw_networkx_edges(G,pos,edgelist=path_edges,width=2.5,edge_color='tomato',ax=ax)
        ax.set_title(f"Dijkstra's Shortest Path: {' -> '.join(path)}");canvas.draw()

class HammingDetailWindow(tk.Toplevel):
    def __init__(self, parent, calculations):
        super().__init__(parent)
        self.title("Physical Layer: Hamming Decode Analysis")
        self.geometry("800x600")
        main_frame=ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH,expand=True)
        canvas=tk.Canvas(main_frame)
        canvas.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        scrollbar=ttk.Scrollbar(main_frame,orient=tk.VERTICAL,command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT,fill=tk.Y)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollable_frame=ttk.Frame(canvas)
        canvas.create_window((0,0),window=scrollable_frame,anchor="nw")
        scrollable_frame.bind("<Configure>",lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        if not calculations:
            ttk.Label(scrollable_frame,text="Hamming check complete. No errors were detected.",font=("Arial",12),padding=20).pack()
            return
        ttk.Label(scrollable_frame,text=f"Detected and corrected {len(calculations)} single-bit error(s):",font=("Arial",12,"bold"),padding=10).pack(anchor='w')
        for calc in calculations:
            frame=ttk.LabelFrame(scrollable_frame,text=f"Error in Block at index {calc['block_index']}",padding=10)
            frame.pack(padx=10,pady=5,fill=tk.X)
            ttk.Label(frame,font=("Courier", 10), text=f"Received:    {calc['original_block']}").grid(row=0,column=0,sticky='w',pady=2)
            ttk.Label(frame,font=("Courier", 10, "bold"), text="Parity Checks:").grid(row=1, column=0, sticky='w', pady=(8,2))
            ttk.Label(frame,font=("Courier", 10), text=f"  {calc['c1_calc']}").grid(row=2,column=0,sticky='w')
            ttk.Label(frame,font=("Courier", 10), text=f"  {calc['c2_calc']}").grid(row=3,column=0,sticky='w')
            ttk.Label(frame,font=("Courier", 10), text=f"  {calc['c3_calc']}").grid(row=4,column=0,sticky='w')
            ttk.Label(frame,font=("Courier", 10, "bold"), text=f"Syndrome (c3c2c1): {calc['syndrome']} -> Error at bit {calc['error_pos']}").grid(row=5,column=0,sticky='w',pady=(8,2))
            ttk.Label(frame,font=("Courier", 10, "bold"), text=f"Corrected:   {calc['corrected_block']}", foreground="green").grid(row=6,column=0,sticky='w',pady=2)


class SenderFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding="10")
        self.controller = controller; self.packet=None
        self.graph={'A':{'B':4,'C':2,'D':3},'B':{'A':4,'C':1,'E':5,'F':2},'C':{'A':2,'B':1,'D':3,'G':4},'D':{'A':3,'C':3,'H':2},'E':{'B':5,'F':1,'I':3},'F':{'B':2,'E':1,'G':2,'J':4},'G':{'C':4,'F':2,'H':3},'H':{'D':2,'G':3,'J':1},'I':{'E':3,'J':2},'J':{'F':4,'H':1,'I':2}}
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Step 1: Build Packet", font=("Arial", 12, "bold")).pack(fill=tk.X, pady=(0,5))
        input_container=ttk.Frame(self, padding=10, relief=tk.RIDGE);input_container.pack(fill=tk.X, pady=5);input_container.columnconfigure(1,weight=1)
        ttk.Label(input_container,text="Data:").grid(row=0,column=0,sticky='w',padx=5);self.data_entry=ttk.Entry(input_container);self.data_entry.grid(row=0,column=1,sticky='ew');self.data_entry.insert(0,"Test Data")
        ttk.Label(input_container,text="Source:").grid(row=1,column=0,sticky='w',padx=5);self.source_combo=ttk.Combobox(input_container,values=list(self.graph.keys()),state="readonly");self.source_combo.grid(row=1,column=1,sticky='ew');self.source_combo.set('A')
        ttk.Label(input_container,text="Destination:").grid(row=2,column=0,sticky='w',padx=5);self.dest_combo=ttk.Combobox(input_container,values=list(self.graph.keys()),state="readonly");self.dest_combo.grid(row=2,column=1,sticky='ew');self.dest_combo.set('J')
        ttk.Button(input_container,text="Process All Layers",command=self.process_all_layers).grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Label(self, text="Step 2: Inspect Layer Details", font=("Arial", 12, "bold")).pack(fill=tk.X, pady=(10,5))
        btn_frame=ttk.Frame(self, padding=10, relief=tk.RIDGE);btn_frame.pack(fill=tk.X, pady=5)
        layer_names=["Application","Transport","Network","Data Link","Physical"]
        for i,name in enumerate(layer_names):
            ttk.Button(btn_frame,text=f"Show {name}",command=lambda l=i: self.show_layer_window(l+1)).pack(side=tk.LEFT,padx=5)
        
        ttk.Label(self, text="Step 3: Simulate Transmission", font=("Arial", 12, "bold")).pack(fill=tk.X, pady=(10,5))
        tx_container=ttk.Frame(self, padding="10", relief=tk.RIDGE);tx_container.pack(fill=tk.X, pady=5)
        self.error_var = tk.BooleanVar();ttk.Checkbutton(tx_container, text="Introduce Random Bit Error", variable=self.error_var).pack(side=tk.LEFT, padx=10)
        self.transmit_button = ttk.Button(tx_container,text="Transmit Frame",command=self.controller.initiate_transmission, state=tk.DISABLED)
        self.transmit_button.pack(side=tk.LEFT,padx=10)

        log_frame=ttk.LabelFrame(self,text="Sender Log");log_frame.pack(fill=tk.BOTH,expand=True,pady=10)
        self.status_text=tk.Text(log_frame,height=10,wrap=tk.WORD,font=("Courier",10));self.status_text.pack(fill=tk.BOTH,expand=True,padx=5,pady=5)
        self.status_text.tag_config("green", foreground="green");self.status_text.tag_config("red", foreground="red");self.status_text.tag_config("blue", foreground="blue")

    def log(self,message, color="black"):
        self.status_text.insert(tk.END,f"[{time.strftime('%H:%M:%S')}] {message}\n", color);self.status_text.see(tk.END);self.update_idletasks()

    def process_all_layers(self):
        if not self.data_entry.get(): messagebox.showerror("Input Error","Please enter data."); return
        self.packet=NetworkPacket(self.data_entry.get()); self.status_text.delete(1.0,tk.END)
        try:
            self.log("Processing..."); self.packet.process_application_layer(); self.log("-> Application OK")
            self.packet.process_transport_layer(); self.log("-> Transport OK")
            self.packet.process_network_layer(self.graph,self.source_combo.get(),self.dest_combo.get()); self.log("-> Network OK")
            self.packet.process_datalink_layer(); self.log("-> Data Link OK")
            self.packet.process_physical_layer(); self.log("-> Physical OK")
            self.log("\nPacket ready for transmission.", "green"); self.transmit_button.config(state=tk.NORMAL)
        except Exception as e: messagebox.showerror("Error",str(e));self.log(f"ERROR: {e}", "red")

    def show_layer_window(self,layer_num):
        if not self.packet: messagebox.showerror("Order Error","Process layers first."); return
        try:
            if layer_num==1: LayerWindow(self, "Sender L7: Application", self.packet.application_data, self.packet.binary_views['application'], self.packet.frame_explanations['application'])
            elif layer_num==2: LayerWindow(self, "Sender L4: Transport", self.packet.transport_data, self.packet.binary_views['transport'], self.packet.frame_explanations['transport'])
            elif layer_num==3: path=self.packet.process_network_layer(self.graph,self.source_combo.get(),self.dest_combo.get());LayerWindow(self, "Sender L3: Network", self.packet.network_data, self.packet.binary_views['network'], self.packet.frame_explanations['network'], graph_data=self.graph, path=path)
            elif layer_num==4: LayerWindow(self, "Sender L2: Data Link", self.packet.datalink_frame, self.packet.binary_views['datalink'], self.packet.frame_explanations['datalink'])
            elif layer_num==5: LayerWindow(self, "Sender L1: Physical", self.packet.physical_stream, self.packet.binary_views['physical'], self.packet.frame_explanations['physical'])
        except Exception as e: messagebox.showerror("Error",f"Could not display layer window.\n{e}")

class ReceiverFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding="10")
        self.controller = controller; self.packet = NetworkPacketReceiver()
        self.setup_ui()

    def setup_ui(self):
        final_data_frame = ttk.LabelFrame(self, text="Final Decoded Data");final_data_frame.pack(fill=tk.X, pady=5)
        self.final_data_text = tk.Text(final_data_frame, height=4, font=("Arial", 14, "bold"), wrap=tk.WORD, bg="#eaf7e9", state=tk.DISABLED)
        self.final_data_text.pack(fill=tk.X, expand=True, padx=5, pady=5)

        btn_frame=ttk.LabelFrame(self, text="Inspect Received Layers");btn_frame.pack(fill=tk.X, pady=5)
        btn_container = ttk.Frame(btn_frame, padding=10); btn_container.pack()
        layer_names=["Physical","Data Link","Network","Transport","Application","Final Data"]
        self.layer_buttons = []
        for i, name in enumerate(layer_names):
            btn = ttk.Button(btn_container,text=f"Show {name}",command=lambda l=i: self.show_layer_window(l+1), state=tk.DISABLED)
            btn.pack(side=tk.LEFT,padx=2); self.layer_buttons.append(btn)

        log_frame=ttk.LabelFrame(self,text="Receiver Log");log_frame.pack(fill=tk.BOTH,expand=True,pady=10)
        self.status_text=tk.Text(log_frame,height=10,wrap=tk.WORD,font=("Courier",10));self.status_text.pack(fill=tk.BOTH,expand=True,padx=5,pady=5)
        self.status_text.tag_config("green", foreground="green");self.status_text.tag_config("red", foreground="red");self.status_text.tag_config("blue", foreground="blue")

    def set_buttons_state(self, state):
        for btn in self.layer_buttons: btn.config(state=state)

    def log(self,message, color="black"):
        self.status_text.insert(tk.END,f"[{time.strftime('%H:%M:%S')}] {message}\n", color);self.status_text.see(tk.END);self.update_idletasks()

    def clear_all(self):
        self.status_text.delete("1.0", tk.END)
        self.final_data_text.config(state=tk.NORMAL); self.final_data_text.delete("1.0", tk.END); self.final_data_text.config(state=tk.DISABLED)
        self.packet.reset(); self.set_buttons_state(tk.DISABLED)

    def receive_and_process(self, stream):
        self.clear_all(); self.log("Received new physical stream...")
        try:
            self.packet.process_physical_layer(stream)
            if self.packet.was_correction_performed: self.log("Physical Layer: Error detected AND CORRECTED.", "blue")
            else: self.log("Physical Layer: Frame passed integrity check.", "blue")
            
            self.packet.process_datalink_layer(); self.log("Data Link Layer: De-stuffed and De-framed.")
            self.packet.process_network_layer(); self.log("Network Layer: Stripped ETH Header.")
            self.packet.process_transport_layer(); self.log("Transport Layer: Stripped IP Header.")
            self.packet.process_application_layer(); self.log("Application Layer: Stripped TCP Header.")
            self.packet.get_original_data(); self.log("Final Data: Extracted.", "green")

            self.final_data_text.config(state=tk.NORMAL);self.final_data_text.delete("1.0", tk.END);self.final_data_text.insert(tk.END, self.packet.original_payload);self.final_data_text.config(state=tk.DISABLED)
            self.set_buttons_state(tk.NORMAL)
            return True
        except Exception as e:
            self.log(f"ERROR: Decapsulation failed: {e}", "red"); self.set_buttons_state(tk.DISABLED)
            return False

    def show_layer_window(self,layer_num):
        if not self.packet.physical_data: messagebox.showerror("Error", "No data has been processed."); return
        try:
            if layer_num==1: HammingDetailWindow(self, self.packet.hamming_calculations)
            elif layer_num==2:
                exp = f"Received corrected stream from L1.\nDe-framed and removed {len(self.packet.destuffing_positions)} stuffed bits.\n\nResulting payload passed to L3 is shown above."
                LayerWindow(self,"Receiver L2: Data Link", self.packet.network_input, self.packet.to_binary(self.packet.network_input), exp)
            elif layer_num==3:
                payload, header = self.packet._strip_header(self.packet.network_input, r'^\s*(\[ETH.*?\])')
                exp = f"Received data from L2 (shown above).\n\nStripped ETH Header:\n{header}\n\nResulting payload passed to L4 is:\n{payload}"
                LayerWindow(self,"Receiver L3: Network", self.packet.network_input, self.packet.to_binary(self.packet.network_input), exp)
            elif layer_num==4:
                payload, header = self.packet._strip_header(self.packet.transport_input, r'^\s*(\[IP.*?\])')
                exp = f"Received data from L3 (shown above).\n\nStripped IP Header:\n{header}\n\nResulting payload passed to L5 is:\n{payload}"
                LayerWindow(self,"Receiver L4: Transport", self.packet.transport_input, self.packet.to_binary(self.packet.transport_input), exp)
            elif layer_num==5:
                payload, header = self.packet._strip_header(self.packet.application_input, r'^\s*(\[TCP.*?\])')
                exp = f"Received data from L4 (shown above).\n\nStripped TCP Header:\n{header}\n\nResulting payload (final data) is:\n{payload}"
                LayerWindow(self,"Receiver L5: Application", self.packet.application_input, self.packet.to_binary(self.packet.application_input), exp)
            elif layer_num==6:
                _, header = self.packet._strip_header(self.packet.final_data, r'^\s*(\[HTTP.*?\])')
                exp = f"Received data from L5 (shown above).\n\nStripped HTTP Header:\n{header}\n\nSUCCESS! The original data is:\n'{self.packet.original_payload}'"
                LayerWindow(self,"Receiver: Final Data", self.packet.final_data, self.packet.to_binary(self.packet.final_data), exp)
        except Exception as e: messagebox.showerror("Display Error",f"Could not show layer.\n{e}")


class IntegratedSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Integrated Network Protocol Simulator")
        self.root.geometry("1000x800")
        self.notebook = ttk.Notebook(self.root)
        self.sender_ui = SenderFrame(self.notebook, self)
        self.receiver_ui = ReceiverFrame(self.notebook, self)
        self.notebook.add(self.sender_ui, text="Sender")
        self.notebook.add(self.receiver_ui, text="Receiver")
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

    def initiate_transmission(self):
        if not self.sender_ui.packet or not self.sender_ui.packet.physical_stream:
            messagebox.showerror("Order Error","Process layers on Sender tab first.")
            return

        self.sender_ui.log("\n--- NEW TRANSMISSION ATTEMPT ---", "blue")
        stream = self.sender_ui.packet.physical_stream
        
        if self.sender_ui.error_var.get():
            self.sender_ui.log("Injecting a random single-bit error...", "red")
            pos = random.randint(0, len(stream) - 1)
       
            stream = stream[:pos] + ('0' if stream[pos] == '1' else '1') + stream[pos+1:]
        else:
            self.sender_ui.log("Transmitting frame without errors.")

        self.notebook.select(self.receiver_ui)
        transmission_ok = self.receiver_ui.receive_and_process(stream)

        if transmission_ok:
            if self.receiver_ui.packet.was_correction_performed:
                self.sender_ui.log("Receiver Response: ACK (Frame was corrected by receiver).", "green")
            else:
                self.sender_ui.log("Receiver Response: ACK (Frame OK).", "green")
            self.sender_ui.log("Transmission successful!", "green")
        else:
            self.sender_ui.log("Receiver Response: NAK (Uncorrectable Frame).", "red")
            self.sender_ui.log("Transmission failed.", "red")

if __name__ == "__main__":
    root = tk.Tk()
    app = IntegratedSimulator(root)
    root.mainloop()

