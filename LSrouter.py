####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################

import json
import networkx as nx
from packet import Packet
from router import Router

class LSrouter(Router):

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)

        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        
        self.graph = nx.Graph()
        self.graph.add_node(self.addr)

        self.forwarding_table = {}
        self.neighbors = {}
        self.seq_num = 0

        self.link_state_db = {
            self.addr: {"seq": 0, "links": {}}
        }

    # ------------------------------------------------------------------
    # Các hàm hỗ trợ nội bộ (Private helpers)
    # ------------------------------------------------------------------

    def _broadcast_own_ls(self, exclude_port=None):
        content = json.dumps({
            "src":   self.addr,
            "seq":   self.seq_num,
            "links": self.link_state_db[self.addr]["links"],
        })
        for port, (neighbor_addr, _) in self.neighbors.items():
            if port == exclude_port:
                continue
            pkt = Packet(Packet.ROUTING, self.addr, neighbor_addr)
            pkt.content = content
            self.send(port, pkt)

    def _apply_link_state(self, src, links):
        if self.graph.has_node(src):
            edges = list(self.graph.edges(src))
            self.graph.remove_edges_from(edges)
        else:
            self.graph.add_node(src)

        for neighbor, cost in links.items():
            if not self.graph.has_node(neighbor):
                self.graph.add_node(neighbor)
            self.graph.add_edge(src, neighbor, weight=cost)

    def _recompute_forwarding_table(self):
        self.forwarding_table = {}
        try:
            _, paths = nx.single_source_dijkstra(
                self.graph, self.addr, weight="weight"
            )
        except Exception:
            return

        for dest, path in paths.items():
            if dest == self.addr:
                continue
            if len(path) < 2:
                continue
            next_hop = path[1]
            for port, (neighbor_addr, _) in self.neighbors.items():
                if neighbor_addr == next_hop:
                    self.forwarding_table[dest] = port
                    break

    # ------------------------------------------------------------------
    # Giao diện chính của Router
    # ------------------------------------------------------------------

    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            if packet.dst_addr in self.forwarding_table:
                self.send(self.forwarding_table[packet.dst_addr], packet)
        else:
            try:
                data = json.loads(packet.content)
            except (json.JSONDecodeError, AttributeError, TypeError):
                return

            src   = data["src"]
            seq   = data["seq"]
            links = data["links"]

            if src in self.link_state_db and self.link_state_db[src]["seq"] >= seq:
                return

            self.link_state_db[src] = {"seq": seq, "links": links}

            self._apply_link_state(src, links)
            self._recompute_forwarding_table()

            for out_port, (neighbor_addr, _) in self.neighbors.items():
                if out_port == port:
                    continue
                fwd = Packet(Packet.ROUTING, self.addr, neighbor_addr)
                fwd.content = packet.content
                self.send(out_port, fwd)

    def handle_new_link(self, port, endpoint, cost):
        self.neighbors[port] = (endpoint, cost)

        if not self.graph.has_node(endpoint):
            self.graph.add_node(endpoint)
        self.graph.add_edge(self.addr, endpoint, weight=cost)

        self.seq_num += 1
        self.link_state_db[self.addr] = {
            "seq":   self.seq_num,
            "links": {addr: c for (addr, c) in self.neighbors.values()},
        }

        self._recompute_forwarding_table()
        self._broadcast_own_ls()

    def handle_remove_link(self, port):
        if port not in self.neighbors:
            return

        endpoint, _ = self.neighbors.pop(port)

        if self.graph.has_edge(self.addr, endpoint):
            self.graph.remove_edge(self.addr, endpoint)

        self.seq_num += 1
        self.link_state_db[self.addr] = {
            "seq":   self.seq_num,
            "links": {addr: c for (addr, c) in self.neighbors.values()},
        }

        self._recompute_forwarding_table()
        self._broadcast_own_ls()

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_own_ls()

    def __repr__(self):
        lines = [f"LSrouter(addr={self.addr}, seq={self.seq_num})"]
        lines.append("  neighbors:")
        for port, (addr, cost) in self.neighbors.items():
            lines.append(f"    port {port} -> {addr}  cost={cost}")
        lines.append("  forwarding_table:")
        for dest, port in sorted(self.forwarding_table.items()):
            lines.append(f"    {dest} -> port {port}")
        lines.append("  link_state_db:")
        for router, info in sorted(self.link_state_db.items()):
            lines.append(f"    {router}: seq={info['seq']}  links={info['links']}")
        return "\n".join(lines)