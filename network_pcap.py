import scapy.all as scapy
from collections import defaultdict
import ipaddress

class NetworkAnalyzer:
    def __init__(self, pcap_file=None):
        """
        Initialize NetworkAnalyzer with optional PCAP file path.
        
        :param pcap_file: Path to the PCAP file to be analyzed (optional)
        """
        self.pcap_file = pcap_file
        self.analysis_results = None
    
    def analyze_pcap(self, pcap_file=None):
        """
        Analyze network packets from a PCAP file and generate a detailed report.
        
        :param pcap_file: Path to the PCAP file to be analyzed (optional)
        :return: Dictionary containing detailed packet analysis
        """
        # Use provided file path or the one set during initialization
        file_to_analyze = pcap_file or self.pcap_file
        
        if not file_to_analyze:
            raise ValueError("No PCAP file specified. Please provide a file path.")
        
        # Read packets from the PCAP file
        packets = scapy.rdpcap(file_to_analyze)
        
        # Analysis containers
        analysis_report = {
            'total_packets': len(packets),
            'protocols': defaultdict(int),
            'ip_connections': defaultdict(lambda: {'src_count': 0, 'dst_count': 0}),
            'port_stats': defaultdict(lambda: {'tcp': 0, 'udp': 0}),
            'packet_sizes': {
                'min': float('inf'),
                'max': 0,
                'average': 0,
                'total': 0
            }
        }
        
        # Detailed packet analysis
        for packet in packets:
            # Packet size analysis
            packet_len = len(packet)
            analysis_report['packet_sizes']['total'] += packet_len
            analysis_report['packet_sizes']['min'] = min(analysis_report['packet_sizes']['min'], packet_len)
            analysis_report['packet_sizes']['max'] = max(analysis_report['packet_sizes']['max'], packet_len)
            
            # Protocol analysis
            if scapy.IP in packet:
                # IP layer analysis
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                # IP connection tracking
                analysis_report['ip_connections'][src_ip]['src_count'] += 1
                analysis_report['ip_connections'][dst_ip]['dst_count'] += 1
                
                # Protocol tracking
                if scapy.TCP in packet:
                    analysis_report['protocols']['TCP'] += 1
                    analysis_report['port_stats'][packet[scapy.TCP].sport]['tcp'] += 1
                    analysis_report['port_stats'][packet[scapy.TCP].dport]['tcp'] += 1
                elif scapy.UDP in packet:
                    analysis_report['protocols']['UDP'] += 1
                    analysis_report['port_stats'][packet[scapy.UDP].sport]['udp'] += 1
                    analysis_report['port_stats'][packet[scapy.UDP].dport]['udp'] += 1
                elif scapy.ICMP in packet:
                    analysis_report['protocols']['ICMP'] += 1
                else:
                    analysis_report['protocols']['Other'] += 1
        
        # Calculate average packet size
        if analysis_report['total_packets'] > 0:
            analysis_report['packet_sizes']['average'] = analysis_report['packet_sizes']['total'] / analysis_report['total_packets']
        
        # Filter and sort top connections and ports
        analysis_report['top_src_ips'] = sorted(
            analysis_report['ip_connections'].items(), 
            key=lambda x: x[1]['src_count'], 
            reverse=True
        )[:10]
        
        analysis_report['top_dst_ips'] = sorted(
            analysis_report['ip_connections'].items(), 
            key=lambda x: x[1]['dst_count'], 
            reverse=True
        )[:10]
        
        analysis_report['top_ports'] = sorted(
            analysis_report['port_stats'].items(), 
            key=lambda x: x[1]['tcp'] + x[1]['udp'], 
            reverse=True
        )[:10]
        
        # Store results for later reference
        self.analysis_results = analysis_report
        
        return analysis_report
    
    def generate_report(self, analysis_report=None):
        """
        Generate a human-readable report from the packet analysis.
        
        :param analysis_report: Dictionary containing packet analysis results
                                Defaults to last analyzed results
        """
        # Use provided report or last analyzed results
        report_data = analysis_report or self.analysis_results
        
        if not report_data:
            print("No analysis results available. Please run analyze_pcap() first.")
            return
        
        print("=== PCAP File Analysis Report ===")
        print(f"Total Packets Analyzed: {report_data['total_packets']}")
        
        print("\n--- Protocol Distribution ---")
        for proto, count in report_data['protocols'].items():
            print(f"{proto}: {count} packets ({count/report_data['total_packets']*100:.2f}%)")
        
        print("\n--- Packet Size Statistics ---")
        sizes = report_data['packet_sizes']
        print(f"Minimum Packet Size: {sizes['min']} bytes")
        print(f"Maximum Packet Size: {sizes['max']} bytes")
        print(f"Average Packet Size: {sizes['average']:.2f} bytes")
        
        print("\n--- Top 10 Source IPs ---")
        for ip, stats in report_data['top_src_ips']:
            print(f"{ip}: {stats['src_count']} packets")
        
        print("\n--- Top 10 Destination IPs ---")
        for ip, stats in report_data['top_dst_ips']:
            print(f"{ip}: {stats['dst_count']} packets")
        
        print("\n--- Top 10 Ports ---")
        for port, stats in report_data['top_ports']:
            print(f"Port {port}: TCP: {stats['tcp']}, UDP: {stats['udp']}")

# Example usage
if __name__ == "__main__":
    # Replace with the path to your PCAP file
    analyzer = NetworkAnalyzer("network_capture.pcap")
    results = analyzer.analyze_pcap()
    analyzer.generate_report()
