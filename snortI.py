from scapy.all import rdpcap

class RealTimeData:
    def __init__(self, log_file):
        self.log_file = log_file
        self.packet_data = []

    def extract_data(self):
        packets = rdpcap(self.log_file)

        for packet in packets:
            data = {
                'timestamp': packet.time,
                'src_ip': packet[1].src if packet.haslayer('IP') else None,
                'dst_ip': packet[1].dst if packet.haslayer('IP') else None,
                'src_port': packet[1].sport if packet.haslayer('TCP') else None,
                'dst_port': packet[1].dport if packet.haslayer('TCP') else None,
                'payload': bytes(packet.payload)
            }
            self.packet_data.append(data)

    def get_data(self):
        return self.packet_data
 

if __name__ == "__main__":
    # log_file_path = r'./Real Time Data/snort.alert.fast'
    # extractor = RealTimeData(log_file_path)
    # extractor.extract_data()
    # data = extractor.get_data()
    # for entry in data:
    #     print(entry)

    import subprocess

    def cat_file(filename):
        try:
            # Run the 'cat' command
            output = subprocess.check_output(['cat', filename])
            print(output.decode('utf-8'))
        except subprocess.CalledProcessError:
            print(f"Failed to run 'cat' on {filename}")

    # Replace 'yourfile.txt' with your filename
    cat_file(r'./Real Time Data/snort.alert.fast')

