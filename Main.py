from kMeansLearner import kMeansLearner
import numpy as np
from Config import FlowFeaturesConfig
from AnalyserWorker import FlowFeatures, wave_analyze
from ReadFlow import get_meta_pkt_info
import os

if __name__ == '__main__':

    parsed_pkt_num = {0: 0}
    parsed_pkt_len = {0: 0}
    # pcap_file = './SYN DoS/SYN_DoS.pcap' 
    pcap_file = './202003251400.pcap/output0.pcap' 
    # pcap_file = './202006101400.pcap/output3.pcap' 
    # pcap_file = './202006101400_10.pcap/output6.pcap'
    dev_id = 0

    print("Reading pcap file...")

    meta_data = get_meta_pkt_info(pcap_file, dev_id, parsed_pkt_num, parsed_pkt_len)

    # for data in meta_data:
    #     # print(f"Address: {data.addr}, Type: {data.type_code}, Length: {data.length}, Timestamp: {data.timestamp}")
    #     with open('./SYN DoS/SYN_DoS.txt', 'a') as f:
    #         f.write(f"Address: {data.addr}, Type: {data.type_code}, Length: {data.length}, Timestamp: {data.timestamp}\n")

    print(f"Total number of packets: {parsed_pkt_num[dev_id]}")
    print(f"Total length of packets: {parsed_pkt_len[dev_id]}")

    print("Analyzing flow features...")

    p_analyzer_config = FlowFeaturesConfig.__dict__

    flow_features = FlowFeatures(num_train_data=p_analyzer_config['num_train_data'], train_result_file=p_analyzer_config['save_to_file_from_centers'])
    per_flow = 50000
    for i in range(0, len(meta_data), per_flow):
        wave_analyze(meta_data[i : i + per_flow], flow_features, p_analyzer_config)

    print("Saving flow features...")

    save_dir = './result/SYNDOS/'
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    flow_features.save_flow_features(save_dir + 'SYN_DoS.json')