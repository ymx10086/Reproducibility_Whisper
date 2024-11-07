import torch
import numpy as np
import random
from time import sleep
from collections import defaultdict
import math
import Config
from kMeansLearner import kMeansLearner
import json

class FlowFeatures:
    max_cluster_dist = 1e9
    def __init__(self, num_train_data = 10000, start_learn = False, train_result_file = None):
        # Initialize a list to store the flow features (training dataset)
        self.train_set = []
        self.flow_features = []
        self.num_train_data = num_train_data
        self.start_learn = start_learn
        self.train_result = None
        self.train_result_file = train_result_file

    def add_train_data(self, feature):
        """
        Add a single feature record to the training dataset.

        :param feature: A single flow feature (e.g., a list or dict representing a feature)
        """
        self.train_set.append(feature)

    def add_batch_train_data(self, features):
        """
        Add a batch of feature records to the training dataset.

        :param features: A list of flow features (e.g., a list of lists or list of dicts representing multiple features)
        """
        self.train_set.extend(features)

    def get_training_data(self):
        """
        Get all training data stored in the dataset.

        :return: The entire training dataset (a list of features)
        """
        return self.train_set

    def clear_training_data(self):
        """
        Clear all training data from the dataset.
        """
        self.train_set.clear()

    def add_feature(self, feature):
        """
        Add a single flow feature to the list.

        :param feature: A single flow feature (e.g., a list or dict representing a feature)
        """
        self.flow_features.append(feature)

    def get_feature_by_index(self, index):
        """
        Get a flow feature by its index in the list.

        :param index: The index of the flow feature in the list
        :return: The flow feature at the specified index (dictionary)
        """
        if 0 <= index < len(self.flow_features):
            return self.flow_features[index]
        else:
            raise IndexError("Feature index out of range.")

    def display_features(self):
        """
        Print all stored flow features to the console.
        """
        if not self.train_set:
            print("No flow features available.")
        else:
            for i, feature in enumerate(self.flow_features):
                print(f"Feature {i + 1}: {feature}")
    
    def clear_features(self):
        """
        Clear all stored flow features.
        """
        self.flow_features.clear()

    def get_all_features(self):
        """
        Get all stored flow features as a list.

        :return: A list of flow features
        """
        return self.flow_features
    
    def reach_learn(self):
        return len(self.train_set) >= self.num_train_data
    
    def start_train(self, num_clusters = 10):
        print(f"Start training the learner with {len(self.train_set)} samples.")
        sleep(1)
        self.start_learn = True
        learner = kMeansLearner(num_clusters=num_clusters)
        self.train_result = learner.perform_kmeans_clustering(self.train_set, Config.FlowFeaturesConfig.num_clusters)
        with open(Config.FlowFeaturesConfig.save_to_file_for_centers, 'w') as f:
            json.dump(self.train_result, f)

    def get_feature_centers(self):
        if self.train_result is not None:
            return self.train_result
        elif self.train_result_file is not None:
            # TODO: Load the training result from the json file
            print(f"Loading feature centers from {self.train_result_file}.")
            with open(self.train_result_file, 'r') as f:
                self.train_result = json.load(f)
            return self.train_result
        
    def save_feature_centers(self, file_path):
        with open(file_path, 'w') as f:
            json.dump(self.train_result, f)

        print(f"Feature centers saved to {file_path}.")

    def save_flow_features(self, file_path):
        with open(file_path, 'a+') as f:
            json.dump({'Results' : self.flow_features}, f)
        
        print(f"Flow features saved to {file_path}, including {len(self.flow_features)} records.")


def weight_transform(info):
    """
    Transform packet metadata into a weighted value.

    :param info: A PacketMetaData-like object with attributes: pkt_length, proto_code, and time_stamp
    :return: The transformed weight as a double
    """
    return info.length * 10 + info.type_code / 10 + -math.log2(info.timestamp) * 15.68

def wave_analyze(raw_data, flowfeatures : FlowFeatures, p_analyzer_config : dict):
    cur_len = len(raw_data)
    min_interval_time = 1e-5

    # Address aggregate
    mp = defaultdict(list)
    analysis_pkt_len = 0

    for i in range(cur_len):
        addr = raw_data[i].addr
        analysis_pkt_len += raw_data[i].length
        mp[addr].append(i)

    # Iterate through the aggregated map
    for addr, idx_list in mp.items():
        if len(idx_list) < 2 * p_analyzer_config['n_fft']:
            continue

        # Calculate time interval
        for i in range(len(idx_list) - 1, 0, -1):
            raw_data[idx_list[i]].timestamp -= raw_data[idx_list[i - 1]].timestamp
            if raw_data[idx_list[i]].timestamp <= 0:
                raw_data[idx_list[i]].timestamp = min_interval_time
        raw_data[idx_list[0]].timestamp = min_interval_time

        # Packet encoding
        ten = torch.zeros(len(idx_list))
        for i, idx in enumerate(idx_list):
            ten[i] = weight_transform(raw_data[idx])

        print(f"Source : {addr} The length of the packet is {ten.shape[0]}")

        # Frequency domain analysis
        ten_fft = torch.stft(ten, p_analyzer_config['n_fft'], return_complex=False)

        # ten_fft = torch.view_as_real(ten_fft)

        ten_power = ten_fft[..., 0] ** 2 + ten_fft[..., 1] ** 2

        ten_power = ten_power.squeeze()

        ten_res = (ten_power + 1).log2().permute(1, 0)
        
        ten_res = torch.where(torch.isnan(ten_res), torch.zeros_like(ten_res), ten_res)
        ten_res = torch.where(torch.isinf(ten_res), torch.zeros_like(ten_res), ten_res)

        if ten_res.size(0) > p_analyzer_config['mean_win_train'] + 1:
            data_to_add = []
            for _ in range(p_analyzer_config['num_train_sample']):
                start_index = random.randint(0, ten_res.size(0) - p_analyzer_config['mean_win_train'] - 1)
                ten_temp = ten_res[start_index:start_index + p_analyzer_config['mean_win_train']].mean(0)
                data_to_add.append(ten_temp.tolist())

            flowfeatures.add_batch_train_data(data_to_add)
        else:
            ten_temp = ten_res.mean(0)
            data_to_add = ten_temp.tolist()

            flowfeatures.add_train_data(data_to_add)

        if flowfeatures.reach_learn() and not flowfeatures.start_learn:
            print(f"Trigger the training of learner.")
            flowfeatures.start_train(p_analyzer_config['num_clusters'])

        centers = flowfeatures.get_feature_centers()
        # Turn the centers into tensor
        centers = torch.tensor(centers)

        # Testing phase: calculate min distance to cluster centers
        min_dist = flowfeatures.max_cluster_dist
        if ten_res.size(0) > p_analyzer_config['mean_win_test']:
            max_dist = 0
            for i in range(0, ten_res.size(0) - p_analyzer_config['mean_win_test'], p_analyzer_config['mean_win_test']):
                tt = ten_res[i:i + p_analyzer_config['mean_win_test']].mean(0)
                min_dist = min([torch.norm(tt - center).item() for center in centers])
                max_dist = max(max_dist, min_dist)
            min_dist = max_dist
        else:
            tt = ten_res.mean(0)
            min_dist = min([torch.norm(tt - center).item() for center in centers])
            
        print(f"Analyzer {len(idx_list)} packets, with loss: {min_dist:.3f}")
        if p_analyzer_config['ip_verbose'] and p_analyzer_config['verbose_ip_target'] == addr:
            print(f"Analyzer abnormal {len(idx_list)} packets, with loss: {min_dist:.3f}")

        buf_loc = {
            'address': addr,
            'distence': min_dist,
            'packet_num': len(idx_list)
        }
        flowfeatures.add_feature(buf_loc)

