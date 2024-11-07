from dataclasses import dataclass

@dataclass
class FlowFeaturesConfig:
    n_fft = 50
    mean_win_train = 50
    mean_win_test = 100
    num_train_data = 2000
    num_train_sample = 50
    ip_verbose = True
    verbose_ip_target = "192.168.3.11"
    save_to_file = False
    save_to_file_for_centers = "./centers.json"
    save_to_file_from_centers = "./centers.json"
    num_clusters = 10