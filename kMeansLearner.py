import numpy as np
import numpy as np
from sklearn.cluster import KMeans

class kMeansLearner:
    def __init__(self, num_clusters = 10):
        self.num_clusters = num_clusters
        # self.centroids = None

    def perform_kmeans_clustering(self, train_set, k):
        """
        Perform KMeans clustering algorithm.

        Parameters:
        - train_set: A nested list (2D array) representing the training dataset.
        - k: The number of clusters.

        Returns:
        - train_result: The centroids of the clusters, represented as a 2D array
                        (equivalent to C++'s vector<vector<double_t>>).
        """
        # Convert the input train_set into a numpy array
        dataset = np.array(train_set)
        
        # Initialize KMeans from scikit-learn with the specified number of clusters
        kmeans = KMeans(n_clusters=k, random_state=42)
        
        # Fit the KMeans algorithm to the dataset
        kmeans.fit(dataset)
        
        # Retrieve the centroids of the clusters
        centroids = kmeans.cluster_centers_
        
        # Convert centroids to a list (equivalent to C++'s vector<vector<double_t>>)
        train_result = centroids.tolist()

        return train_result
