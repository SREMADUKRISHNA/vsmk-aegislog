import math

class ThreatModel:
    """
    A lightweight, rule-based machine learning hybrid model for threat scoring.
    Uses a Logistic Regression inference approach with pre-tuned weights 
    optimized for brute-force detection.
    """
    
    def __init__(self):
        # Weights tuned for brute-force detection
        # High positive weight for max failures from a single IP
        # Moderate weight for overall failure ratio
        self.weights = {
            'failure_ratio': 10.0,       # If 100% fails, high impact
            'max_single_ip_fails': 0.8,  # Each failed login from top attacker adds to score
            'unique_ip_count': 0.1,      # Slight increase for distributed attacks
            'bias': -4.0                 # Baseline bias to keep score low for normal traffic
        }

    def _sigmoid(self, x):
        """Standard sigmoid activation function."""
        try:
            return 1 / (1 + math.exp(-x))
        except OverflowError:
            return 0 if x < 0 else 1

    def predict_score(self, features):
        """
        Predicts a threat score (0-100) based on extracted features.
        """
        # Linear combination
        z = self.weights['bias']
        z += features['failure_ratio'] * self.weights['failure_ratio']
        z += features['max_single_ip_fails'] * self.weights['max_single_ip_fails']
        z += features['unique_ip_count'] * self.weights['unique_ip_count']
        
        # Apply activation
        probability = self._sigmoid(z)
        
        # Scale to 0-100
        score = int(probability * 100)
        return score

    def get_threat_level(self, score):
        if score < 30:
            return "LOW"
        elif score < 70:
            return "MEDIUM"
        else:
            return "HIGH"
