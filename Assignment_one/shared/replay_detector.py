"""
Replay Detection Module
Detects and prevents replayed protected application records.
Uses sliding window approach based on sequence numbers.
"""

from .config import REPLAY_WINDOW_SIZE


class ReplayDetector:
    """
    Detects replayed records using a sliding window approach.
    Maintains a window of recently seen sequence numbers.
    """

    def __init__(self, window_size=REPLAY_WINDOW_SIZE):
        """
        Initialize replay detector.

        Args:
            window_size: Size of sliding window (max sequence numbers to track)
        """
        self.window_size = window_size
        self.seen_sequences = set()
        self.max_sequence = -1

    def check(self, sequence_number):
        """
        Check if sequence number is a replay without updating state.

        Args:
            sequence_number: int sequence number from record

        Returns:
            dict: {
                'is_replay': bool,
                'is_out_of_order': bool,
                'message': str
            }
        """
        if sequence_number in self.seen_sequences:
            return {
                'is_replay': True,
                'is_out_of_order': False,
                'message': f'Replay detected: sequence {sequence_number} already seen'
            }

        if sequence_number < self.max_sequence:
            return {
                'is_replay': True,
                'is_out_of_order': True,
                'message': f'Out-of-order/replayed: sequence {sequence_number} < max {self.max_sequence}'
            }

        return {
            'is_replay': False,
            'is_out_of_order': False,
            'message': f'Sequence {sequence_number} accepted'
        }

    def register(self, sequence_number):
        """
        Commit a sequence number after successful authentication.
        """
        self.seen_sequences.add(sequence_number)

        if sequence_number > self.max_sequence:
            self.max_sequence = sequence_number

        if len(self.seen_sequences) > self.window_size:
            min_sequence = self.max_sequence - self.window_size
            self.seen_sequences = {seq for seq in self.seen_sequences if seq > min_sequence}

    def check_and_update(self, sequence_number):
        """
        Check if sequence number is a replay and update window.
        Prefer check() + register() after auth success in the receiver path.
        """
        result = self.check(sequence_number)
        if not result['is_replay']:
            self.register(sequence_number)
            result['message'] = f'Sequence {sequence_number} accepted'
        return result

    def is_replay(self, sequence_number):
        """
        Quick check if sequence is likely a replay (without updating).

        Args:
            sequence_number: int to check

        Returns:
            bool: True if likely replay or out-of-order
        """
        return self.check(sequence_number)['is_replay']

    def get_max_sequence(self):
        """Return the maximum sequence number seen."""
        return self.max_sequence

    def get_window_size(self):
        """Return the current window size."""
        return len(self.seen_sequences)

    def reset(self):
        """Reset replay detector (for testing)."""
        self.seen_sequences.clear()
        self.max_sequence = -1

    def export_state(self):
        """Export replay detector state (for debugging)."""
        return {
            'window_size': len(self.seen_sequences),
            'max_sequence': self.max_sequence,
            'max_window_capacity': self.window_size
        }
