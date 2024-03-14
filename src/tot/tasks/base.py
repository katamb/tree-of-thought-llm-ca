import os
DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data')


class Task:
    def __init__(self):
        pass

    def __len__(self) -> int:
        pass

    def get_input(self, idx: int) -> str:
        pass

    def test_output(self, idx: int, output: str):
        pass

    def write_result(self, idx: int, model: str, model_output: str, time_taken: float, previous_ct: int, previous_pt: int, prior_costs: float):
        pass
