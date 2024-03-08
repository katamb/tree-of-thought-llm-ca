import os
import re
from tot.tasks.base import Task, DATA_PATH
from tot.prompts.codeanalysis import *
from tot.models import gpt


class CodeAnalysisTask(Task):
    """
    Input (x)   : a text instruction
    Output (y)  : a text generation
    Reward (r)  : # TODO
    Input Example: 
    Output Example: 
    """
    def __init__(self, file='J11609.java'):
        """
        file: a text file, each line is some sentences
        """
        super().__init__()
        path = os.path.join(DATA_PATH, 'codeanalysis', file)
        self.data = open(path).read()
        self.steps = 8
        self.stops = [
            'Review User Input Handling',
            'Analyze Data Flow',
            'Check for Mitigations',
            'Evaluate Conditional Branching',
            'Assess Error Handling',
            'Identify Code Leaking Secrets',
            'Provide verdict',
            None
        ]

    def __len__(self) -> int:
        return len(self.data)
    
    def get_input(self, idx: int) -> str:
        return self.data #[idx]
    
    def test_output(self, idx: int, output: str):  # todo
        return {'r': 10}
    
    #@staticmethod
    #def standard_prompt_wrap(x: str, y:str='') -> str:
    #    return standard_prompt.format(input=x) + y

    @staticmethod
    def cot_prompt_wrap(x: str, y:str='') -> str:
        return cot_prompt.format(input=x) + y

    @staticmethod
    def vote_prompt_wrap(x: str, ys: list) -> str:
        prompt = vote_prompt
        for i, y in enumerate(ys, 1):
            # y = y.replace('Plan:\n', '')
            # TODO: truncate the plan part?
            prompt += f'Choice {i}:\n{y}\n'
        return prompt
    
    @staticmethod
    def vote_outputs_unwrap(vote_outputs: list, n_candidates: int) -> list:
        vote_results = [0] * n_candidates
        for vote_output in vote_outputs:
            pattern = r".*best choice is .*(\d+).*"
            match = re.match(pattern, vote_output, re.DOTALL)
            if match:
                vote = int(match.groups()[0]) - 1
                if vote in range(n_candidates):
                    vote_results[vote] += 1
            else:
                print(f'vote no match: {[vote_output]}')
        return vote_results
