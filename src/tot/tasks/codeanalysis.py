import os
import re
from datetime import date
from tot.tasks.base import Task, DATA_PATH
from tot.prompts.codeanalysis import *
from tot.models import gpt, gpt_usage, get_tokens


def clean_result(text):
    pattern = r'\b(?:cwe-|CWE-|cwe|CWE)(\d+)\b'
    matches = re.findall(pattern, text, re.IGNORECASE)
    unique_matches = set(matches)
    formatted_matches = [f'CWE-{match}' for match in unique_matches]
    return " ".join(formatted_matches)


def get_cwes(input_text):
    vulnerabilities = ""
    if "\n" in input_text:
        for line in input_text.split("\n"):
            if "vulnerability: YES |" in line.strip():
                vulnerabilities += clean_result(line.strip()) + " "
    else:
        if "vulnerability: YES |" in input_text.strip():
            vulnerabilities += clean_result(input_text.strip()) + " "

    return vulnerabilities.strip()


class CodeAnalysisTask(Task):
    """
    Input (x)   : a text instruction
    Output (y)  : a text generation
    Reward (r)  : # TODO
    Input Example: 
    Output Example: 
    """
    def __init__(self, file='file_names.txt'):
        """
        file: a text file, each line is some sentences
        """
        super().__init__()
        path = os.path.join(DATA_PATH, 'codeanalysis', file)
        self.data = open(path).readlines()
        self.directory_path = os.path.join("/home", "thesis", "juliet-top-25", "src", "testcases")
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
        file_name = self.data[idx].strip()
        for root, dirs, files in os.walk(self.directory_path):
            for file in files:
                if file_name in file:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        content = f.readlines()
                    content[0] = "package com.bank.service;\n"  # remove package name to avoid leaking clues to LLM

                    for i, line in enumerate(content):  # remove whitespace to save on tokens
                        content[i] = line.strip()
                    return "\n".join(content)
    
    def test_output(self, idx: int, output: str):  # todo Is there any point here?
        return {'r': 10}

    def write_result(self, idx, model, model_output, time_taken, previous_ct, previous_pt, prior_costs):
        cwes = get_cwes(model_output[0])
        with open("results.csv", "a") as res:
            res.write(
                f"{model};"
                f"juliet-top-25-subset-34;"
                f"cot_high_level;"
                f"{self.data[idx].strip()};"
                f"{len(cwes) != 0};"
                f"{cwes};"
                f"{time_taken};"
                f"total_tokens: {get_tokens()[0] - previous_ct + get_tokens()[1] - previous_pt}, completion_tokens: {get_tokens()[0] - previous_ct}, prompt_tokens: {get_tokens()[1] - previous_pt};"
                f"{gpt_usage(model) - prior_costs};"
                f"{str(date.today())}\n"
            )

    #@staticmethod
    #def standard_prompt_wrap(x: str, y:str='') -> str:
    #    return standard_prompt.format(input=x) + y

    @staticmethod
    def cot_prompt_wrap(x: str, y:str='') -> str:
        return cot_prompt.format(input=x) + y

    @staticmethod
    def vote_prompt_wrap(x: str, ys: list) -> str:
        prompt = vote_prompt.format(input=x)
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
