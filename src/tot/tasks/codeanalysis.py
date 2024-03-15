import os
import re
from datetime import date
from tot.tasks.base import Task, DATA_PATH
from tot.prompts.codeanalysis import *
from tot.models import gpt, gpt_usage


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
        self.next_step = [
            "",
            """2. Review User Input Handling: Look for any input sources that are not properly validated or sanitized before being used in unsafe manner. If variable that is passed into unsafe function is not directly influenced by external user input, the vulnerability is not currently present and must not be reported.""",
            """2. Review User Input Handling: Look for any input sources that are not properly validated or sanitized before being used in unsafe manner. If variable that is passed into unsafe function is not directly influenced by external user input, the vulnerability is not currently present and must not be reported.
3. Analyze Data Flow: Trace the flow of untrusted data to the system command. Ensure that there are no points where user-controlled input can directly influence the command execution.""",
            """2. Review User Input Handling: Look for any input sources that are not properly validated or sanitized before being used in unsafe manner. If variable that is passed into unsafe function is not directly influenced by external user input, the vulnerability is not currently present and must not be reported.
3. Analyze Data Flow: Trace the flow of untrusted data to the system command. Ensure that there are no points where user-controlled input can directly influence the command execution.
4. Check for Mitigations: Examine if there are any mitigations in place to prevent command injection, such as input validation, sanitization, or using safer alternatives to executing system commands.""",
            """2. Review User Input Handling: Look for any input sources that are not properly validated or sanitized before being used in unsafe manner. If variable that is passed into unsafe function is not directly influenced by external user input, the vulnerability is not currently present and must not be reported.
3. Analyze Data Flow: Trace the flow of untrusted data to the system command. Ensure that there are no points where user-controlled input can directly influence the command execution.
4. Check for Mitigations: Examine if there are any mitigations in place to prevent command injection, such as input validation, sanitization, or using safer alternatives to executing system commands.
5. Evaluate Conditional Branching: If there's dead code (that can never be reached), then this part must not be evaluated.""",
            """2. Review User Input Handling: Look for any input sources that are not properly validated or sanitized before being used in unsafe manner. If variable that is passed into unsafe function is not directly influenced by external user input, the vulnerability is not currently present and must not be reported.
3. Analyze Data Flow: Trace the flow of untrusted data to the system command. Ensure that there are no points where user-controlled input can directly influence the command execution.
4. Check for Mitigations: Examine if there are any mitigations in place to prevent command injection, such as input validation, sanitization, or using safer alternatives to executing system commands.
5. Evaluate Conditional Branching: If there's dead code (that can never be reached), then this part must not be evaluated.
6. Assess Error Handling: Evaluate how errors, if any, are handled.""",
            """2. Review User Input Handling: Look for any input sources that are not properly validated or sanitized before being used in unsafe manner. If variable that is passed into unsafe function is not directly influenced by external user input, the vulnerability is not currently present and must not be reported.
3. Analyze Data Flow: Trace the flow of untrusted data to the system command. Ensure that there are no points where user-controlled input can directly influence the command execution.
4. Check for Mitigations: Examine if there are any mitigations in place to prevent command injection, such as input validation, sanitization, or using safer alternatives to executing system commands.
5. Evaluate Conditional Branching: If there's dead code (that can never be reached), then this part must not be evaluated.
6. Assess Error Handling: Evaluate how errors, if any, are handled.
7. Identify Code Leaking Secrets: Check whether the code contains secrets that should not be public knowledge.""",
            """2. Review User Input Handling: Look for any input sources that are not properly validated or sanitized before being used in unsafe manner. If variable that is passed into unsafe function is not directly influenced by external user input, the vulnerability is not currently present and must not be reported.
3. Analyze Data Flow: Trace the flow of untrusted data to the system command. Ensure that there are no points where user-controlled input can directly influence the command execution.
4. Check for Mitigations: Examine if there are any mitigations in place to prevent command injection, such as input validation, sanitization, or using safer alternatives to executing system commands.
5. Evaluate Conditional Branching: If there's dead code (that can never be reached), then this part must not be evaluated.
6. Assess Error Handling: Evaluate how errors, if any, are handled.
7. Identify Code Leaking Secrets: Check whether the code contains secrets that should not be public knowledge.
8. Provide verdict (one line for every potential discovered weakness). Keep in mind you must not report vulnerabilities that cannot be currently abused by malicious actors. False positive results must be kept to minimum. The response for the last step (verdict) must be in the format:
 vulnerability: <YES or NO> | vulnerability type: <CWE_ID> |
 ..."""
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

    def write_result(self, idx, model, model_output, time_taken,  prior_gpt_usage):
        cwes = get_cwes(model_output[0])
        current_usage = gpt_usage(model)
        current_cost = current_usage["cost"]
        current_ct = current_usage["completion_tokens"]
        current_pt = current_usage["prompt_tokens"]
        prior_cost = prior_gpt_usage["cost"]
        prior_ct = prior_gpt_usage["completion_tokens"]
        prior_pt = prior_gpt_usage["prompt_tokens"]
        with open("results.csv", "a") as res:
            res.write(
                f"{model};"
                f"juliet-top-25-subset-34;"
                f"tot_high_level;"
                f"{self.data[idx].strip()};"
                f"{len(cwes) != 0};"
                f"{cwes};"
                f"{time_taken};"
                f"total_tokens: {current_ct - prior_ct + current_pt - prior_pt}, completion_tokens: {current_ct - prior_ct}, prompt_tokens: {current_pt - prior_pt};"
                f"{current_cost - prior_cost};"
                f"{str(date.today())}\n"
            )

    # @staticmethod
    # def standard_prompt_wrap(x: str, y:str='') -> str:
    #    return standard_prompt.format(input=x) + y

    def cot_prompt_wrap(self, x: str, y: str = '', idx: int = 0) -> str:
        return cot_prompt.format(input=x, step_nr=(idx + 1), next_steps=self.next_step[idx]) + y

    @staticmethod
    def vote_prompt_wrap(x: str, ys: list) -> str:
        prompt = vote_prompt.format(input=x)
        for i, y in enumerate(ys, 1):
            # y = y.replace('Plan:\n', '')
            # TODO: truncate the plan part?
            resp = y.split("\n----\n")[-1]
            prompt += f'Choice {i}:\n{resp}\n'
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
