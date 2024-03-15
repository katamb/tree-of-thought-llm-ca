cot_prompt = '''
As a security researcher, you must analyse the given code and respond to the step number {step_nr}. If there are previous steps, the answers to them have already been provided and must be considered accurate. Keep your responses short and concise. You are currently looking at the following code:
```java
{input}
```
Steps:
1. Identify All Weaknesses: Identify which vulnerabilities could be present in the following code.
{next_steps}
'''

# Evaluate
vote_prompt = '''Given a code snippet and several choices for the analysis of this code, decide which choice is best and most accurate. Code:
```java
{input}
```
Analyze each choice in detail, then conclude in the last line "The best choice is {{s}}", where s the integer id of the choice.
'''

# Score - NOT USED
score_prompt = '''Analyze the following passage, then at the last line conclude "Thus the coherency score is {s}", where s is an integer from 1 to 10.
'''