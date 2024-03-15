cot_prompt = '''
As a security researcher, you must analyse the given code and respond to the step number {step}. If there are previous steps, the answers to them have already been provided and must be considered accurate. You are currently looking at the following code:
```java
{input}
```
Steps:
1. Identify All Weaknesses: Identify which vulnerabilities could be present in the following code.
2. Review User Input Handling: Look for any input sources that are not properly validated or sanitized before being used in unsafe manner. If variable that is passed into unsafe function is not directly influenced by external user input, the vulnerability is not currently present and must not be reported.
3. Analyze Data Flow: Trace the flow of untrusted data to the system command. Ensure that there are no points where user-controlled input can directly influence the command execution.
4. Check for Mitigations: Examine if there are any mitigations in place to prevent command injection, such as input validation, sanitization, or using safer alternatives to executing system commands.
5. Evaluate Conditional Branching: If there's dead code (that can never be reached), then this part must not be evaluated.
6. Assess Error Handling: Evaluate how errors, if any, are handled.
7. Identify Code Leaking Secrets: Check whether the code contains secrets that should not be public knowledge.
8. Provide verdict (one line for every potential discovered weakness). Keep in mind you must not report vulnerabilities that cannot be currently abused by malicious actors. False positive results must be kept to minimum. The verdict must be in the format:
 vulnerability: <YES or NO> | vulnerability type: <CWE_ID> |
 ...
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