# Part of the malicious test fixture: exists so the SAST leg has something
# to find, alongside the runtime attacks in server.js. Never executed.
import subprocess

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def run_untrusted(cmd):
    # shell=True on an untrusted argument: command injection.
    return subprocess.run(cmd, shell=True, capture_output=True)


def eval_untrusted(expr):
    return eval(expr)
