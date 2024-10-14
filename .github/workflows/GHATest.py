import argparse
import subprocess
import sys

parser = argparse.ArgumentParser()

parser.add_argument('-a')    
parser.add_argument('-p')  
parser.add_argument('-l') 
parser.add_argument('-n')

print("RUNNING")
args = parser.parse_args()
print(args)            

test = subprocess.run(f"ssh -o StrictHostKeyChecking=no -i ~/.ssh/jenkins_regression_lab -l {args.l} -p {args.p} {args.a} build {args.n} -s -v", shell=True)
print(f"Ending test with exit code {test.returncode}")
exit(test.returncode)
