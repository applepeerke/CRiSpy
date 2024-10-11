# CRiSp 
CRiSp stands for `Code Review involving Security Patterns`.
It is a tool to scan a code base of any language for security vulnerabilities. 

CRiSp is built as a starting point for manual security code review.
Due to the general patterns it searches for it is suitable for (nearly) all program languages. 
It contains deep-diving analysis for some specific languages, like
* Python
* Java
* C#

## Prerequisites
In order to run CRiSp on you local machine, you need to have the following installed:
* [Python](https://www.python.org/) 3.10 or higher.
* A few dependencies listed in `requirements.txt`


## Getting started
THe frontend is generated from OpenAPI docs.
   1. `cd "<my_path_to_src>"`
   2. Start the web server: `python main.py`
   3. In your web browser, navigate to `http://0.0.0.0:8086/docs`

That's all, have fun!

## Output
All output is directed to a CRiSp subfolder in `Output/Result` (by default).
The potential findings are listed in 
* `Findings.csv`, or in a file called 
* `<project>_Vnnn.csv`.

### Dataflow
In supported frameworks (e.g. Python Django/FastAPI/Marshmallow or Java Spring) a subfolder `DataFlow` may be created.
In `DataFlow` you can find the endpoints with their vulnerabilities in the following csv files:
* `Endpoints_<framework>.csv`
* `Model - field validations.csv`

### Other output
* `Log.csv`
* `version_vulnerabilities.csv` (optional) with CVE vulnerabilities found in dependencies/packages.
