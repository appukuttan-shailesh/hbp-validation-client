import os
import uuid
import json
import sciunit
import pickle
import argparse
from datetime import datetime
from importlib import import_module
import mimetypes
import math
try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path  # Python 2 backport

parser = argparse.ArgumentParser()
parser.add_argument("model_pickle_file", help="absolute path of pickled file of sciunit.Model instance")
parser.add_argument("test_config_file", help="absolute path of the test config file")
parser.add_argument("test_result_file", help="desired absolute path of the generated test result file")
args = parser.parse_args()

with open(args.model_pickle_file, 'rb') as file:
    model = pickle.load(file)
test_config_file = args.test_config_file
test_result_file = args.test_result_file

base_folder = os.path.dirname(os.path.realpath(test_config_file))

# Load the test info from config file
with open(test_config_file) as file:
    test_info = json.load(file)

# Identify test class path
path_parts = test_info["test_instance_path"].split(".")
cls_name = path_parts[-1]
module_name = ".".join(path_parts[:-1])
test_module = import_module(module_name)
test_cls = getattr(test_module, cls_name)

# Read observation data required by test
with open(os.path.join(base_folder, test_info["test_observation_file"]), 'r') as file:
    observation_data = file.read()
content_type = mimetypes.guess_type(test_info["test_observation_file"])[0]
if content_type == "application/json":
    observation_data = json.loads(observation_data)

# Create the :class:`sciunit.Test` instance
params = test_info["params"]
test = test_cls(observation=observation_data, **params)
test.uuid = test_info["test_instance_id"]

print("----------------------------------------------")
print("Test name: ", test.name)
print("Test type: ", type(test))
print("----------------------------------------------")

# Check the model
if not isinstance(model, sciunit.Model):
    raise TypeError("`model` is not a sciunit Model!")
print("----------------------------------------------")
print("Model name: ", model.name)
print("Model type: ", type(model))
print("----------------------------------------------")

# Run the test
t_start = datetime.utcnow()
score = test.judge(model, deep_error=True)
t_end = datetime.utcnow()

print("----------------------------------------------")
print("Score: ", score.score)
if "figures" in score.related_data:
    print("Output files: ")
    for item in score.related_data["figures"]:
        print(item)
print("----------------------------------------------")

score.runtime = str(int(math.ceil((t_end-t_start).total_seconds()))) + " s"
score.exec_timestamp = t_end
# score.exec_platform = str(self._get_platform())

# Save result info to file
Path(os.path.join(base_folder, "results")).mkdir(parents=True, exist_ok=True)
with open(test_result_file, 'wb') as file:
    pickle.dump(score, file)
