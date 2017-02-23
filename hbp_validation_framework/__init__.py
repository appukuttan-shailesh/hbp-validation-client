"""
A Python package for working with the Human Brain Project Model Validation Framework.

Andrew Davison, CNRS, February 2016

Licence: BSD 3-clause, see LICENSE.txt

"""

import os
from importlib import import_module
import platform
try:  # Python 3
    from urllib.request import urlopen
    from urllib.error import URLError
except ImportError:  # Python 2
    from urllib2 import urlopen, URLError
import socket
import json
import quantities
import requests


VALIDATION_FRAMEWORK_URL = "https://validation.brainsimulation.eu"
#VALIDATION_FRAMEWORK_URL = "http://127.0.0.1:8001"


class ValidationTestLibrary(object):
    """
    Client for the HBP Validation Test library.

    Usage
    -----

    # Download the test definition
    test_library = ValidationTestLibrary()
    test = test_library.get_validation_test(test_uri)

    # Run the test
    score = test.judge(model)  # tests use the SciUnit framework

    # Register the result
    test_library.register(score)
    """

    def __init__(self, url=VALIDATION_FRAMEWORK_URL):
        self.url = url

    def get_validation_test(self, test_uri, **params):
        """
        Download a test definition from the given URL, or load from a local JSON file.

        `params` are additional keyword arguments to be passed to the :class:`Test` constructor.

        Returns a :class:`sciunit.Test` instance.
        """
        if os.path.isfile(test_uri):
            # test_uri is a local path
            with open(test_uri) as fp:
                config = json.load(fp)
        else:
            config = requests.get(test_uri).json()

        # Import the Test class specified in the definition.
        # This assumes that the module containing the class is installed.
        # In future we could add the ability to (optionally) install
        # Python packages automatically.

        path_parts = config["code"]["path"].split(".")
        cls_name = path_parts[-1]
        module_name = ".".join(path_parts[:-1])
        test_module = import_module(module_name)
        test_cls = getattr(test_module, cls_name)

        # Load the reference data ("observations")
        # For now this is assumed to be in JSON format, but we
        # should support other data formats.
        # For now, data is assumed to be on the local disk, but we
        # need to add support for remote downloads.
        with open(config["data_location"]) as fp:
            observation_data = json.load(fp)

        # Transform string representations of quantities, e.g. "-65 mV",
        # into :class:`quantities.Quantity` objects.
        observations = {}
        for key, val in observation_data.items():
            quantity_parts = val.split(" ")
            number = float(quantity_parts[0])
            if len(quantity_parts) > 1:
                assert len(quantity_parts) == 2
                units = getattr(quantities, quantity_parts[1])
            else:
                units = getattr(quantities, "unitless")
            observations[key] = number * units

        # Create the :class:`sciunit.Test` instance
        test_instance = test_cls(observations, **params)
        test_instance.id = test_uri
        return test_instance

    def register(self, test_result, data_store=None):
        """
        Register the test result with the HBP Validation Results Service.

        Arguments:
            test_result - a :class:`sciunit.Score` instance returned by `test.judge(model)`
            data_store - a :class:`DataStore` instance, for uploading related data
                         generated by the test run, e.g. figures.
        """
        print("TEST RESULT: {}".format(test_result))
        print(test_result.model)
        print(test_result.prediction)
        print(test_result.observation)
        print(test_result.score)
        for file_path in test_result.related_data:
            print(file_path)
        # depending on value of data_store,
        # upload data file to Collab storage,
        # or just store path if it is on HPAC machine
        if data_store:
            results_storage = data_store.upload_data(test_result.related_data["figures"])
        else:
            results_storage = ""

        # check that the model is registered with the model registry.
        # If not, offer to register it?

        data = {
            "model_instance": {
                "model_id": test_result.model.id,  # uri? overload 'model.name' attribute?
                "version": test_result.model.version,
                "parameters": test_result.model.params
            },
            "test_definition": test_result.test.id,  # this should be the test URI provided to get_validation_test()
            "results_storage": results_storage,
            "result": test_result.score,
            "passed": None,
            "platform": self.get_platform(),
        }
        response = requests.post(self.url + "/results/", data=json.dumps(data))
        print(response)

    def get_platform(self):
        """
        Return a dict containing information about the platform the test was run on.
        """
        # This needs to be extended to support remote execution, e.g. job queues on clusters.
        # Use Sumatra?
        network_name = platform.node()
        bits, linkage = platform.architecture()
        if _have_internet_connection():
            try:
                ip_addr = socket.gethostbyname(network_name)
            except socket.gaierror:
                ip_addr = "127.0.0.1"
        else:
            ip_addr = "127.0.0.1"
        return dict(architecture_bits=bits,
                    architecture_linkage=linkage,
                    machine=platform.machine(),
                    network_name=network_name,
                    ip_addr=ip_addr,
                    processor=platform.processor(),
                    release=platform.release(),
                    system_name=platform.system(),
                    version=platform.version())


def _have_internet_connection():
    """
    Not foolproof, but allows checking for an external connection with a short
    timeout, before trying socket.gethostbyname(), which has a very long
    timeout.
    """
    test_address = 'http://74.125.113.99'  # google.com
    try:
        urlopen(test_address, timeout=1)
        return True
    except (URLError, socket.timeout):
        pass
    return False