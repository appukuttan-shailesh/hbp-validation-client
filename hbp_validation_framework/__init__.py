"""
A Python package for working with the Human Brain Project Model Validation Framework.

Andrew Davison and Shailesh Appukuttan, CNRS, February 2016

Licence: BSD 3-clause, see LICENSE.txt

"""

import os
from importlib import import_module
import platform
try:  # Python 3
    from urllib.request import urlopen
    from urllib.parse import urlparse, urlencode
    from urllib.error import URLError
except ImportError:  # Python 2
    from urllib2 import urlopen, URLError
    from urlparse import urlparse
    from urllib import urlencode
import socket
import json
import ast
import getpass
import quantities
import requests
from requests.auth import AuthBase
from .datastores import URI_SCHEME_MAP


#VALIDATION_FRAMEWORK_URL = "https://validation.brainsimulation.eu"
VALIDATION_FRAMEWORK_URL = "https://validation-dev.brainsimulation.eu"
#VALIDATION_FRAMEWORK_URL = "https://validation-v1.brainsimulation.eu"
#VALIDATION_FRAMEWORK_URL = "http://127.0.0.1:8001"


class HBPAuth(AuthBase):
    """Attaches OIDC Bearer Authentication to the given Request object."""

    def __init__(self, token):
        # setup any auth-related data here
        self.token = token

    def __call__(self, r):
        # modify and return the request
        r.headers['Authorization'] = 'Bearer ' + self.token
        return r



class BaseClient(object):
    """

    """

    def __init__(self, username,
                 password=None,
                 url=VALIDATION_FRAMEWORK_URL):
        self.username = username
        self.url = url
        self.verify = True
        if password is None:
            # prompt for password
            #password = getpass.getpass()
            password = os.environ.get('HBP_PASS')
        self._hbp_auth(username, password)
        self.auth = HBPAuth(self.token)

    def _hbp_auth(self, username, password):
        """
        """
        redirect_uri = self.url + '/complete/hbp/'

        self.session = requests.Session()
        # 1. login button on NMPI
        rNMPI1 = self.session.get(self.url + "/login/hbp/?next=/config.json",
                                  allow_redirects=False, verify=self.verify)
        # 2. receives a redirect or some Javascript for doing an XMLHttpRequest
        if rNMPI1.status_code in (302, 200):
            # Get its new destination (location)
            if rNMPI1.status_code == 302:
                url = rNMPI1.headers.get('location')
            else:
                res = rNMPI1.content
                state = res[res.find("state")+6:res.find("&redirect_uri")]
                # Dev ID = 90c719e0-29ce-43a2-9c53-15cb314c2d0b
                # Prototype ID = 8a6b7458-1044-4ebd-9b7e-f8fd3469069c
                # Prod ID = 3ae21f28-0302-4d28-8581-15853ad6107d
                url = "https://services.humanbrainproject.eu/oidc/authorize?state={}&redirect_uri={}/complete/hbp/&response_type=code&client_id=90c719e0-29ce-43a2-9c53-15cb314c2d0b".format(state, self.url)
            # get the exchange cookie
            cookie = rNMPI1.headers.get('set-cookie').split(";")[0]
            self.session.headers.update({'cookie': cookie})
            # 3. request to the provided url at HBP
            rHBP1 = self.session.get(url, allow_redirects=False, verify=self.verify)
            # 4. receives a redirect to HBP login page
            if rHBP1.status_code == 302:
                # Get its new destination (location)
                url = rHBP1.headers.get('location')
                cookie = rHBP1.headers.get('set-cookie').split(";")[0]
                self.session.headers.update({'cookie': cookie})
                # 5. request to the provided url at HBP
                rHBP2 = self.session.get(url, allow_redirects=False, verify=self.verify)
                # 6. HBP responds with the auth form
                if rHBP2.text:
                    # 7. Request to the auth service url
                    formdata = {
                        'j_username': username,
                        'j_password': password,
                        'submit': 'Login',
                        'redirect_uri': redirect_uri + '&response_type=code&client_id=nmpi'
                    }
                    headers = {'accept': 'application/json'}
                    rNMPI2 = self.session.post("https://services.humanbrainproject.eu/oidc/j_spring_security_check",
                                               data=formdata,
                                               allow_redirects=True,
                                               verify=self.verify,
                                               headers=headers)
                    # check good communication
                    if rNMPI2.status_code == requests.codes.ok:
                        #import pdb; pdb.set_trace()
                        # check success address
                        if rNMPI2.url == self.url + '/config.json':
                            # print rNMPI2.text
                            res = rNMPI2.json()
                            self.token = res['auth']['token']['access_token']
                            self.config = res
                        # unauthorized
                        else:
                            if 'error' in rNMPI2.url:
                                raise Exception("Authentication Failure: No token retrieved." + rNMPI2.url)
                            else:
                                raise Exception("Unhandled error in Authentication." + rNMPI2.url)
                    else:
                        raise Exception("Communication error")
                else:
                    raise Exception("Something went wrong. No text.")
            else:
                raise Exception("Something went wrong. Status code {} from HBP, expected 302".format(rHBP1.status_code))
        else:
            raise Exception("Something went wrong. Status code {} from NMPI, expected 302".format(rNMPI1.status_code))


class TestLibrary(BaseClient):
    """
    Client for the HBP Validation Test library.

    Usage
    -----
    # TODO
    test_library = TestLibrary()

    # List test definitions
    tests = test_library.list_validation_tests(brain_region="hippocampus",
                                               cell_type="pyramidal cell")

    # Download the test definition
    test = test_library.get_validation_test(test_uri)

    # Run the test
    score = test.judge(model)  # tests use the SciUnit framework

    # Register the result
    test_library.register(score)
    """

    def get_test_definition(self, test_path="", test_id = "", alias=""):
        """
        Download a test definition from the test library
        in the following ways (in order of priority):
        1) load from a local JSON file specified via 'test_path'
        2) specify the 'test_id'
        3) specify the 'alias' (of the test)
        Returns a dict containing information about the test.
        Also see: `get__test()`.
        """
        if test_path == "" and test_id == "" and alias == "":
            raise Exception("test_path or test_id or alias needs to be provided for finding a test.")

        if test_path and os.path.isfile(test_path):
            # test_path is a local path
            with open(test_path) as fp:
                test_json = json.load(fp)
        else:
            if test_id:
                test_uri = self.url + "/validationtestdef/?id=" + test_id + "&format=json"
            else:
                test_uri = self.url + "/validationtestdef/?alias=" + alias + "&format=json"
            test_json = requests.get(test_uri, auth=self.auth)

        if str(test_json) != "<Response [200]>":
            raise Exception("Error in retrieving test. Response = " + str(test_json.content))
        test_json = test_json.json()
        return test_json["tests"][0]

    def get_test_instance(self, instance_path="", test_id="", alias="", version="", instance_id=""):
        """
        Download a test instance definition from the test library
        in the following ways (in order of priority):
        1) load from a local JSON file specified via 'instance_path'
        2) specify 'instance_id' correspoding to test instance in test library
        3) specify "test_id" and "version"
        4) specify "alias" (of the test) and "version"
        Returns a dict containing information about the test instance.
        """
        if instance_path == "" and instance_id=="" and (test_id == "" or version == "") and (alias == "" or version == ""):
            raise Exception("instance_path or instance_id or (test_id, version) or (alias, version) needs to be provided for finding a test instance.")
        if instance_path and os.path.isfile(instance_path):
            # instance_path is a local path
            with open(instance_path) as fp:
                test_instance_json = json.load(fp)
        else:
            if instance_id:
                instance_uri = self.url + "/validationtestscode/?id=" + instance_id + "&format=json"
            elif test_id and version:
                instance_uri = self.url + "/validationtestscode/?test_definition_id=" + test_id + "&version=" + version + "&format=json"
            else:
                instance_uri = self.url + "/validationtestscode/?test_alias=" + alias + "&version=" + version + "&format=json"
            test_instance_json = requests.get(instance_uri, auth=self.auth)

        if str(test_instance_json) != "<Response [200]>":
            raise Exception("Error in retrieving test instance. Response = " + str(test_instance_json.content))
        test_instance_json = test_instance_json.json()
        return test_instance_json["tests"][0]

    def list_test_instances(self, instance_path="", test_id="", alias=""):
        """
        Download a list of test instance definitions belonging to a specified
        test from the test library in the following ways (in order of priority):
        1) load from a local JSON file specified via 'instance_path'
        2) specify "test_id"
        3) specify "alias" (of the test)
        Returns a list of dicts containing information about the test instances.
        """
        if instance_path == "" and test_id == "" and alias == "":
            raise Exception("instance_path or test_id or alias needs to be provided for finding test instances.")
        if instance_path and os.path.isfile(instance_path):
            # instance_path is a local path
            with open(instance_path) as fp:
                test_instances_json = json.load(fp)
        else:
            if test_id:
                instance_uri = self.url + "/validationtestscode/?test_definition_id=" + test_id + "&format=json"
            else:
                instance_uri = self.url + "/validationtestscode/?test_alias=" + alias + "&format=json"
            test_instances_json = requests.get(instance_uri, auth=self.auth)

        if str(test_instances_json) != "<Response [200]>":
            raise Exception("Error in retrieving test instances. Response = " + str(test_instances_json))
        test_instances_json = test_instances_json.json()
        return test_instances_json["tests"]

    def add_test_instance(self, test_id="", alias="", repository="", path="", version=""):
        """
        Register a new test instance definition for a test registered in the test library.
        Returns the UUID of the test instance that has been created.

        Note: 'alias' is not currently implemented in the API, and the same is kept for future use here.
        TO DO: Either test_id or alias needs to be provided, with test_id taking precedence over alias.
        """
        test_definition_id = test_id    # as needed by API
        instance_data = locals()
        for key in ["self", "test_id"]:
            instance_data.pop(key)

        if test_definition_id == "" and alias == "":
            raise Exception("test_id needs to be provided for finding the model.")
            #raise Exception("test_id or alias needs to be provided for finding the model.")
        elif test_definition_id != "":
            url = self.url + "/validationtestscode/?format=json"
        else:
            raise Exception("alias is not currently implemented for this feature.")
            #url = self.url + "/validationtestscode/?alias=" + alias + "&format=json"
        headers = {'Content-type': 'application/json'}
        response = requests.post(url, data=json.dumps([instance_data]),
                                 auth=self.auth, headers=headers)
        if str(response) == "<Response [201]>":
            return response.content
        else:
            raise Exception("Error in adding test instance. Response = " + str(response))


    def edit_test_instance(self, test_id="", alias="", repository="", path="", version=""):
        """
        Edit an existing test instance definition in the test library.

        Note: 'alias' is not currently implemented in the API, and the same is kept for future use here.
        TO DO: Either test_id or alias needs to be provided, with test_id taking precedence over alias.
        """
        test_definition_id = test_id    # as needed by API
        instance_data = locals()
        for key in ["self", "test_id"]:
            instance_data.pop(key)

        if test_id == "" and alias == "":
            raise Exception("test_id needs to be provided for finding the model.")
            #raise Exception("test_id or alias needs to be provided for finding the model.")
        elif test_id != "":
            url = self.url + "/validationtestscode/?format=json"
        else:
            raise Exception("alias is not currently implemented for this feature.")
            #url = self.url + "/validationtestscode/?alias=" + alias + "&format=json"
        headers = {'Content-type': 'application/json'}
        response = requests.put(url, data=json.dumps([instance_data]),
                                 auth=self.auth, headers=headers)
        if str(response) == "<Response [202]>":
            return response.content
        else:
            raise Exception("Error in editing test instance. Response = " + str(response.content))

    # TODO
    def get_test(self, test_path="", test_id = "", alias="", instance_id ="", **params):
        """
        Download a test definition from the test library using the 'test_id' or alias,
        or load from a local JSON file specified via 'test_path'. 'test_path' takes priority if mutliple specified.
        'test_id' takes priority over 'alias' when both provided.
        `params` are additional keyword arguments to be passed to the :class:`Test` constructor.
        Returns a :class:`sciunit.Test` instance.
        """
        test_json = self.get_test_definition(test_path=test_path, test_id=test_id, alias=alias)
        test_instances_json = self.get_test_instance(instance_id=instance_id)

        # Import the Test class specified in the definition.
        # This assumes that the module containing the class is installed.
        # In future we could add the ability to (optionally) install
        # Python packages automatically.
        path_parts = test_instances_json["path"].split(".")
        cls_name = path_parts[-1]
        module_name = ".".join(path_parts[:-1])
        test_module = import_module(module_name)
        test_cls = getattr(test_module, cls_name)

        # Load the reference data ("observations")
        observation_data = self._load_reference_data(test_json["data_location"])

        # Transform string representations of quantities, e.g. "-65 mV",
        # into :class:`quantities.Quantity` objects.
        observations = {}
        if type(observation_data.values()[0]) is dict:
            observations = observation_data
        else:
            for key, val in observation_data.items():
                try:
                    observations[key] = int(val)
                except ValueError:
                    try:
                        observations[key] = float(val)
                    except ValueError:
                        quantity_parts = val.split(" ")
                        number = float(quantity_parts[0])
                        units = " ".join(quantity_parts[1:])
                        observations[key] = quantities.Quantity(number, units)

        # Create the :class:`sciunit.Test` instance
        test_instance = test_cls(observations, **params)
        test_instance.id = test_instances_json["id"]  # this is just the path part. Should be a full url
        return test_instance

    def _load_reference_data(self, uri):
        # Load the reference data ("observations"). For now this is assumed
        # to be in JSON format, but we should support other data formats.
        parse_result = urlparse(uri)
        datastore = URI_SCHEME_MAP[parse_result.scheme](auth=self.auth)
        observation_data = datastore.load_data(uri)
        return observation_data

    def get_options(self, param=""):
        """
        Will return the list of valid values (where applicable) for various fields.
        If a parameter is specified then, only values that correspond to it will be returned,
        else values for all fields are returned.
        Note: When specified, only the first parameter is considered; the rest are ignored.
              So the function either returns for all parameters or a single parameter.

        Example Usage:
        data = test_library.get_options()
        or
        data = test_library.get_options("cell_type")
        """
        if param == "":
            param = "all"

        if param in ["cell_type", "test_type", "score_type", "brain_region", "model_type", "data_modalities", "species", "all"]:
            url = self.url + "/authorizedcollabparameterrest/?python_client=true&parameters="+param+"&format=json"
        else:
            raise Exception("Parameter, if specified, has to be one from: cell_type, test_type, score_type, brain_region, model_type, data_modalities, species, all]")
        data = requests.get(url, auth=self.auth).json()
        return ast.literal_eval(json.dumps(data))

    def register_test(self, name="", alias=None, author="", publication="",
                      species="", brain_region="", cell_type="", age="", data_modality="",
                      test_type="", score_type="", protocol="", data_location="", data_type="",
                      version="", repository="", path=""):
        """
        To register a new test on the test catalog.
        You need to specify an instance (version) of this test when creating it.

        Example usage:
        test = test_library.register_test(name="Cell Density Test", alias="CDT-4", author="Shailesh Appukuttan", publication="Halasy et al., 1996",
                            species="Mouse (Mus musculus)", brain_region="Hippocampus", cell_type="Other", age="TBD", data_modality="electron microscopy",
              test_type="network structure", score_type="Other", protocol="To be filled later", data_location="collab://Validation Framework/observations/test_data/cell_density_Halasy_1996.json", data_type="Mean, SD",
              repository="https://github.com/appukuttan-shailesh/morphounit.git", path="morphounit.tests.CellDensityTest", version="1.0")
        """
        values = self.get_options()

        if species not in values["species"]:
            raise Exception("species = '" +species+"' is invalid.\nValue has to be one of these: " + str(values["species"]))
        if brain_region not in values["brain_region"]:
            raise Exception("brain_region = '" +brain_region+"' is invalid.\nValue has to be one of these: " + str(values["brain_region"]))
        if cell_type not in values["cell_type"]:
            raise Exception("cell_type = '" +cell_type+"' is invalid.\nValue has to be one of these: " + str(values["cell_type"]))
        if data_modality not in values["data_modalities"]:
            raise Exception("data_modality = '" +data_modality+"' is invalid.\nValue has to be one of these: " + str(values["data_modality"]))
        if test_type not in values["test_type"]:
            raise Exception("test_type = '" +test_type+"' is invalid.\nValue has to be one of these: " + str(values["test_type"]))
        if score_type not in values["score_type"]:
            raise Exception("score_type = '" +score_type+"' is invalid.\nValue has to be one of these: " + str(values["score_type"]))

        if alias == "":
            alias = None

        test_data = locals()
        test_data.pop("self")
        code_data = {}
        for key in ["version", "repository", "path"]:
            code_data[key] = test_data.pop(key)

        test_list_uri = self.url + "/validationtestdef/?format=json"
        test_json = {
                        "test_data": test_data,
                        "code_data": code_data
                    }

        headers = {'Content-type': 'application/json'}
        response = requests.post(test_list_uri, data=json.dumps(test_json),
                                 auth=self.auth, headers=headers)
        if str(response) == "<Response [201]>":
            return response.json()
        else:
            raise Exception("Error in adding test. Response = " + str(response.json()))

    def edit_test(self, name="", test_id="", alias=None, author="", publication="",
                      species="", brain_region="", cell_type="", age="", data_modality="",
                      test_type="", score_type="", protocol="", data_location="", data_type=""):
        """
        To edit an existing test in the test library.
        test_id must be provided. Any of the other parameters maybe updated.
        Note: this does not allow editing details of instances. Will be implemented later, if required.

        Example usage:
        test = test_library.register_test(name="Cell Density Test", alias="CDT-4", author="Shailesh Appukuttan", publication="Halasy et al., 1996",
                            species="Mouse (Mus musculus)", brain_region="Hippocampus", cell_type="Other", age="TBD", data_modality="electron microscopy",
              test_type="network structure", score_type="Other", protocol="To be filled later", data_location="collab://Validation Framework/observations/test_data/cell_density_Halasy_1996.json", data_type="Mean, SD",
              repository="https://github.com/appukuttan-shailesh/morphounit.git", path="morphounit.tests.CellDensityTest", version="1.0")
        """
        values = self.get_options()

        if species not in values["species"]:
            raise Exception("species = '" +species+"' is invalid.\nValue has to be one of these: " + str(values["species"]))
        if brain_region not in values["brain_region"]:
            raise Exception("brain_region = '" +brain_region+"' is invalid.\nValue has to be one of these: " + str(values["brain_region"]))
        if cell_type not in values["cell_type"]:
            raise Exception("cell_type = '" +cell_type+"' is invalid.\nValue has to be one of these: " + str(values["cell_type"]))
        if data_modality not in values["data_modalities"]:
            raise Exception("data_modality = '" +data_modality+"' is invalid.\nValue has to be one of these: " + str(values["data_modality"]))
        if test_type not in values["test_type"]:
            raise Exception("test_type = '" +test_type+"' is invalid.\nValue has to be one of these: " + str(values["test_type"]))
        if score_type not in values["score_type"]:
            raise Exception("score_type = '" +score_type+"' is invalid.\nValue has to be one of these: " + str(values["score_type"]))

        if alias == "":
            alias = None

        id = test_id   # as needed by API
        test_data = locals()
        for key in ["self", "test_id"]:
            test_data.pop(key)

        test_list_uri = self.url + "/validationtestdef/?format=json"
        test_json = test_data   # retaining similar structure as other methods

        headers = {'Content-type': 'application/json'}
        response = requests.put(test_list_uri, data=json.dumps(test_json),
                                auth=self.auth, headers=headers)
        if str(response) == "<Response [202]>":
            return response.json()
        else:
            raise Exception("Error in editing test. Response = " + str(response.json()))

    # TODO
    def list_validation_tests(self, **filters):
        """
        docstring needed
        """
        url = self.url + "/search?{}".format(urlencode(filters))
        print(url)
        response = requests.get(url)
        return response.json()

    def register_result(self, test_result="", data_store=None):
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
            if not data_store.authorized:
                data_store.authorize(self.auth)  # relies on data store using HBP authorization
                                                 # if this is not the case, need to authenticate/authorize
                                                 # the data store before passing to `register()`
            if data_store.collab_id is None:
                data_store.collab_id = project
            results_storage = data_store.upload_data(test_result.related_data["figures"])
        else:
            results_storage = ""

        # check that the model is registered with the model registry.
        # If not, offer to register it?
        result_uri = self.url + "/validationmodelresultrest2/?format=json"
        result_json = {
                        "model_version_id": test_result.model.id,
                        "test_code_id": test_result.related_data["test_instance_id"],
                        "results_storage": "Dummy",
                        "score": test_result.score,
                        "passed": None,
                        "timestamp": "2049-05-18T18:47:14Z",
                        "platform": "abcde",    #self.get_platform(),
                        "project": "azerty",
                        "normalized_score": test_result.score
                      }

                #"model_id": test_result.model.id,  # uri? overload 'model.name' attribute?
                #"version": test_result.model.version,

        print(result_json)
        headers = {'Content-type': 'application/json'}
        response = requests.post(result_uri, data=json.dumps([result_json]),
                                 auth=self.auth, headers=headers)
        print(response.content)

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

    # TODO
    def list_validation_results(self, **filters):
        """
        docstring needed
        """
        return 0


class ModelCatalog(BaseClient):
    """
    Client for the HBP Model Repository. Can do the following:
    > Retrieve a specific model description from the repository
    > Retrieve a list of model descriptions from the repository
    > Return list of valid values (where applicable) for model catalog fields
    > Add a new model description to the repository
    > Add a new model instance for an existing model in the repository
    > Add a new image for an existing model in the repository

    Usage
    -----
    model_catalog = ModelCatalog()
    """

    def get_model(self, model_id="", alias="", instances=True, images=True):
        """
        Retrieve a model description by its model_id or alias.
        Either model_id or alias needs to be provided, with model_id taking precedence over alias.
        Will return the entire model description as a JSON object.

        (Optional) Set 'instances' to False if you wish to omit the details of the model instances.
        (Optional) Set 'images' to False if you wish to omit the details of the model images.

        Example usage:
        model = model_catalog.get_model(model_id="8c7cb9f6-e380-452c-9e98-e77254b088c5")
        or
        model = model_catalog.get_model(alias="B1")
        """
        if model_id == "" and alias == "":
            raise Exception("Model ID or alias needs to be provided for finding a model.")
        elif model_id != "":
            model_uri = self.url + "/scientificmodel/?id=" + model_id + "&format=json"
        else:
            model_uri = self.url + "/scientificmodel/?alias=" + alias + "&format=json"

        model = requests.get(model_uri, auth=self.auth)
        if str(model) != "<Response [200]>":
            raise Exception("Error in retrieving model. Possibly invalid model_id or alias. Response = " + str(model))
        model = model.json()
        if instances == False:
            model["models"][0].pop("instances")
        if images == False:
            model["models"][0].pop("images")
        return model["models"][0]

    def list_models(self, **filters):
        """
        List models satisfying all specified filters

        Example usage:
        models = model_catalog.list_models()
        models = model_catalog.list_models(app_id="39968")
        models = model_catalog.list_models(cell_type="Pyramidal Cell",
                                           brain_region="Hippocampus")
        """
        params = locals()["filters"]
        model_list_uri = self.url + "/scientificmodel/?"+urlencode(params)+"&format=json"
        models = requests.get(model_list_uri, auth=self.auth).json()
        return models["models"]

    def get_options(self, param=""):
        """
        Will return the list of valid values (where applicable) for various fields.
        If a parameter is specified then, only values that correspond to it will be returned,
        else values for all fields are returned.
        Note: When specified, only the first parameter is considered; the rest are ignored.
              So the function either returns for all parameters or a single parameter.

        Example Usage:
        data = model_catalog.get_options()
        or
        data = model_catalog.get_options("cell_type")
        """
        if param == "":
            param = "all"

        if param in ["cell_type", "test_type", "score_type", "brain_region", "model_type", "data_modalities", "species", "all"]:
            url = self.url + "/authorizedcollabparameterrest/?python_client=true&parameters="+param+"&format=json"
        else:
            raise Exception("Parameter, if specified, has to be one from: cell_type, test_type, score_type, brain_region, model_type, data_modalities, species, all]")
        data = requests.get(url, auth=self.auth).json()
        return ast.literal_eval(json.dumps(data))

    def register_model(self, app_id="", name="", alias=None, author="", private="False",
                       cell_type="", model_type="", brain_region="", species="", description="",
                       instances=[], images=[]):
        """
        To register a new model on the model catalog

        Example usage:
        (without specification of instances and images)
        model = model_catalog.register_model(app_id="39968", name="Test Model - B2",
                        alias="Model-B2", author="Shailesh Appukuttan",
                        private="False", cell_type="Granule Cell", model_type="Single Cell",
                        brain_region="Basal Ganglia", species="Mouse (Mus musculus)",
                        description="This is a test entry")
        or
        (with specification of instances and images)
        model = model_catalog.register_model(app_id="39968", name="Client Test - C2",
                        alias="C2", author="Shailesh Appukuttan",
                        private="False", cell_type="Granule Cell", model_type="Single Cell",
                        brain_region="Basal Ganglia", species="Mouse (Mus musculus)",
                        description="This is a test entry! Please ignore.",
                        instances=[{"source":"https://www.abcde.com",
                                    "version":"1.0", "parameters":""},
                                   {"source":"https://www.12345.com",
                                    "version":"2.0", "parameters":""}],
                        images=[{"url":"http://www.neuron.yale.edu/neuron/sites/default/themes/xchameleon/logo.png",
                                 "caption":"NEURON Logo"},
                                {"url":"https://collab.humanbrainproject.eu/assets/hbp_diamond_120.png",
                                 "caption":"HBP Logo"}])
        """
        values = self.get_options()

        if cell_type not in values["cell_type"]:
            raise Exception("cell_type = '" +cell_type+"' is invalid.\nValue has to be one of these: " + str(values["cell_type"]))
        if model_type not in values["model_type"]:
            raise Exception("model_type = '" +model_type+"' is invalid.\nValue has to be one of these: " + str(values["model_type"]))
        if brain_region not in values["brain_region"]:
            raise Exception("brain_region = '" +brain_region+"' is invalid.\nValue has to be one of these: " + str(values["brain_region"]))
        if species not in values["species"]:
            raise Exception("species = '" +species+"' is invalid.\nValue has to be one of these: " + str(values["species"]))

        if private not in ["True", "False"]:
            raise Exception("Model's 'private' attribute should be specified as True / False. Default value is False.")
        if alias == "":
            alias = None

        model_data = locals()
        for key in ["self", "app_id", "instances", "images"]:
            model_data.pop(key)

        model_list_uri = self.url + "/scientificmodel/?app_id="+app_id+"&format=json"
        model_json = {
                        "model": model_data,
                        "model_instance":instances,
                        "model_image":images
                     }
        headers = {'Content-type': 'application/json'}
        response = requests.post(model_list_uri, data=json.dumps(model_json),
                                 auth=self.auth, headers=headers)
        if str(response) == "<Response [201]>":
            return response.json()
        else:
            raise Exception("Error in adding model. Response = " + str(response.json()))

    def edit_model(self, app_id="", name="", model_id="", alias=None, author="", private="False",
                       cell_type="", model_type="", brain_region="", species="", description=""):
        """
        To edit an existing model description on the model catalog.
        model_id must be provided. Any of the other parameters maybe updated.
        Note: this does not allow editing details of instances and images. Will be implemented later, if required.

        Example usage:
        model = model_catalog.edit_model(app_id="39968", name="Test Model - B2",
                        model_id="8c7cb9f6-e380-452c-9e98-e77254b088c5",
                        alias="Model-B2", author="Shailesh Appukuttan",
                        private="False", cell_type="Granule Cell", model_type="Single Cell",
                        brain_region="Basal Ganglia", species="Mouse (Mus musculus)",
                        description="This is a test entry")
        """
        values = self.get_options()

        if cell_type not in values["cell_type"]:
            raise Exception("cell_type = '" +cell_type+"' is invalid.\nValue has to be one of these: " + str(values["cell_type"]))
        if model_type not in values["model_type"]:
            raise Exception("model_type = '" +model_type+"' is invalid.\nValue has to be one of these: " + str(values["model_type"]))
        if brain_region not in values["brain_region"]:
            raise Exception("brain_region = '" +brain_region+"' is invalid.\nValue has to be one of these: " + str(values["brain_region"]))
        if species not in values["species"]:
            raise Exception("species = '" +species+"' is invalid.\nValue has to be one of these: " + str(values["species"]))

        if private not in ["True", "False"]:
            raise Exception("Model's 'private' attribute should be specified as True / False. Default value is False.")
        if alias == "":
            alias = None

        id = model_id   # as needed by API
        model_data = locals()
        for key in ["self", "app_id", "model_id"]:
            model_data.pop(key)

        model_list_uri = self.url + "/scientificmodel/?app_id="+app_id+"&format=json"
        model_json = {
                        "models": [model_data]
                     }
        headers = {'Content-type': 'application/json'}
        response = requests.put(model_list_uri, data=json.dumps(model_json),
                                 auth=self.auth, headers=headers)
        if str(response) == "<Response [202]>":
            return response.json()
        else:
            raise Exception("Error in updating model. Response = " + str(response.json()))

    def add_model_instance(self, model_id="", alias="", source="", version="", parameters=""):
        """
        To add a single new instance of an existing model in the model catalog.
        'model_id' needs to be specified as input parameter.
        Returns the UUID of the instance added to the model catalog.

        Example usage:
        instance_id = model_catalog.add_model_instance(model_id="196b89a3-e672-4b96-8739-748ba3850254",
                                                  source="https://www.abcde.com",
                                                  version="1.0",
                                                  parameters="")

        Note: 'alias' is not currently implemented in the API, and the same is kept for future use here.
        TO DO: Either model_id or alias needs to be provided, with model_id taking precedence over alias.
        """
        instance_data = locals()
        instance_data.pop("self")

        if model_id == "" and alias == "":
            raise Exception("Model ID needs to be provided for finding the model.")
            #raise Exception("Model ID or alias needs to be provided for finding the model.")
        elif model_id != "":
            url = self.url + "/scientificmodelinstance/?format=json"
        else:
            raise Exception("alias is not currently implemented for this feature.")
            #url = self.url + "/scientificmodelinstance/?alias=" + alias + "&format=json"
        headers = {'Content-type': 'application/json'}
        response = requests.post(url, data=json.dumps([instance_data]),
                                 auth=self.auth, headers=headers)
        if str(response) == "<Response [201]>":
            return response.json()
        else:
            raise Exception("Error in adding model instance. Response = " + str(response.json()))

    def get_model_instance(self, instance_path="", model_id="", alias=""):
        """
        Download a model instance definition from the model catalog
        in the following ways (in order of priority):
        1) load from a local JSON file specified via 'instance_path'
        2) specify 'instance_id' correspoding to test instance in test library
        3) specify "model_id" and "version"
        4) specify "alias" (of the model) and "version"
        Returns a dict containing information about the model instance.
        """
        if instance_path == "" and model_id == "" and alias == "":
            raise Exception("instance_path or model_id or alias needs to be provided for finding model instances.")
        if instance_path and os.path.isfile(instance_path):
            # instance_path is a local path
            with open(instance_path) as fp:
                model_instances_json = json.load(fp)
        else:
            if model_id:
                instance_uri = self.url + "/scientificmodelinstance/?model_id=" + model_id + "&format=json"
            else:
                instance_uri = self.url + "/scientificmodelinstance/?model_alias=" + alias + "&format=json"
            model_instances_json = requests.get(instance_uri, auth=self.auth)
        print model_instances_json.content
        if str(model_instances_json) != "<Response [200]>":
            raise Exception("Error in retrieving model instances. Response = " + str(model_instances_json))
        model_instances_json = model_instances_json.json()
        return model_instances_json#["instances"]

    def list_model_instances(self, instance_path="", model_id="", alias=""):
        """
        Download a list of model instance definitions belonging to a specified
        model from the model catalog in the following ways (in order of priority):
        1) load from a local JSON file specified via 'instance_path'
        2) specify "model_id"
        3) specify "alias" (of the model)
        Returns a list of dicts containing information about the model instances.
        """
        if instance_path == "" and model_id == "" and alias == "":
            raise Exception("instance_path or model_id or alias needs to be provided for finding model instances.")
        if instance_path and os.path.isfile(instance_path):
            # instance_path is a local path
            with open(instance_path) as fp:
                model_instances_json = json.load(fp)
        else:
            if model_id:
                instance_uri = self.url + "/scientificmodelinstance/?model_id=" + model_id + "&format=json"
            else:
                instance_uri = self.url + "/scientificmodelinstance/?model_alias=" + alias + "&format=json"
            model_instances_json = requests.get(instance_uri, auth=self.auth)
        print "++++++",model_instances_json.content
        if str(model_instances_json) != "<Response [200]>":
            raise Exception("Error in retrieving model instances. Response = " + str(model_instances_json))
        model_instances_json = model_instances_json.json()
        return model_instances_json#["instances"]

    def add_model_image(self, model_id="", alias="", url="", caption=""):
        """
        To add a new image to an existing model in the model catalog.
        'model_id' needs to be specified as input parameter.
        Returns the UUID of the image added in the model catalog.

        Example usage:
        image_id = model_catalog.add_model_image(model_id="196b89a3-e672-4b96-8739-748ba3850254",
                                               url="http://www.neuron.yale.edu/neuron/sites/default/themes/xchameleon/logo.png",
                                               caption="NEURON Logo")

        Note: 'alias' is not currently implemented in the API, and the same is kept for future use here.
        TO DO: Either model_id or alias needs to be provided, with uri taking precedence over alias.
        """
        image_data = locals()
        image_data.pop("self")
        image_data.pop("alias")

        if model_id == "" and alias == "":
            raise Exception("Model ID needs to be provided for finding the model.")
            #raise Exception("Model ID or alias needs to be provided for finding the model.")
        elif model_id != "":
            url = self.url + "/scientificmodelimage/?format=json"
        else:
            raise Exception("alias is not currently implemented for this feature.")
            #url = self.url + "/scientificmodelimage/?alias=" + alias + "&format=json"
        headers = {'Content-type': 'application/json'}
        response = requests.post(url, data=json.dumps([image_data]),
                                 auth=self.auth, headers=headers)
        if str(response) == "<Response [201]>":
            return response.json()
        else:
            raise Exception("Error in adding image. Response = " + str(response.json()))

    def list_model_images(self, model_id="", alias=""):
        """
        Download a list of images associated with a model
        from the model catalog in the following ways (in order of priority):
        1) specify "model_id"
        2) specify "alias" (of the model)
        Returns a list of dicts containing information about the model images.
        """
        if model_id == "" and alias == "":
            raise Exception("model_id or alias needs to be provided for finding model images.")
        elif model_id:
            instance_uri = self.url + "/scientificmodelimage/?model_id=" + model_id + "&format=json"
        else:
            instance_uri = self.url + "/scientificmodelimage/?model_alias=" + alias + "&format=json"
        model_images_json = requests.get(instance_uri, auth=self.auth)
        #print model_images_json.content
        if str(model_images_json) != "<Response [200]>":
            raise Exception("Error in retrieving model instances. Response = " + str(model_images_json))
        model_images_json = model_images_json.json()
        return model_images_json#["images"]

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
