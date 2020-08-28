"""
A Python package for working with the Human Brain Project Model Validation Framework.

Andrew Davison and Shailesh Appukuttan, CNRS, 2017-2020

License: BSD 3-clause, see LICENSE.txt

"""

import getpass
import json
import os
import platform
import re
import socket
from importlib import import_module
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse, urljoin
from urllib.request import urlopen

import requests
from requests.auth import AuthBase

import sciunit
import simplejson
import collections

from .datastores import URI_SCHEME_MAP

# For BPO loader
import sys
from neuron import h

# check if running within Jupyter notebook inside Collab v2
try:
    from clb_nb_utils import oauth
    have_collab_token_handler = True
except ImportError:
    have_collab_token_handler = False

TOKENFILE = os.path.expanduser("~/.hbptoken")


class ResponseError(Exception):
    pass


def handle_response_error(message, response):
    try:
        structured_error_message = response.json()
    except simplejson.errors.JSONDecodeError:
        structured_error_message = None
    if structured_error_message:
        response_text = str(structured_error_message)  # temporary, to be improved
    else:
        response_text = response.text
    full_message = "{}. Response = {}".format(message, response_text)
    raise ResponseError(full_message)


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
    Base class that handles HBP authentication
    """
    # Note: Could possibly simplify the code later

    __test__ = False

    def __init__(self, username=None,
                 password=None,
                 environment="production",
                 token=None):
        self.username = username
        self.verify = True
        self.environment = environment
        self.token = token
        if environment == "production":
            self.url = "https://validation-v2.brainsimulation.eu"
            self.client_id = "8a6b7458-1044-4ebd-9b7e-f8fd3469069c" # Prod ID
        elif environment == "integration":
            self.url = "https://validation-staging.brainsimulation.eu"
            self.client_id = "8a6b7458-1044-4ebd-9b7e-f8fd3469069c"
        elif environment == "dev":
            self.url = "https://validation-dev.brainsimulation.eu"
            self.client_id = "90c719e0-29ce-43a2-9c53-15cb314c2d0b" # Dev ID
        else:
            if os.path.isfile('config.json') and os.access('config.json', os.R_OK):
                with open('config.json') as config_file:
                    config = json.load(config_file)
                    if environment in config:
                        if "url" in config[environment] and "client_id" in config[environment]:
                            self.url = config[environment]["url"]
                            self.client_id = config[environment]["client_id"]
                            self.verify = config[environment].get("verify_ssl", True)
                        else:
                            raise KeyError("Cannot load environment info: config.json does not contain sufficient info for environment = {}".format(environment))
                    else:
                        raise KeyError("Cannot load environment info: config.json does not contain environment = {}".format(environment))
            else:
                raise IOError("Cannot load environment info: config.json not found in the current directory.")
        if self.token:
            pass
        elif password is None:
            self.token = None
            if have_collab_token_handler:
                    # if are we running in a Jupyter notebook within the Collaboratory
                    # the token is already available
                    self.token = oauth.get_token()
            elif os.path.exists(TOKENFILE):
                # check for a stored token
                with open(TOKENFILE) as fp:
                    # self.token = json.load(fp).get(username, None)["access_token"]
                    data = json.load(fp).get(username, None)
                    if data and "access_token" in data:
                        self.token = data["access_token"]
                        if not self._check_token_valid():
                            print("HBP authentication token is invalid or has expired. Will need to re-authenticate.")
                            self.token = None
                    else:
                        print("HBP authentication token file not having required JSON data.")
            else:
                print("HBP authentication token file not found locally.")

            if self.token is None:
                if not username:
                    print("\n==============================================")
                    print("Please enter your HBP username.")
                    username = input('HBP Username: ')

                password = os.environ.get('HBP_PASS')
                if password is not None:
                    try:
                        self._hbp_auth(username, password)
                    except Exception:
                        print("Authentication Failure. Possibly incorrect HBP password saved in environment variable 'HBP_PASS'.")
                if not hasattr(self, 'config'):
                    try:
                        # prompt for password
                        print("Please enter your HBP password: ")
                        password = getpass.getpass()
                        self._hbp_auth(username, password)
                    except Exception:
                        print("Authentication Failure! Password entered is possibly incorrect.")
                        raise
                with open(TOKENFILE, "w") as fp:
                    json.dump({username: self.config["token"]}, fp)
                os.chmod(TOKENFILE, 0o600)
        else:
            try:
                self._hbp_auth(username, password)
            except Exception:
                print("Authentication Failure! Password entered is possibly incorrect.")
                raise
            with open(TOKENFILE, "w") as fp:
                json.dump({username: self.config["token"]}, fp)
            os.chmod(TOKENFILE, 0o600)
        self.auth = HBPAuth(self.token)

    def _check_token_valid(self):
        url = "https://drive.ebrains.eu/api2/auth/ping/"
        data = requests.get(url, auth=HBPAuth(self.token), verify=self.verify)
        if data.status_code == 200:
            return True
        else:
            return False

    # def exists_in_collab_else_create(self, project_id):
    #     #  TODO: needs to be updated for Collab v2
    #     """
    #     Checks with the hbp-collab-service if the Model Catalog / Validation Framework app
    #     exists inside the current collab (if run inside the Collaboratory), or Collab ID
    #     specified by the user (when run externally).
    #     """
    #     try:
    #         url = "https://services.humanbrainproject.eu/collab/v0/collab/"+str(project_id)+"/nav/all/"
    #         response = requests.get(url, auth=HBPAuth(self.token), verify=self.verify)
    #     except ValueError:
    #         print("Error contacting hbp-collab-service for Collab info. Possibly invalid Collab ID: {}".format(project_id))

    #     for app_item in response.json():
    #         if app_item["app_id"] == str(self.app_id):
    #             app_nav_id = app_item["id"]
    #             print ("Using existing {} app in this Collab. App nav ID: {}".format(self.app_name,app_nav_id))
    #             break
    #     else:
    #         url = "https://services.humanbrainproject.eu/collab/v0/collab/"+str(project_id)+"/nav/root/"
    #         collab_root = requests.get(url, auth=HBPAuth(self.token), verify=self.verify).json()["id"]
    #         import uuid
    #         app_info = {"app_id": self.app_id,
    #                     "context": str(uuid.uuid4()),
    #                     "name": self.app_name,
    #                     "order_index": "-1",
    #                     "parent": collab_root,
    #                     "type": "IT"}
    #         url = "https://services.humanbrainproject.eu/collab/v0/collab/"+str(project_id)+"/nav/"
    #         headers = {'Content-type': 'application/json'}
    #         response = requests.post(url, data=json.dumps(app_info),
    #                                  auth=HBPAuth(self.token), headers=headers,
    #                                  verify=self.verify)
    #         app_nav_id = response.json()["id"]
    #         print ("New {} app created in this Collab. App nav ID: {}".format(self.app_name,app_nav_id))
    #     return app_nav_id

    # def _configure_app_collab(self, config_data):
    #     #  TODO: needs to be updated for Collab v2
    #     """
    #     Used to configure the apps inside a Collab. Example `config_data`:
    #         {
    #            "config":{
    #               "app_id":68489,
    #               "app_type":"model_catalog",
    #               "brain_region":"",
    #               "cell_type":"",
    #               "project_id":8123,
    #               "recording_modality":"",
    #               "model_scope":"",
    #               "abstraction_level":"",
    #               "organization":"",
    #               "species":"",
    #               "test_type":""
    #            },
    #            "only_if_new":False,
    #            "url":"https://validation-v1.brainsimulation.eu/parametersconfiguration-model-catalog/parametersconfigurationrest/"
    #         }
    #     """
    #     if not config_data["config"]["project_id"]:
    #         raise ValueError("`project_id` cannot be empty!")
    #     if not config_data["config"]["app_id"]:
    #         raise ValueError("`app_id` cannot be empty!")
    #     # check if the app has previously been configured: decide POST or PUT
    #     response = requests.get(config_data["url"]+"?app_id="+str(config_data["config"]["app_id"]), auth=self.auth, verify=self.verify)
    #     headers = {'Content-type': 'application/json'}
    #     config_data["config"]["id"] = config_data["config"]["app_id"]
    #     app_id = config_data["config"].pop("app_id")
    #     if not response.json()["param"]:
    #         response = requests.post(config_data["url"], data=json.dumps(config_data["config"]),
    #                                  auth=self.auth, headers=headers,
    #                                  verify=self.verify)
    #         if response.status_code == 201:
    #             print("New app has beeen created and sucessfully configured!")
    #         else:
    #             print("Error! App could not be configured. Response = " + str(response.content))
    #     else:
    #         if not config_data["only_if_new"]:
    #             response = requests.put(config_data["url"], data=json.dumps(config_data["config"]),
    #                                     auth=self.auth, headers=headers,
    #                                     verify=self.verify)
    #             if response.status_code == 202:
    #                 print("Existing app has beeen sucessfully reconfigured!")
    #             else:
    #                 print("Error! App could not be reconfigured. Response = " + str(response.content))

    def _hbp_auth(self, username, password):
        """
        HBP authentication
        """
        redirect_uri = self.url + '/auth'
        session = requests.Session()
        # log-in page of model validation service
        r_login = session.get(self.url + "/login", allow_redirects=False)
        if r_login.status_code != 302:
            raise Exception(
                "Something went wrong. Status code {} from login, expected 302"
                .format(r_login.status_code))
        # redirects to EBRAINS IAM log-in page
        iam_auth_url = r_login.headers.get('location')
        r_iam1 = session.get(iam_auth_url, allow_redirects=False)
        if r_iam1.status_code != 200:
            raise Exception(
                "Something went wrong loading EBRAINS log-in page. Status code {}"
                .format(r_iam1.status_code))
        # fill-in and submit form
        match = re.search(r'action=\"(?P<url>[^\"]+)\"', r_iam1.text)
        if not match:
            raise Exception("Received an unexpected page")
        iam_authenticate_url = match['url'].replace("&amp;", "&")
        r_iam2 = session.post(
            iam_authenticate_url,
            data={"username": username, "password": password},
            headers={"Referer": iam_auth_url, "Host": "iam.ebrains.eu", "Origin": "https://iam.ebrains.eu"},
            allow_redirects=False
        )
        if r_iam2.status_code != 302:
            raise Exception(
                "Something went wrong. Status code {} from authenticate, expected 302"
                .format(r_iam2.status_code))
        # redirects back to model validation service
        r_val = session.get(r_iam2.headers['Location'])
        if r_val.status_code != 200:
            raise Exception(
                "Something went wrong. Status code {} from final authentication step"
                .format(r_val.status_code))
        config = r_val.json()
        self.token = config['token']['access_token']
        self.config = config

    @classmethod
    def from_existing(cls, client):
        """Used to easily create a TestLibrary if you already have a ModelCatalog, or vice versa"""
        obj = cls.__new__(cls)
        for attrname in ("username", "url", "client_id", "token", "verify", "auth", "environment"):
            setattr(obj, attrname, getattr(client, attrname))
        obj._set_app_info()
        return obj

    def _get_attribute_options(self, param, valid_params):
        if param in ("", "all"):
            url = self.url + "/vocab/"
        elif param in valid_params:
            url = self.url + "/vocab/" + param.replace("_", "-") + "/"
        else:
            raise Exception("Specified attribute '{}' is invalid. Valid attributes: {}".format(param, valid_params))
        attribute_options = requests.get(url, auth=self.auth, verify=self.verify).json()
        return attribute_options


class TestLibrary(BaseClient):
    """Client for the HBP Validation Test library.

    The TestLibrary client manages all actions pertaining to tests and results.
    The following actions can be performed:

    ====================================   ====================================
    Action                                 Method
    ====================================   ====================================
    Get test definition                    :meth:`get_test_definition`
    Get test as Python (sciunit) class     :meth:`get_validation_test`
    List test definitions                  :meth:`list_tests`
    Add new test definition                :meth:`add_test`
    Edit test definition                   :meth:`edit_test`
    Get test instances                     :meth:`get_test_instance`
    List test instances                    :meth:`list_test_instances`
    Add new test instance                  :meth:`add_test_instance`
    Edit test instance                     :meth:`edit_test_instance`
    Get valid attribute values             :meth:`get_attribute_options`
    Get test result                        :meth:`get_result`
    List test results                      :meth:`list_results`
    Register test result                   :meth:`register_result`
    ====================================   ====================================

    Parameters
    ----------
    username : string
        Your HBP Collaboratory username. Not needed in Jupyter notebooks within the HBP Collaboratory.
    password : string, optional
        Your HBP Collaboratory password; advisable to not enter as plaintext.
        If left empty, you would be prompted for password at run time (safer).
        Not needed in Jupyter notebooks within the HBP Collaboratory.
    environment : string, optional
        Used to indicate whether being used for development/testing purposes.
        Set as `production` as default for using the production system,
        which is appropriate for most users. When set to `dev`, it uses the
        `development` system. Other environments, if required, should be defined
        inside a json file named `config.json` in the working directory. Example:

        .. code-block:: JSON

            {
                "prod": {
                    "url": "https://validation-v1.brainsimulation.eu",
                    "client_id": "3ae21f28-0302-4d28-8581-15853ad6107d"
                },
                "dev_test": {
                    "url": "https://localhost:8000",
                    "client_id": "90c719e0-29ce-43a2-9c53-15cb314c2d0b",
                    "verify_ssl": false
                }
            }

    token : string, optional
        You may directly input a valid authenticated token from Collaboratory v1 or v2.
        Note: you should use the `access_token` and NOT `refresh_token`.

    Examples
    --------
    Instantiate an instance of the TestLibrary class

    >>> test_library = TestLibrary(username="<<hbp_username>>", password="<<hbp_password>>")
    >>> test_library = TestLibrary(token="<<token>>")
    """

    __test__ = False

    def __init__(self, username=None, password=None, environment="production", token=None):
        super(TestLibrary, self).__init__(username, password, environment, token)
        self._set_app_info()

    def _set_app_info(self):
        #  TODO: check if needs to be updated for Collab v2
        if self.environment == "production":
            self.app_id = 360
            self.app_name = "Validation Framework"
        elif self.environment == "dev":
            self.app_id = 349
            self.app_name = "Validation Framework (dev)"
        elif self.environment == "integration":
            self.app_id = 432
            self.app_name = "Model Validation app (staging)"

    # def set_app_config(self, project_id="", only_if_new=False, recording_modality="", test_type="", species="", brain_region="", cell_type="", model_scope="", abstraction_level="", organization=""):
    #     #  TODO: needs to be updated for Collab v2
    #     inputArgs = locals()
    #     params = {}
    #     params["url"] = self.url + "/parametersconfiguration-validation-app/parametersconfigurationrest/"
    #     params["only_if_new"] = only_if_new
    #     params["config"] = inputArgs
    #     params["config"].pop("self")
    #     params["config"].pop("only_if_new")
    #     params["config"]["app_type"] = "validation_app"
    #     self._configure_app_collab(params)

    def get_test_definition(self, test_path="", test_id = "", alias=""):
        """Retrieve a specific test definition.

        A specific test definition can be retrieved from the test library
        in the following ways (in order of priority):

        1. load from a local JSON file specified via `test_path`
        2. specify the `test_id`
        3. specify the `alias` (of the test)

        Parameters
        ----------
        test_path : string
            Location of local JSON file with test definition.
        test_id : UUID
            System generated unique identifier associated with test definition.
        alias : string
            User-assigned unique identifier associated with test definition.

        Note
        ----
        Also see: :meth:`get_validation_test`

        Returns
        -------
        dict
            Information about the test.

        Examples
        --------
        >>> test = test_library.get_test_definition("/home/shailesh/Work/dummy_test.json")
        >>> test = test_library.get_test_definition(test_id="7b63f87b-d709-4194-bae1-15329daf3dec")
        >>> test = test_library.get_test_definition(alias="CDT-6")
        """

        if test_path == "" and test_id == "" and alias == "":
            raise Exception("test_path or test_id or alias needs to be provided for finding a test.")
        if test_path:
            if os.path.isfile(test_path):
                # test_path is a local path
                with open(test_path) as fp:
                    test_json = json.load(fp)
            else:
                raise Exception("Error in local file path specified by test_path.")
        else:
            if test_id:
                url = self.url + "/tests/" + test_id
            else:
                url = self.url + "/tests/" + quote(alias)
            test_json = requests.get(url, auth=self.auth, verify=self.verify)

        if test_json.status_code != 200:
            handle_response_error("Error in retrieving test", test_json)
        return test_json.json()

    def get_validation_test(self, test_path="", instance_path="", instance_id ="", test_id = "", alias="", version="", **params):
        """Retrieve a specific test instance as a Python class (sciunit.Test instance).

        A specific test definition can be specified
        in the following ways (in order of priority):

        1. load from a local JSON file specified via `test_path` and `instance_path`
        2. specify `instance_id` corresponding to test instance in test library
        3. specify `test_id` and `version`
        4. specify `alias` (of the test) and `version`
        Note: for (3) and (4) above, if `version` is not specified,
              then the latest test version is retrieved

        Parameters
        ----------
        test_path : string
            Location of local JSON file with test definition.
        instance_path : string
            Location of local JSON file with test instance metadata.
        instance_id : UUID
            System generated unique identifier associated with test instance.
        test_id : UUID
            System generated unique identifier associated with test definition.
        alias : string
            User-assigned unique identifier associated with test definition.
        version : string
            User-assigned identifier (unique for each test) associated with test instance.
        **params :
            Additional keyword arguments to be passed to the Test constructor.

        Note
        ----
        To confirm the priority of parameters for specifying tests and instances,
        see :meth:`get_test_definition` and :meth:`get_test_instance`

        Returns
        -------
        sciunit.Test
            Returns a :class:`sciunit.Test` instance.

        Examples
        --------
        >>> test = test_library.get_validation_test(alias="CDT-6", instance_id="36a1960e-3e1f-4c3c-a3b6-d94e6754da1b")
        """

        if test_path == "" and instance_id == "" and test_id == "" and alias == "":
            raise Exception("One of the following needs to be provided for finding the required test:\n"
                            "test_path, instance_id, test_id or alias")
        else:
            if instance_id:
                # `instance_id` is sufficient for identifying both test and instance
                test_instance_json = self.get_test_instance(instance_path=instance_path, instance_id=instance_id) # instance_path added just to maintain order of priority
                test_id = test_instance_json["test_id"]
                test_json = self.get_test_definition(test_path=test_path, test_id=test_id) # test_path added just to maintain order of priority
            else:
                test_json = self.get_test_definition(test_path=test_path, test_id=test_id, alias=alias)
                test_id = test_json["id"] # in case test_id was not input for specifying test
                test_instance_json = self.get_test_instance(instance_path=instance_path, instance_id=instance_id, test_id=test_id, version=version)

        # Import the Test class specified in the definition.
        # This assumes that the module containing the class is installed.
        # In future we could add the ability to (optionally) install
        # Python packages automatically.
        path_parts = test_instance_json["path"].split(".")
        cls_name = path_parts[-1]
        module_name = ".".join(path_parts[:-1])
        test_module = import_module(module_name)
        test_cls = getattr(test_module, cls_name)

        # Load the reference data ("observations")
        observation_data = self._load_reference_data(test_json["data_location"])

        # Create the :class:`sciunit.Test` instance
        test_instance = test_cls(observation=observation_data, **params)
        test_instance.uuid = test_instance_json["id"]
        return test_instance

    def list_tests(self, size=1000000, from_index=0, **filters):
        """Retrieve a list of test definitions satisfying specified filters.

        The filters may specify one or more attributes that belong
        to a test definition. The following test attributes can be specified:

        * name
        * alias
        * author
        * species
        * age
        * brain_region
        * cell_type
        * recording_modality
        * test_type
        * score_type
        * model_scope
        * abstraction_level
        * data_type
        * publication

        Parameters
        ----------
        size : positive integer
            Max number of tests to be returned; default is set to 1000000.
        from_index : positive integer
            Index of first test to be returned; default is set to 0.
        **filters : variable length keyword arguments
            To be used to filter test definitions from the test library.

        Returns
        -------
        list
            List of model descriptions satisfying specified filters.

        Examples
        --------
        >>> tests = test_library.list_tests()
        >>> tests = test_library.list_tests(test_type="single cell activity")
        >>> tests = test_library.list_tests(test_type="single cell activity", cell_type="Pyramidal Cell")
        """

        # TODO: verify valid filters for v2 APIs
        valid_filters = ["name", "alias", "author", "species", "age", "brain_region", "cell_type", "recording_modality", "test_type", "score_type", "model_scope", "abstraction_level", "data_type", "publication"]
        params = locals()["filters"]
        for filter in params:
            if filter not in valid_filters:
                raise ValueError("The specified filter '{}' is an invalid filter!\nValid filters are: {}".format(filter, valid_filters))

        url = self.url + "/tests/"
        url += "?" + urlencode(params) + "&size=" + str(size) + "&from_index=" + str(from_index)
        response = requests.get(url, auth=self.auth, verify=self.verify)
        if response.status_code != 200:
            handle_response_error("Error listing tests", response)
        tests = response.json()
        return tests

    def add_test(self, name="", alias="", version="", author="", species="",
                      age="", brain_region="", cell_type="", recording_modality="",
                      test_type="", score_type="", protocol="", data_location="",
                      data_type="", publication="", repository="", path=""):
        """Register a new test on the test library.

        This allows you to add a new test to the test library. A test instance
        (version) needs to be specified when registering a new test.

        Parameters
        ----------
        name : string
            Name of the test definition to be created.
        alias : string, optional
            User-assigned unique identifier to be associated with test definition.
        version : string
            User-assigned identifier (unique for each test) associated with test instance.
        author : string
            Name of person creating the test.
        species : string
            The species from which the data was collected.
        age : string
            The age of the specimen.
        brain_region : string
            The brain region being targeted in the test.
        cell_type : string
            The type of cell being examined.
        recording_modality : string
            Specifies the type of observation used in the test.
        test_type : string
            Specifies the type of the test.
        score_type : string
            The type of score produced by the test.
        protocol : string
            Experimental protocol involved in obtaining reference data.
        data_location : string
            URL of file containing reference data (observation).
        data_type : string
            The type of reference data (observation).
        publication : string
            Publication or comment (e.g. "Unpublished") to be associated with observation.
        repository : string
            URL of Python package repository (e.g. GitHub).
        path : string
            Python path (not filesystem path) to test source code within Python package.

        Returns
        -------
        UUID
            UUID of the test instance that has been created.

        Examples
        --------
        >>> test = test_library.add_test(name="Cell Density Test", alias="", version="1.0", author="Shailesh Appukuttan",
                                species="Mouse (Mus musculus)", age="TBD", brain_region="Hippocampus", cell_type="Other",
                                recording_modality="electron microscopy", test_type="network structure", score_type="Other", protocol="Later",
                                data_location="https://object.cscs.ch/v1/AUTH_c0a333ecf7c045809321ce9d9ecdfdea/sp6_validation_data/hippounit/feat_CA1_pyr_cACpyr_more_features.json",
                                data_type="Mean, SD", publication="Halasy et al., 1996",
                                repository="https://github.com/appukuttan-shailesh/morphounit.git", path="morphounit.tests.CellDensityTest")
        """

        values = self.get_attribute_options()

        if species not in values["species"]:
            raise Exception("species = '" +species+"' is invalid.\nValue has to be one of these: " + str(values["species"]))
        if brain_region not in values["brain_region"]:
            raise Exception("brain_region = '" +brain_region+"' is invalid.\nValue has to be one of these: " + str(values["brain_region"]))
        if cell_type not in values["cell_type"]:
            raise Exception("cell_type = '" +cell_type+"' is invalid.\nValue has to be one of these: " + str(values["cell_type"]))
        if recording_modality not in values["recording_modality"]:
            raise Exception("recording_modality = '" +recording_modality+"' is invalid.\nValue has to be one of these: " + str(values["recording_modality"]))
        if test_type not in values["test_type"]:
            raise Exception("test_type = '" +test_type+"' is invalid.\nValue has to be one of these: " + str(values["test_type"]))
        if score_type not in values["score_type"]:
            raise Exception("score_type = '" +score_type+"' is invalid.\nValue has to be one of these: " + str(values["score_type"]))

        if alias == "":
            alias = None

        test_data = locals()
        test_data.pop("self")
        test_data["description"] = test_data.pop("protocol")
        for key in ("author", "data_location"):
            if not isinstance(test_data[key], list):
                test_data[key] = [test_data[key]]
        code_data = {}
        for key in ["version", "repository", "path", "values"]:
            value = test_data.pop(key)
            if value:
                code_data[key] = value
        if code_data:
            test_data["instances"] = [code_data]

        url = self.url + "/tests/"
        headers = {'Content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(test_data),
                                 auth=self.auth, headers=headers,
                                 verify=self.verify)
        if response.status_code == 201:
            return response.json()["id"]
        else:
            handle_response_error("Error in adding test", response)

    def edit_test(self, name=None, test_id="", alias="", author=None,
                  species=None, age=None, brain_region=None, cell_type=None, recording_modality=None,
                  test_type=None, score_type=None, protocol=None, data_location=None,
                  data_type=None, publication=None):
        """Edit an existing test in the test library.

        To update an existing test, the `test_id` must be provided. Any of the
        other parameters may be updated.
        Only the parameters being updated need to be specified.

        Parameters
        ----------
        name : string
            Name of the test definition.
        test_id : UUID
            System generated unique identifier associated with test definition.
        alias : string, optional
            User-assigned unique identifier to be associated with test definition.
        author : string
            Name of person who created the test.
        species : string
            The species from which the data was collected.
        age : string
            The age of the specimen.
        brain_region : string
            The brain region being targeted in the test.
        cell_type : string
            The type of cell being examined.
        recording_modality : string
            Specifies the type of observation used in the test.
        test_type : string
            Specifies the type of the test.
        score_type : string
            The type of score produced by the test.
        protocol : string
            Experimental protocol involved in obtaining reference data.
        data_location : string
            URL of file containing reference data (observation).
        data_type : string
            The type of reference data (observation).
        publication : string
            Publication or comment (e.g. "Unpublished") to be associated with observation.

        Note
        ----
        Test instances cannot be edited here.
        This has to be done using :meth:`edit_test_instance`

        Returns
        -------
        UUID
            (Verify!) UUID of the test instance that has been edited.

        Examples
        --------
        test = test_library.edit_test(name="Cell Density Test", test_id="7b63f87b-d709-4194-bae1-15329daf3dec", alias="CDT-6", author="Shailesh Appukuttan", publication="Halasy et al., 1996",
                                      species="Mouse (Mus musculus)", brain_region="Hippocampus", cell_type="Other", age="TBD", recording_modality="electron microscopy",
                                      test_type="network structure", score_type="Other", protocol="To be filled sometime later", data_location="https://object.cscs.ch/v1/AUTH_c0a333ecf7c045809321ce9d9ecdfdea/sp6_validation_data/hippounit/feat_CA1_pyr_cACpyr_more_features.json", data_type="Mean, SD")
        """

        if test_id == "":
            raise Exception("Test ID needs to be provided for editing a test.")

        test_data = {}
        args = locals()
        for field in ("name", "alias", "author", "species", "age", "brain_region", "cell_type",
                      "recording_modality", "test_type", "score_type", "protocol", "data_location",
                      "data_type"):  # todo: handle publicaton
            value = args[field]
            if value:
                test_data[field] = value

        values = self.get_attribute_options()
        for field in ("species", "brain_region", "cell_type", "recording_modality", "test_type", "score_type"):
            if field in test_data and test_data[field] not in values[field]:
                raise Exception(field + " = '"  + test_data[field] + "' is invalid.\n"
                                "Value has to be one of these: " + values[field])

        for field in ("author", "data_location"):
            if not isinstance(test_data[field], list):
                test_data[field] = [test_data[field]]

        url = self.url + "/tests/" + test_id
        headers = {'Content-type': 'application/json'}
        response = requests.put(url, data=json.dumps(test_data),
                                auth=self.auth, headers=headers,
                                verify=self.verify)
        if response.status_code == 200:
            return response.json()["id"]
        else:
            handle_response_error("Error in editing test", response)

    def delete_test(self, test_id="", alias=""):
        """ONLY FOR SUPERUSERS: Delete a specific test definition by its test_id or alias.

        A specific test definition can be deleted from the test library, along with all
        associated test instances, in the following ways (in order of priority):

        1. specify the `test_id`
        2. specify the `alias` (of the test)

        Parameters
        ----------
        test_id : UUID
            System generated unique identifier associated with test definition.
        alias : string
            User-assigned unique identifier associated with test definition.

        Note
        ----
        * This feature is only for superusers!

        Examples
        --------
        >>> test_library.delete_test(test_id="8c7cb9f6-e380-452c-9e98-e77254b088c5")
        >>> test_library.delete_test(alias="B1")
        """

        if test_id == "" and alias == "":
            raise Exception("test ID or alias needs to be provided for deleting a test.")
        elif test_id != "":
            url = self.url + "/tests/" + test_id
        else:
            url = self.url + "/tests/" + quote(alias)

        test_json = requests.delete(url, auth=self.auth, verify=self.verify)
        if test_json.status_code == 403:
            handle_response_error("Only SuperUser accounts can delete data", test_json)
        elif test_json.status_code != 200:
            handle_response_error("Error in deleting test", test_json)

    def get_test_instance(self, instance_path="", instance_id="", test_id="", alias="", version=""):
        """Retrieve a specific test instance definition from the test library.

        A specific test instance can be retrieved
        in the following ways (in order of priority):

        1. load from a local JSON file specified via `instance_path`
        2. specify `instance_id` corresponding to test instance in test library
        3. specify `test_id` and `version`
        4. specify `alias` (of the test) and `version`
        Note: for (3) and (4) above, if `version` is not specified,
              then the latest test version is retrieved

        Parameters
        ----------
        instance_path : string
            Location of local JSON file with test instance metadata.
        instance_id : UUID
            System generated unique identifier associated with test instance.
        test_id : UUID
            System generated unique identifier associated with test definition.
        alias : string
            User-assigned unique identifier associated with test definition.
        version : string
            User-assigned identifier (unique for each test) associated with test instance.

        Returns
        -------
        dict
            Information about the test instance.

        Examples
        --------
        >>> test_instance = test_library.get_test_instance(test_id="7b63f87b-d709-4194-bae1-15329daf3dec", version="1.0")
        >>> test_instance = test_library.get_test_instance(test_id="7b63f87b-d709-4194-bae1-15329daf3dec")
        """

        if instance_path == "" and instance_id == "" and test_id == "" and alias == "":
            raise Exception("instance_path or instance_id or test_id or alias needs to be provided for finding a test instance.")
        if instance_path:
            if os.path.isfile(instance_path):
                # instance_path is a local path
                with open(instance_path) as fp:
                    test_instance_json = json.load(fp)
            else:
                raise Exception("Error in local file path specified by instance_path.")
        else:
            test_identifier = test_id or alias
            if instance_id:
                url = self.url + "/tests/query/instances/" + instance_id
            elif test_id and version:
                url = self.url + "/tests/" + test_id + "/instances/?version=" + version
            elif alias and version:
                url = self.url + "/tests/" + quote(alias) + "/instances/?version=" + version
            elif test_id and not version:
                url = self.url + "/tests/" + test_id + "/instances/latest"
            else:
                url = self.url + "/tests/" + quote(alias) + "/instances/latest"
            response = requests.get(url, auth=self.auth, verify=self.verify)

        if response.status_code != 200:
            handle_response_error("Error in retrieving test instance", response)
        test_instance_json = response.json()
        if isinstance(test_instance_json, list):  # can have multiple instances with the same version but different parameters
            if len(test_instance_json) == 1:
                test_instance_json = test_instance_json[0]
            elif len(test_instance_json) > 1:
                return max(test_instance_json, key=lambda x: x['timestamp'])
        return test_instance_json

    def list_test_instances(self, instance_path="", test_id="", alias=""):
        """Retrieve list of test instances belonging to a specified test.

        This can be retrieved in the following ways (in order of priority):

        1. load from a local JSON file specified via `instance_path`
        2. specify `test_id`
        3. specify `alias` (of the test)

        Parameters
        ----------
        instance_path : string
            Location of local JSON file with test instance metadata.
        test_id : UUID
            System generated unique identifier associated with test definition.
        alias : string
            User-assigned unique identifier associated with test definition.

        Returns
        -------
        dict[]
            Information about the test instances.

        Examples
        --------
        >>> test_instances = test_library.list_test_instances(test_id="8b63f87b-d709-4194-bae1-15329daf3dec")
        """

        if instance_path == "" and test_id == "" and alias == "":
            raise Exception("instance_path or test_id or alias needs to be provided for finding test instances.")
        if instance_path and os.path.isfile(instance_path):
            # instance_path is a local path
            with open(instance_path) as fp:
                test_instances_json = json.load(fp)
        else:
            if test_id:
                url = self.url + "/tests/" + test_id + "/instances/?size=100000"
            else:
                url = self.url + "/tests/" + quote(alias) + "/instances/?size=100000"
            response = requests.get(url, auth=self.auth, verify=self.verify)

        if response.status_code != 200:
            handle_response_error("Error in retrieving test instances", response)
        test_instances_json = response.json()
        return test_instances_json

    def add_test_instance(self, test_id="", alias="", repository="", path="", version="", description="", parameters=""):
        """Register a new test instance.

        This allows to add a new instance to an existing test in the test library.
        The `test_id` needs to be specified as input parameter.

        Parameters
        ----------
        test_id : UUID
            System generated unique identifier associated with test definition.
        alias : string
            User-assigned unique identifier associated with test definition.
        repository : string
            URL of Python package repository (e.g. github).
        path : string
            Python path (not filesystem path) to test source code within Python package.
        version : string
            User-assigned identifier (unique for each test) associated with test instance.
        description : string, optional
            Text describing this specific test instance.
        parameters : string, optional
            Any additional parameters to be submitted to test, or used by it, at runtime.

        Returns
        -------
        UUID
            UUID of the test instance that has been created.

        Note
        ----
        * `alias` is not currently implemented in the API; kept for future use.
        * TODO: Either test_id or alias needs to be provided, with test_id taking precedence over alias.

        Examples
        --------
        >>> response = test_library.add_test_instance(test_id="7b63f87b-d709-4194-bae1-15329daf3dec",
                                        repository="https://github.com/appukuttan-shailesh/morphounit.git",
                                        path="morphounit.tests.CellDensityTest",
                                        version="3.0")
        """

        instance_data = {}
        if repository:
            instance_data["repository"] = repository
        if path:
            instance_data["path"] = path
        if version:
            instance_data["version"] = version
        if description:
            instance_data["description"] = description
        if parameters:
            instance_data["parameters"] = parameters

        test_id = test_id or alias
        if not test_id:
            raise Exception("test_id or alias needs to be provided for finding the test.")
        else:
            url = self.url + "/tests/" + test_id + "/instances/"

        headers = {'Content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(instance_data),
                                 auth=self.auth, headers=headers,
                                 verify=self.verify)
        if response.status_code == 201:
            return response.json()["id"]
        else:
            handle_response_error("Error in adding test instance", response)

    def edit_test_instance(self, instance_id="", test_id="", alias="", repository=None, path=None, version=None, description=None, parameters=None):
        """Edit an existing test instance.

        This allows to edit an instance of an existing test in the test library.
        The test instance can be specified in the following ways (in order of priority):

        1. specify `instance_id` corresponding to test instance in test library
        2. specify `test_id` and `version`
        3. specify `alias` (of the test) and `version`

        Only the parameters being updated need to be specified. You cannot
        edit the test `version` in the latter two cases. To do so,
        you must employ the first option above. You can retrieve the `instance_id`
        via :meth:`get_test_instance`

        Parameters
        ----------
        instance_id : UUID
            System generated unique identifier associated with test instance.
        test_id : UUID
            System generated unique identifier associated with test definition.
        alias : string
            User-assigned unique identifier associated with test definition.
        repository : string
            URL of Python package repository (e.g. github).
        path : string
            Python path (not filesystem path) to test source code within Python package.
        version : string
            User-assigned identifier (unique for each test) associated with test instance.
        description : string, optional
            Text describing this specific test instance.
        parameters : string, optional
            Any additional parameters to be submitted to test, or used by it, at runtime.

        Returns
        -------
        UUID
            UUID of the test instance that has was edited.

        Examples
        --------
        >>> response = test_library.edit_test_instance(test_id="7b63f87b-d709-4194-bae1-15329daf3dec",
                                        repository="https://github.com/appukuttan-shailesh/morphounit.git",
                                        path="morphounit.tests.CellDensityTest",
                                        version="4.0")
        """

        test_identifier = test_id or alias
        if instance_id == "" and (test_identifier == "" or version is None):
            raise Exception("instance_id or (test_id, version) or (alias, version) needs to be provided for finding a test instance.")

        instance_data = {}
        args = locals()
        for field in ("repository", "path", "version", "description", "parameters"):
            value = args[field]
            if value:
                instance_data[field] = value

        if instance_id:
            url = self.url + "/tests/query/instances/" + instance_id
        else:
            url = self.url + "/tests/" + test_identifier + "/instances/?version=" + version
            response0 = requests.get(url, auth=self.auth, verify=self.verify)
            if response0.status_code != 200:
                raise Exception("Invalid test identifier and/or version")
            url = self.url + "/tests/query/instances/" + response0.json()[0]["id"]  # todo: handle more than 1 instance in response

        headers = {'Content-type': 'application/json'}
        response = requests.put(url, data=json.dumps(instance_data), auth=self.auth, headers=headers,
                                verify=self.verify)
        if response.status_code == 200:
            return response.json()["id"]
        else:
            handle_response_error("Error in editing test instance", response)

    def delete_test_instance(self, instance_id="", test_id="", alias="", version=""):
        """ONLY FOR SUPERUSERS: Delete an existing test instance.

        This allows to delete an instance of an existing test in the test library.
        The test instance can be specified in the following ways (in order of priority):

        1. specify `instance_id` corresponding to test instance in test library
        2. specify `test_id` and `version`
        3. specify `alias` (of the test) and `version`

        Parameters
        ----------
        instance_id : UUID
            System generated unique identifier associated with test instance.
        test_id : UUID
            System generated unique identifier associated with test definition.
        alias : string
            User-assigned unique identifier associated with test definition.
        version : string
            User-assigned unique identifier associated with test instance.

        Note
        ----
        * This feature is only for superusers!

        Examples
        --------
        >>> test_library.delete_model_instance(test_id="8c7cb9f6-e380-452c-9e98-e77254b088c5")
        >>> test_library.delete_model_instance(alias="B1", version="1.0")
        """

        test_identifier = test_id or alias
        if instance_id == "" and (test_identifier == "" or version == ""):
            raise Exception("instance_id or (test_id, version) or (alias, version) needs to be provided for finding a test instance.")

        if instance_id:
            url = self.url + "/tests/query/instances/" + instance_id
        else:
            url = self.url + "/tests/" + test_identifier + "/instances/" + version
            response0 = requests.get(url, auth=self.auth, verify=self.verify)
            if response0.status_code != 200:
                raise Exception("Invalid test identifier and/or version")
            url = self.url + "/tests/query/instances/" + response0.json()[0]["id"]
        response = requests.delete(url, auth=self.auth, verify=self.verify)
        if response.status_code == 403:
            handle_response_error("Only SuperUser accounts can delete data", response)
        elif response.status_code != 200:
            handle_response_error("Error in deleting test instance", response)

    def _load_reference_data(self, uri_list):
        # Load the reference data ("observations").
        observation_data = []
        return_single = False
        if not isinstance(uri_list, list):
            uri_list = [uri_list]
            return_single = True
        for uri in uri_list:
            parse_result = urlparse(uri)
            datastore = URI_SCHEME_MAP[parse_result.scheme](auth=self.auth)
            observation_data.append(datastore.load_data(uri))
        if return_single:
            return observation_data[0]
        else:
            return observation_data

    def get_attribute_options(self, param=""):
        """Retrieve valid values for test attributes.

        Will return the list of valid values (where applicable) for various test attributes.
        The following test attributes can be specified:

        * cell_type
        * test_type
        * score_type
        * brain_region
        * recording_modality
        * species

        If an attribute is specified, then only values that correspond to it will be returned,
        else values for all attributes are returned.

        Parameters
        ----------
        param : string, optional
            Attribute of interest

        Returns
        -------
        dict
            Dictionary with key(s) as attribute(s), and value(s) as list of valid options.

        Examples
        --------
        >>> data = test_library.get_attribute_options()
        >>> data = test_library.get_attribute_options("cell types")
        """
        valid_params = ["species", "brain_region", "cell_type", "test_type", "score_type", "recording_modality", "implementation_status"]
        options = self._get_attribute_options(param, valid_params)
        return options

    def get_result(self, result_id=""):
        """Retrieve a test result.

        This allows to retrieve the test result score and other related information.
        The `result_id` needs to be specified as input parameter.

        Parameters
        ----------
        result_id : UUID
            System generated unique identifier associated with result.

        Returns
        -------
        dict
            Information about the result retrieved.

        Examples
        --------
        >>> result = test_library.get_result(result_id="901ac0f3-2557-4ae3-bb2b-37617312da09")
        """

        if not result_id:
            raise Exception("result_id needs to be provided for finding a specific result.")
        else:
            url = self.url + "/results/" + result_id
        response = requests.get(url, auth=self.auth, verify=self.verify)
        if response.status_code != 200:
            handle_response_error("Error in retrieving result", response)
        result_json = response.json()
        return result_json

    def list_results(self, size=1000000, from_index=0, **filters):
        """Retrieve test results satisfying specified filters.

        This allows to retrieve a list of test results with their scores
        and other related information.

        Parameters
        ----------
        size : positive integer
            Max number of results to be returned; default is set to 1000000.
        from_index : positive integer
            Index of first result to be returned; default is set to 0.
        **filters : variable length keyword arguments
            To be used to filter the results metadata.

        Returns
        -------
        dict
            Information about the results retrieved.

        Examples
        --------
        >>> results = test_library.list_results()
        >>> results = test_library.list_results(test_id="7b63f87b-d709-4194-bae1-15329daf3dec")
        >>> results = test_library.list_results(id="901ac0f3-2557-4ae3-bb2b-37617312da09")
        >>> results = test_library.list_results(model_instance_id="f32776c7-658f-462f-a944-1daf8765ec97")
        """

        url = self.url + "/results/"
        url += "?" + urlencode(filters) + "&size=" + str(size) + "&from_index=" + str(from_index)
        response = requests.get(url, auth=self.auth, verify=self.verify)
        if response.status_code != 200:
            handle_response_error("Error in retrieving results", response)
        result_json = response.json()
        return result_json

    def register_result(self, test_result, data_store=None, project_id=None):
        """Register test result with HBP Validation Results Service.

        The score of a test, along with related output data such as figures,
        can be registered on the validation framework.

        Parameters
        ----------
        test_result : :class:`sciunit.Score`
            a :class:`sciunit.Score` instance returned by `test.judge(model)`
        data_store : :class:`DataStore`
            a :class:`DataStore` instance, for uploading related data generated by the test run, e.g. figures.
        project_id : str
            String input specifying the Collab path, e.g. 'model-validation' to indicate Collab 'https://wiki.ebrains.eu/bin/view/Collabs/model-validation/'.
            This is used to indicate the Collab where results should be saved.

        Note
        ----
        Source code for this method still contains comments/suggestions from
        previous client. To be removed or implemented.

        Returns
        -------
        UUID
            UUID of the test result that has been created.

        Examples
        --------
        >>> score = test.judge(model)
        >>> response = test_library.register_result(test_result=score)
        """

        if project_id is None:
            project_id = test_result.related_data.get("project_id", None)
        if project_id is None:
            raise Exception("Don't know where to register this result. Please specify `project_id`!")

        model_catalog = ModelCatalog.from_existing(self)
        model_instance_uuid = model_catalog.find_model_instance_else_add(test_result.model)

        results_storage = []
        if data_store:
            if not data_store.authorized:
                data_store.authorize(self.auth)  # relies on data store using HBP authorization
                                                 # if this is not the case, need to authenticate/authorize
                                                 # the data store before passing to `register()`
            if data_store.project_id is None:
                data_store.project_id = project_id
            files_to_upload = []
            if "figures" in test_result.related_data:
                files_to_upload.extend(test_result.related_data["figures"])
            if files_to_upload:
                results_storage.append(data_store.upload_data(files_to_upload))

        url = self.url + "/results/"
        result_json = {
                        "model_instance_id": model_instance_uuid,
                        "test_instance_id": test_result.test.uuid,
                        "results_storage": results_storage,
                        "score": int(test_result.score) if isinstance(test_result.score, bool) else test_result.score,
                        "passed": None if "passed" not in test_result.related_data else test_result.related_data["passed"],
                        #"platform": str(self._get_platform()), # not currently supported in v2
                        "project_id": project_id,
                        "normalized_score": int(test_result.score) if isinstance(test_result.score, bool) else test_result.score,
                      }

        headers = {'Content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(result_json),
                                 auth=self.auth, headers=headers,
                                 verify=self.verify)
        if response.status_code == 201:
            print("Result registered successfully!")
            return response.json()["id"]
        else:
            handle_response_error("Error registering result", response)

    def delete_result(self, result_id=""):
        """ONLY FOR SUPERUSERS: Delete a result on the validation framework.

        This allows to delete an existing result info on the validation framework.
        The `result_id` needs to be specified as input parameter.

        Parameters
        ----------
        result_id : UUID
            System generated unique identifier associated with result.

        Note
        ----
        * This feature is only for superusers!

        Examples
        --------
        >>> model_catalog.delete_result(result_id="2b45e7d4-a7a1-4a31-a287-aee7072e3e75")
        """

        if not result_id:
            raise Exception("result_id needs to be provided for finding a specific result.")
        else:
            url = self.url + "/results/" + result_id
        model_image_json = requests.delete(url, auth=self.auth, verify=self.verify)
        if model_image_json.status_code == 403:
            handle_response_error("Only SuperUser accounts can delete data", model_image_json)
        elif model_image_json.status_code != 200:
            handle_response_error("Error in deleting result", model_image_json)

    def _get_platform(self):
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


class ModelCatalog(BaseClient):
    """Client for the HBP Model Catalog.

    The ModelCatalog client manages all actions pertaining to models.
    The following actions can be performed:

    ====================================   ====================================
    Action                                 Method
    ====================================   ====================================
    Get model description                  :meth:`get_model`
    List model descriptions                :meth:`list_models`
    Register new model description         :meth:`register_model`
    Edit model description                 :meth:`edit_model`
    Get valid attribute values             :meth:`get_attribute_options`
    Get model instance                     :meth:`get_model_instance`
    Download model instance                :meth:`download_model_instance`
    Get BluePyOpt model instance class     :meth:`get_BPO_model`
    List model instances                   :meth:`list_model_instances`
    Add new model instance                 :meth:`add_model_instance`
    Find model instance; else add          :meth:`find_model_instance_else_add`
    Edit existing model instance           :meth:`edit_model_instance`
    Get figure from model description      :meth:`get_model_image`
    List figures from model description    :meth:`list_model_images`
    Add figure to model description        :meth:`add_model_image`
    Edit existing figure metadata          :meth:`edit_model_image`
    ====================================   ====================================

    Parameters
    ----------
    username : string
        Your HBP Collaboratory username. Not needed in Jupyter notebooks within the HBP Collaboratory.
    password : string, optional
        Your HBP Collaboratory password; advisable to not enter as plaintext.
        If left empty, you would be prompted for password at run time (safer).
        Not needed in Jupyter notebooks within the HBP Collaboratory.
    environment : string, optional
        Used to indicate whether being used for development/testing purposes.
        Set as `production` as default for using the production system,
        which is appropriate for most users. When set to `dev`, it uses the
        `development` system. Other environments, if required, should be defined
        inside a json file named `config.json` in the working directory. Example:

        .. code-block:: JSON

            {
                "prod": {
                    "url": "https://validation-v1.brainsimulation.eu",
                    "client_id": "3ae21f28-0302-4d28-8581-15853ad6107d"
                },
                "dev_test": {
                    "url": "https://localhost:8000",
                    "client_id": "90c719e0-29ce-43a2-9c53-15cb314c2d0b",
                    "verify_ssl": false
                }
            }

    token : string, optional
        You may directly input a valid authenticated token from Collaboratory v1 or v2.
        Note: you should use the `access_token` and NOT `refresh_token`.

    Examples
    --------
    Instantiate an instance of the ModelCatalog class

    >>> model_catalog = ModelCatalog(username="<<hbp_username>>", password="<<hbp_password>>")
    >>> model_catalog = ModelCatalog(token="<<token>>")
    """

    __test__ = False

    def __init__(self, username=None, password=None, environment="production", token=None):
        super(ModelCatalog, self).__init__(username, password, environment, token)
        self._set_app_info()

    def _set_app_info(self):
        #  TODO: check if needs to be updated for Collab v2
        if self.environment == "production":
            self.app_id = 357
            self.app_name = "Model Catalog"
        elif self.environment == "dev":
            self.app_id = 348
            self.app_name = "Model Catalog (dev)"
        elif self.environment == "integration":
            self.app_id = 431
            self.app_name = "Model Catalog (staging)"

    # def set_app_config(self, project_id="", only_if_new=False, species="", brain_region="", cell_type="", model_scope="", abstraction_level="", organization=""):
    #     #  TODO: needs to be updated for Collab v2
    #     inputArgs = locals()
    #     params = {}
    #     params["url"] = self.url + "/parametersconfiguration-model-catalog/parametersconfigurationrest/"
    #     params["only_if_new"] = only_if_new
    #     params["config"] = inputArgs
    #     params["config"].pop("self")
    #     params["config"].pop("only_if_new")
    #     params["config"]["app_type"] = "model_catalog"
    #     self._configure_app_collab(params)

    # def set_app_config_minimal(self, project_="", only_if_new=False):
    #     #  TODO: needs to be updated for Collab v2
    #     inputArgs = locals()
    #     species = []
    #     brain_region = []
    #     cell_type = []
    #     model_scope = []
    #     abstraction_level = []
    #     organization = []

    #     models = self.list_models(app_id=app_id)
    #     if len(models) == 0:
    #         print("There are currently no models associated with this Model Catalog app.\nConfiguring filters to show all accessible data.")

    #     for model in models:
    #         if model["species"] not in species:
    #             species.append(model["species"])
    #         if model["brain_region"] not in brain_region:
    #             brain_region.append(model["brain_region"])
    #         if model["cell_type"] not in cell_type:
    #             cell_type.append(model["cell_type"])
    #         if model["model_scope"] not in model_scope:
    #             model_scope.append(model["model_scope"])
    #         if model["abstraction_level"] not in abstraction_level:
    #             abstraction_level.append(model["abstraction_level"])
    #         if model["organization"] not in organization:
    #             organization.append(model["organization"])

    #     filters = {}
    #     for key in ["project_id", "app_id", "species", "brain_region", "cell_type", "model_scope", "abstraction_level", "organization"]:
    #         if isinstance(locals()[key], list):
    #             filters[key] = ",".join(locals()[key])
    #         else:
    #             filters[key] = locals()[key]

    #     params = {}
    #     params["url"] = self.url + "/parametersconfiguration-model-catalog/parametersconfigurationrest/"
    #     params["only_if_new"] = only_if_new
    #     params["config"] = filters
    #     params["config"]["app_type"] = "model_catalog"
    #     self._configure_app_collab(params)

    def get_model(self, model_id="", alias="", instances=True, images=True):
        """Retrieve a specific model description by its model_id or alias.

        A specific model description can be retrieved from the model catalog
        in the following ways (in order of priority):

        1. specify the `model_id`
        2. specify the `alias` (of the model)

        Parameters
        ----------
        model_id : UUID
            System generated unique identifier associated with model description.
        alias : string
            User-assigned unique identifier associated with model description.
        instances : boolean, optional
            Set to False if you wish to omit the details of the model instances; default True.
        images : boolean, optional
            Set to False if you wish to omit the details of the model images (figures); default True.

        Returns
        -------
        dict
            Entire model description as a JSON object.

        Examples
        --------
        >>> model = model_catalog.get_model(model_id="8c7cb9f6-e380-452c-9e98-e77254b088c5")
        >>> model = model_catalog.get_model(alias="B1")
        """

        if model_id == "" and alias == "":
            raise Exception("Model ID or alias needs to be provided for finding a model.")
        elif model_id != "":
            url = self.url + "/models/" + model_id
        else:
            url = self.url + "/models/" + quote(alias)

        model_json = requests.get(url, auth=self.auth, verify=self.verify)
        if model_json.status_code != 200:
            handle_response_error("Error in retrieving model", model_json)
        model_json = model_json.json()

        if instances is False:
            model_json.pop("instances")
        if images is False:
            model_json.pop("images")
        return model_json

    def list_models(self, size=1000000, from_index=0, **filters):
        """Retrieve list of model descriptions satisfying specified filters.

        The filters may specify one or more attributes that belong
        to a model description. The following model attributes can be specified:

        * app_id
        * name
        * alias
        * author
        * organization
        * species
        * brain_region
        * cell_type
        * model_scope
        * abstraction_level
        * owner
        * project
        * license

        Parameters
        ----------
        size : positive integer
            Max number of models to be returned; default is set to 1000000.
        from_index : positive integer
            Index of first model to be returned; default is set to 0.
        **filters : variable length keyword arguments
            To be used to filter model descriptions from the model catalog.

        Returns
        -------
        list
            List of model descriptions satisfying specified filters.

        Examples
        --------
        >>> models = model_catalog.list_models()
        >>> models = model_catalog.list_models(app_id="39968")
        >>> models = model_catalog.list_models(cell_type="Pyramidal Cell", brain_region="Hippocampus")
        """

        # TODO: verify valid filters for v2 APIs
        valid_filters = ["project_id", "name", "alias", "author", "organization", "species", "brain_region", "cell_type", "model_scope", "abstraction_level", "owner", "project", "license"]
        params = locals()["filters"]
        for filter in params:
            if filter not in valid_filters:
                raise ValueError("The specified filter '{}' is an invalid filter!\nValid filters are: {}".format(filter, valid_filters))

        url = self.url + "/models/"
        url += "?" + urlencode(params) + "&size=" + str(size) + "&from_index=" + str(from_index)
        response = requests.get(url, auth=self.auth, verify=self.verify)
        try:
            models = response.json()
        except (json.JSONDecodeError, simplejson.JSONDecodeError):
            handle_response_error("Error in list_models()", response)
        return models

    def register_model(self, project_id="", name="", alias="", author="", organization="", private=False,
                       species="", brain_region="", cell_type="", model_scope="", abstraction_level="", owner="", project="",
                       license="", description="", instances=[], images=[]):
        """Register a new model in the model catalog.

        This allows you to add a new model to the model catalog. Model instances
        and/or images (figures) can optionally be specified at the time of model
        creation, or can be added later individually.

        Parameters
        ----------
        project_id : string
            Specifies the ID of the host collab in the HBP Collaboratory.
            (the model would belong to this collab)
        name : string
            Name of the model description to be created.
        alias : string, optional
            User-assigned unique identifier to be associated with model description.
        author : string
            Name of person creating the model description.
        organization : string, optional
            Option to tag model with organization info.
        private : boolean
            Set visibility of model description. If True, model would only be seen in host app (where created). Default False.
        species : string
            The species for which the model is developed.
        brain_region : string
            The brain region for which the model is developed.
        cell_type : string
            The type of cell for which the model is developed.
        model_scope : string
            Specifies the type of the model.
        abstraction_level : string
            Specifies the model abstraction level.
        owner : string
            Specifies the owner of the model. Need not necessarily be the same as the author.
        project : string
            Can be used to indicate the project to which the model belongs.
        license : string
            Indicates the license applicable for this model.
        description : string
            Provides a description of the model.
        instances : list, optional
            Specify a list of instances (versions) of the model.
        images : list, optional
            Specify a list of images (figures) to be linked to the model.

        Returns
        -------
        UUID
            UUID of the model description that has been created.

        Examples
        --------
        (without instances and images)

        >>> model = model_catalog.register_model(project_id="39968", name="Test Model - B2",
                        alias="Model vB2", author="Shailesh Appukuttan", organization="HBP-SP6",
                        private=False, cell_type="Granule Cell", model_scope="Single cell model",
                        abstraction_level="Spiking neurons",
                        brain_region="Basal Ganglia", species="Mouse (Mus musculus)",
                        owner="Andrew Davison", project="SP 6.4", license="BSD 3-Clause",
                        description="This is a test entry")

        (with instances and images)

        >>> model = model_catalog.register_model(project_id="39968", name="Test Model - C2",
                        alias="Model vC2", author="Shailesh Appukuttan", organization="HBP-SP6",
                        private=False, cell_type="Granule Cell", model_scope="Single cell model",
                        abstraction_level="Spiking neurons",
                        brain_region="Basal Ganglia", species="Mouse (Mus musculus)",
                        owner="Andrew Davison", project="SP 6.4", license="BSD 3-Clause",
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

        values = self.get_attribute_options()

        if cell_type not in values["cell_type"]:
            raise Exception("cell_type = '" +cell_type+"' is invalid.\nValue has to be one of these: " + str(values["cell_type"]))
        if model_scope not in values["model_scope"]:
            raise Exception("model_scope = '" +model_scope+"' is invalid.\nValue has to be one of these: " + str(values["model_scope"]))
        if abstraction_level not in values["abstraction_level"]:
            raise Exception("abstraction_level = '" +abstraction_level+"' is invalid.\nValue has to be one of these: " + str(values["abstraction_level"]))
        if brain_region not in values["brain_region"]:
            raise Exception("brain_region = '" +brain_region+"' is invalid.\nValue has to be one of these: " + str(values["brain_region"]))
        if species not in values["species"]:
            raise Exception("species = '" +species+"' is invalid.\nValue has to be one of these: " + str(values["species"]))

        if private not in [True, False]:
            raise Exception("Model's 'private' attribute should be specified as True / False. Default value is False.")

        model_data = locals()
        for key in ["self", "values"]:
            model_data.pop(key)
        for key in ["author", "owner"]:
            if not isinstance(model_data[key], list):
                model_data[key] = [model_data[key]]

        url = self.url + "/models/"
        headers = {'Content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(model_data),
                                 auth=self.auth, headers=headers,
                                 verify=self.verify)
        if response.status_code == 201:
            return response.json()["id"]
        else:
            handle_response_error("Error in adding model", response)

    def edit_model(self, model_id="", project_id=None, name=None, alias="", author=None, organization=None, private=None, cell_type=None,
                   model_scope=None, abstraction_level=None, brain_region=None, species=None, owner="", project="", license="", description=None):
        """Edit an existing model on the model catalog.

        This allows you to edit a new model to the model catalog.
        The `model_id` must be provided. Any of the other parameters maybe updated.
        Only the parameters being updated need to be specified.

        Parameters
        ----------
        model_id : UUID
            System generated unique identifier associated with model description.
        project_id : string
            Specifies the ID of the host collab in the HBP Collaboratory.
            (the model would belong to this collab)
        name : string
            Name of the model description to be created.
        alias : string, optional
            User-assigned unique identifier to be associated with model description.
        author : string
            Name of person creating the model description.
        organization : string, optional
            Option to tag model with organization info.
        private : boolean
            Set visibility of model description. If True, model would only be seen in host app (where created). Default False.
        species : string
            The species for which the model is developed.
        brain_region : string
            The brain region for which the model is developed.
        cell_type : string
            The type of cell for which the model is developed.
        model_scope : string
            Specifies the type of the model.
        abstraction_level : string
            Specifies the model abstraction level.
        owner : string
            Specifies the owner of the model. Need not necessarily be the same as the author.
        project : string
            Can be used to indicate the project to which the model belongs.
        license : string
            Indicates the license applicable for this model.
        description : string
            Provides a description of the model.

        Note
        ----
        Model instances and images (figures) cannot be edited here.
        This has to be done using :meth:`edit_model_instance` and :meth:`edit_model_image`

        Returns
        -------
        UUID
            UUID of the model description that has been edited.

        Examples
        --------
        >>> model = model_catalog.edit_model(project_id="39968", name="Test Model - B2",
                        model_id="8c7cb9f6-e380-452c-9e98-e77254b088c5",
                        alias="Model-B2", author="Shailesh Appukuttan", organization="HBP-SP6",
                        private=False, cell_type="Granule Cell", model_scope="Single cell model",
                        abstraction_level="Spiking neurons",
                        brain_region="Basal Ganglia", species="Mouse (Mus musculus)",
                        owner="Andrew Davison", project="SP 6.4", license="BSD 3-Clause",
                        description="This is a test entry")
        """
        if model_id == "":
            raise Exception("Model ID needs to be provided for editing a model.")

        model_data = {}
        args = locals()
        for field in ("project_id", "name", "alias", "author", "organization", "private",
                      "cell_type", "model_scope", "abstraction_level", "brain_region",
                      "species", "owner", "project", "license", "description"):
            value = args[field]
            if value:
                model_data[field] = value

        values = self.get_attribute_options()
        for field in ("species", "brain_region", "cell_type", "abstraction_level", "model_scope"):
            if field in model_data and model_data[field] not in values[field]:
                raise Exception(field + " = '"  + model_data[field] + "' is invalid.\n"
                                "Value has to be one of these: " + values[field])

        for field in ("author", "owner"):
            if not isinstance(model_data[field], list):
                model_data[field] = [model_data[field]]

        if model_data["alias"] == "":
            model_data["alias"] = None

        if model_data.get("private", False) not in (True, False):
            raise Exception("Model's 'private' attribute should be specified as True / False. Default value is False.")

        headers = {'Content-type': 'application/json'}
        url = self.url + "/models/" + model_id
        response = requests.put(url, data=json.dumps(model_data),
                                auth=self.auth, headers=headers,
                                verify=self.verify)
        if response.status_code == 200:
            return response.json()["id"]
        else:
            handle_response_error("Error in updating model", response)

    def delete_model(self, model_id="", alias=""):
        """ONLY FOR SUPERUSERS: Delete a specific model description by its model_id or alias.

        A specific model description can be deleted from the model catalog, along with all
        associated model instances, images and results, in the following ways (in order of priority):

        1. specify the `model_id`
        2. specify the `alias` (of the model)

        Parameters
        ----------
        model_id : UUID
            System generated unique identifier associated with model description.
        alias : string
            User-assigned unique identifier associated with model description.

        Note
        ----
        * This feature is only for superusers!

        Examples
        --------
        >>> model_catalog.delete_model(model_id="8c7cb9f6-e380-452c-9e98-e77254b088c5")
        >>> model_catalog.delete_model(alias="B1")
        """

        if model_id == "" and alias == "":
            raise Exception("Model ID or alias needs to be provided for deleting a model.")
        elif model_id != "":
            url = self.url + "/models/" + model_id
        else:
            url = self.url + "/models/" + quote(alias)

        model_json = requests.delete(url, auth=self.auth, verify=self.verify)
        if model_json.status_code == 403:
            handle_response_error("Only SuperUser accounts can delete data", model_json)
        elif model_json.status_code != 200:
            handle_response_error("Error in deleting model", model_json)

    def get_attribute_options(self, param=""):
        """Retrieve valid values for attributes.

        Will return the list of valid values (where applicable) for various attributes.
    	The following model attributes can be specified:

    	* cell_type
    	* brain_region
    	* model_scope
        * abstraction_level
    	* species
    	* organization

        If an attribute is specified then, only values that correspond to it will be returned,
        else values for all attributes are returned.

        Parameters
        ----------
        param : string, optional
            Attribute of interest

        Returns
        -------
        dict
            Dictionary with key(s) as attribute(s), and value(s) as list of valid options.

        Examples
        --------
        >>> data = model_catalog.get_attribute_options()
        >>> data = model_catalog.get_attribute_options("cell types")
        """
        valid_params = ["species", "brain_region", "cell_type", "model_scope", "abstraction_level"]
        return self._get_attribute_options(param, valid_params)

    def get_model_instance(self, instance_path="", instance_id="", model_id="", alias="", version=""):
        """Retrieve an existing model instance.

        A specific model instance can be retrieved
        in the following ways (in order of priority):

        1. load from a local JSON file specified via `instance_path`
        2. specify `instance_id` corresponding to model instance in model catalog
        3. specify `model_id` and `version`
        4. specify `alias` (of the model) and `version`

        Parameters
        ----------
        instance_path : string
            Location of local JSON file with model instance metadata.
        instance_id : UUID
            System generated unique identifier associated with model instance.
        model_id : UUID
            System generated unique identifier associated with model description.
        alias : string
            User-assigned unique identifier associated with model description.
        version : string
            User-assigned identifier (unique for each model) associated with model instance.

        Returns
        -------
        dict
            Information about the model instance.

        Examples
        --------
        >>> model_instance = model_catalog.get_model_instance(instance_id="a035f2b2-fe2e-42fd-82e2-4173a304263b")
        """

        if instance_path == "" and instance_id == "" and (model_id == "" or version == "") and (alias == "" or version == ""):
            raise Exception("instance_path or instance_id or (model_id, version) or (alias, version) needs to be provided for finding a model instance.")
        if instance_path and os.path.isfile(instance_path):
            # instance_path is a local path
            with open(instance_path) as fp:
                model_instance_json = json.load(fp)
        else:
            if instance_id:
                url = self.url + "/models/query/instances/" + instance_id
            elif model_id and version:
                url = self.url + "/models/" + model_id + "/instances/?version=" + version
            else:
                url = self.url + "/models/" + quote(alias) + "/instances/?version=" + version
            model_instance_json = requests.get(url, auth=self.auth, verify=self.verify)
        if model_instance_json.status_code != 200:
            handle_response_error("Error in retrieving model instance", model_instance_json)
        model_instance_json = model_instance_json.json()
        # if specifying a version, this can return multiple instances, since instances
        # can have the same version but different parameters
        if len(model_instance_json) == 1:
            return model_instance_json[0]
        return model_instance_json

    def download_model_instance(self, instance_path="", instance_id="", model_id="", alias="", version="", local_directory=".", overwrite=False):
        """Download files/directory corresponding to an existing model instance.

        Files/directory corresponding to a model instance to be downloaded. The model
        instance can be specified in the following ways (in order of priority):

        1. load from a local JSON file specified via `instance_path`
        2. specify `instance_id` corresponding to model instance in model catalog
        3. specify `model_id` and `version`
        4. specify `alias` (of the model) and `version`

        Parameters
        ----------
        instance_path : string
            Location of local JSON file with model instance metadata.
        instance_id : UUID
            System generated unique identifier associated with model instance.
        model_id : UUID
            System generated unique identifier associated with model description.
        alias : string
            User-assigned unique identifier associated with model description.
        version : string
            User-assigned identifier (unique for each model) associated with model instance.
        local_directory : string
            Directory path (relative/absolute) where files should be downloaded and saved. Default is current location.
        overwrite: Boolean
            Indicates if any existing file at the target location should be overwritten; default is set to False

        Returns
        -------
        string
            Absolute path of the downloaded file/directory.

        Note
        ----
        Existing files, if any, at the target location will be overwritten!

        Examples
        --------
        >>> file_path = model_catalog.download_model_instance(instance_id="a035f2b2-fe2e-42fd-82e2-4173a304263b")
        """

        model_source = self.get_model_instance(instance_path=instance_path, instance_id=instance_id, model_id=model_id, alias=alias, version=version)["source"]
        if model_source[-1]=="/":
            model_source = model_source[:-1]    # remove trailing '/'
        Path(local_directory).mkdir(parents=True, exist_ok=True)
        fileList = []

        if "drive.ebrains.eu/lib/" in model_source:
            # ***** Handles Collab storage urls *****
            repo_id = model_source.split("drive.ebrains.eu/lib/")[1].split("/")[0]
            model_path = "/" + "/".join(model_source.split("drive.ebrains.eu/lib/")[1].split("/")[2:])
            datastore = URI_SCHEME_MAP["collab_v2"](project_id=repo_id, auth=self.auth)
            fileList = datastore.download_data(model_path, local_directory=local_directory, overwrite=overwrite)
        elif model_source.startswith("swift://cscs.ch/"):
            # ***** Handles CSCS private urls *****
            datastore = URI_SCHEME_MAP["swift"]()
            fileList = datastore.download_data(str(model_source), local_directory=local_directory, overwrite=overwrite)
        elif model_source.startswith("https://object.cscs.ch/"):
            # ***** Handles CSCS public urls (file or folder) *****
            model_source = urljoin(model_source, urlparse(model_source).path) # remove query params from URL, e.g. `?bluenaas=true`
            req = requests.head(model_source)
            if req.status_code == 200:
                if "directory" in req.headers["Content-Type"]:
                    base_source = "/".join(model_source.split("/")[:6])
                    model_rel_source = "/".join(model_source.split("/")[6:])
                    dir_name = model_source.split("/")[-1]
                    req = requests.get(base_source)
                    contents = req.text.split("\n")
                    files_match = [os.path.join(base_source, x) for x in contents if x.startswith(model_rel_source) and "." in x]
                    local_directory = os.path.join(local_directory, dir_name)
                    Path(local_directory).mkdir(parents=True, exist_ok=True)
                else:
                    files_match = [model_source]
                datastore = URI_SCHEME_MAP["http"]()
                fileList = datastore.download_data(files_match, local_directory=local_directory, overwrite=overwrite)
            else:
                raise FileNotFoundError("Requested file/folder not found: {}".format(model_source))
        else:
            # ***** Handles ModelDB and external urls (only file; not folder) *****
            datastore = URI_SCHEME_MAP["http"]()
            fileList = datastore.download_data(str(model_source), local_directory=local_directory, overwrite=overwrite)

        if len(fileList) > 0:
            flag = True
            if len(fileList) == 1:
                outpath = fileList[0]
            else:
                outpath = os.path.dirname(os.path.commonprefix(fileList))
            return os.path.abspath(outpath.encode('ascii'))
        else:
            print("\nSource location: {}".format(model_source))
            print("Could not download the specified file(s)!")
            return None

    def get_BPO_model(self, instance_path="", instance_id="", model_id="", alias="", version="", local_directory=".", overwrite=False, list_req_caps=[]):
        """Retrieve a specific BluePyOpt model instance as a Python class (sciunit.Model instance).

        The desired BluePyOpt model instance can be specified 
        in the following ways (in order of priority):

        1. load from a local JSON file specified via `instance_path`
        2. specify `instance_id` corresponding to model instance in model catalog
        3. specify `model_id` and `version`
        4. specify `alias` (of the model) and `version`

        Parameters
        ----------
        instance_path : string
            Location of local JSON file with model instance metadata.
        instance_id : UUID
            System generated unique identifier associated with model instance.
        model_id : UUID
            System generated unique identifier associated with model description.
        alias : string
            User-assigned unique identifier associated with model description.
        version : string
            User-assigned identifier (unique for each model) associated with model instance.
        local_directory : string
            Directory path (relative/absolute) where model instance files should be downloaded and saved. Default is current location.
        overwrite: Boolean
            Indicates if any existing file at the target location should be overwritten; default is set to False
        list_req_caps: list
            List of capabilities that should be sub-classed by the model instance

        Returns
        -------
        sciunit.Model
            Returns a :class:`sciunit.Model` instance.

        Note
        ----
        This method is for use exclusively with models produced via BluePyOpt.
        For more info on BluePyOpt, please visit: https://github.com/BlueBrain/BluePyOpt

        Examples
        --------
        >>> model = model_catalog.get_BPO_model(instance_id="a035f2b2-fe2e-42fd-82e2-4173a304263b")
        """

        try:
            from zipfile import ZipFile
        except ImportError:
            print("Please install the following package: zipfile")
            return

        # get model instance info and metadata from source URL query parameter (`use_cell`)
        model_inst_info = self.get_model_instance(instance_path=instance_path, instance_id=instance_id, model_id=model_id, alias=alias, version=version)
        use_cell = parse_qs(urlparse(model_inst_info["source"]).query)["use_cell"][0]
        # get model info such as name
        model_info = self.get_model(model_id=model_inst_info["model_id"])

        # download model source code; it will be a zip file for BluePyOpt models
        file_path =  self.download_model_instance(instance_id=model_inst_info["id"], local_directory=local_directory, overwrite=overwrite)
        file_path = file_path.decode("utf-8") # converting from bytes object to string
        if file_path == None:
            raise FileNotFoundError("Requested model could not be found: {}".format(model_source))

        # extract the model zip file locally
        try:
            with ZipFile(file_path, 'r') as zipObj:
                zipObj.extractall(local_directory)        
            model_path = os.path.join(local_directory, os.path.basename(file_path).split(".")[0])
        except Exception as e:
            print("Unable to extract model zip file: {} -> {}".format(file_path, e))

        # instantiate model using ModelLoader_BPO class
        ModelLoader_BPO_Class = get_BPO_Model_WithCapabilities(list_req_caps=list_req_caps, name=model_info["name"], model_dir=model_path, SomaSecList_name = "somatic", use_cell=use_cell)
        cell_model = ModelLoader_BPO_Class()

        # # needed to overcome issue with pickling local classes
        # for more, see: https://stackoverflow.com/a/16281779/7383605
        cell_model.__class__ = ModelLoader_BPO
        # above class does not have any of the specified capabilities, so we need to add those here
        # for more, see: https://stackoverflow.com/q/7408216/7383605
        cell_model.__class__.__bases__ = cell_model.__class__.__bases__ + tuple(list_req_caps)
        
        cell_model.model_instance_uuid = model_inst_info["id"]
        cell_model.model_uuid = model_info["id"]                  # not essential; extra info
        cell_model.model_version = model_inst_info["version"]     # not essential; extra info
        return cell_model

    def list_model_instances(self, instance_path="", model_id="", alias=""):
        """Retrieve list of model instances belonging to a specified model.

        This can be retrieved in the following ways (in order of priority):

        1. load from a local JSON file specified via `instance_path`
        2. specify `model_id`
        3. specify `alias` (of the model)

        Parameters
        ----------
        instance_path : string
            Location of local JSON file with model instance metadata.
        model_id : UUID
            System generated unique identifier associated with model description.
        alias : string
            User-assigned unique identifier associated with model description.

        Returns
        -------
        list
            List of dicts containing information about the model instances.

        Examples
        --------
        >>> model_instances = model_catalog.list_model_instances(alias="Model vB2")
        """

        if instance_path == "" and model_id == "" and alias == "":
            raise Exception("instance_path or model_id or alias needs to be provided for finding model instances.")
        if instance_path and os.path.isfile(instance_path):
            # instance_path is a local path
            with open(instance_path) as fp:
                model_instances_json = json.load(fp)
        else:
            if model_id:
                url = self.url + "/models/" + model_id + "/instances/?size=100000"
            else:
                url = self.url + "/models/" + quote(alias) + "/instances/?size=100000"
            model_instances_json = requests.get(url, auth=self.auth, verify=self.verify)
        if model_instances_json.status_code != 200:
            handle_response_error("Error in retrieving model instances", model_instances_json)
        model_instances_json = model_instances_json.json()
        return model_instances_json

    def add_model_instance(self, model_id="", alias="", source="", version="", description="", parameters="", code_format="", hash="", morphology=""):
        """Register a new model instance.

        This allows to add a new instance of an existing model in the model catalog.
        The `model_id` needs to be specified as input parameter.

        Parameters
        ----------
        model_id : UUID
            System generated unique identifier associated with model description.
        alias : string
            User-assigned unique identifier associated with model description.
        source : string
            Path to model source code repository (e.g. github).
        version : string
            User-assigned identifier (unique for each model) associated with model instance.
        description : string, optional
            Text describing this specific model instance.
        parameters : string, optional
            Any additional parameters to be submitted to model, or used by it, at runtime.
        code_format : string, optional
            Indicates the language/platform in which the model was developed.
        hash : string, optional
            Similar to a checksum; can be used to identify model instances from their implementation.
        morphology : string / list, optional
            URL(s) to the morphology file(s) employed in this model.

        Returns
        -------
        UUID
            UUID of the model instance that has been created.

        Note
        ----
        * `alias` is not currently implemented in the API; kept for future use.
        * TODO: Either model_id or alias needs to be provided, with model_id taking precedence over alias.

        Examples
        --------
        >>> instance_id = model_catalog.add_model_instance(model_id="196b89a3-e672-4b96-8739-748ba3850254",
                                                  source="https://www.abcde.com",
                                                  version="1.0",
                                                  description="basic model variant",
                                                  parameters="",
                                                  code_format="py",
                                                  hash="",
                                                  morphology="")
        """

        instance_data = locals()
        instance_data.pop("self")

        for key, val in instance_data.items():
            if val == "":
                instance_data[key] = None

        if model_id == "" and alias == "":
            raise Exception("Model ID needs to be provided for finding the model.")
            #raise Exception("Model ID or alias needs to be provided for finding the model.")
        elif model_id != "":
            url = self.url + "/models/" + model_id + "/instances/"
        else:
            url = self.url + "/models/" + quote(alias) + "/instances/"
        headers = {'Content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(instance_data),
                                 auth=self.auth, headers=headers,
                                 verify=self.verify)
        if response.status_code == 201:
            return response.json()["id"]
        else:
            handle_response_error("Error in adding model instance", response)

    def find_model_instance_else_add(self, model_obj):
        """Find existing model instance; else create a new instance

        This checks if the input model object has an associated model instance.
        If not, a new model instance is created.

        Parameters
        ----------
        model_obj : object
            Python object representing a model.

        Returns
        -------
        UUID
            UUID of the existing or created model instance.

        Note
        ----
        * `model_obj` is expected to contain the attribute `model_instance_uuid`,
          or both the attributes `model_uuid` and `model_version`.

        Examples
        --------
        >>> instance_id = model_catalog.find_model_instance_else_add(model)
        """

        if not getattr(model_obj, "model_instance_uuid", None):
            # check that the model is registered with the model registry.
            if not hasattr(model_obj, "model_uuid"):
                raise AttributeError("Model object does not have a 'model_uuid' attribute. "
                                     "Please register it with the Validation Framework and add the 'model_uuid' to the model object.")
            if not hasattr(model_obj, "model_version"):
                raise AttributeError("Model object does not have a 'model_version' attribute")
            try:
                model_instance_uuid = self.get_model_instance(model_id=model_obj.model_uuid,
                                                              version=model_obj.model_version)['id']
            except Exception:  # probably the instance doesn't exist (todo: distinguish from other reasons for Exception)
                # so we create a new instance
                model_instance_uuid = self.add_model_instance(model_id=model_obj.model_uuid,
                                                            source=getattr(model_obj, "remote_url", ""),
                                                            version=model_obj.model_version,
                                                            parameters=getattr(model_obj, "parameters", ""))
        else:
            model_instance_uuid = model_obj.model_instance_uuid
        return model_instance_uuid

    def edit_model_instance(self, instance_id="", model_id="", alias="", source=None, version=None, description=None, parameters=None, code_format=None, hash=None, morphology=None):
        """Edit an existing model instance.

        This allows to edit an instance of an existing model in the model catalog.
        The model instance can be specified in the following ways (in order of priority):

        1. specify `instance_id` corresponding to model instance in model catalog
        2. specify `model_id` and `version`
        3. specify `alias` (of the model) and `version`

        Only the parameters being updated need to be specified. You cannot
        edit the model `version` in the latter two cases. To do so,
        you must employ the first option above. You can retrieve the `instance_id`
        via :meth:`get_model_instance`

        Parameters
        ----------
        instance_id : UUID
            System generated unique identifier associated with model instance.
        model_id : UUID
            System generated unique identifier associated with model description.
        alias : string
            User-assigned unique identifier associated with model description.
        source : string
            Path to model source code repository (e.g. github).
        version : string
            User-assigned identifier (unique for each model) associated with model instance.
        description : string, optional
            Text describing this specific model instance.
        parameters : string, optional
            Any additional parameters to be submitted to model, or used by it, at runtime.
        code_format : string, optional
            Indicates the language/platform in which the model was developed.
        hash : string, optional
            Similar to a checksum; can be used to identify model instances from their implementation.
        morphology : string / list, optional
            URL(s) to the morphology file(s) employed in this model.

        Returns
        -------
        UUID
            UUID of the model instance that has been edited.

        Examples
        --------
        >>> instance_id = model_catalog.edit_model_instance(instance_id="fd1ab546-80f7-4912-9434-3c62af87bc77",
                                                source="https://www.abcde.com",
                                                version="1.0",
                                                description="passive model variant",
                                                parameters="",
                                                code_format="py",
                                                hash="",
                                                morphology="")
        """

        if instance_id == "" and (model_id == "" or not version) and (alias == "" or not version):
            raise Exception("instance_id or (model_id, version) or (alias, version) needs to be provided for finding a model instance.")

        instance_data = {key:value for key, value in locals().items()
                         if value is not None}

        # assign existing values for parameters not specified
        if instance_id:
            url = self.url + "/models/query/instances/" + instance_id
        else:
            model_identifier = quote(model_id or alias)
            response0 = requests.get(self.url + f"/models/{model_identifier}/instances/?version={version}",
                                     auth=self.auth, verify=self.verify)
            if response0.status_code != 200:
                raise Exception("Invalid model_id, alias and/or version")
            model_data = response0.json()[0]  # to fix: in principle, can have multiple instances with same version but different parameters
            url = self.url + f"/models/{model_identifier}/instances/{model_data['id']}"

        for key in ["self", "instance_id", "alias", "model_id"]:
            instance_data.pop(key)

        headers = {'Content-type': 'application/json'}
        response = requests.put(url, data=json.dumps(instance_data), auth=self.auth, headers=headers,
                                verify=self.verify)
        if response.status_code == 200:
            return response.json()["id"]
        else:
            handle_response_error("Error in editing model instance at {}".format(url), response)

    def delete_model_instance(self, instance_id="", model_id="", alias="", version=""):
        """ONLY FOR SUPERUSERS: Delete an existing model instance.

        This allows to delete an instance of an existing model in the model catalog.
        The model instance can be specified in the following ways (in order of priority):

        1. specify `instance_id` corresponding to model instance in model catalog
        2. specify `model_id` and `version`
        3. specify `alias` (of the model) and `version`

        Parameters
        ----------
        instance_id : UUID
            System generated unique identifier associated with model instance.
        model_id : UUID
            System generated unique identifier associated with model description.
        alias : string
            User-assigned unique identifier associated with model description.
        version : string
            User-assigned unique identifier associated with model instance.

        Note
        ----
        * This feature is only for superusers!

        Examples
        --------
        >>> model_catalog.delete_model_instance(model_id="8c7cb9f6-e380-452c-9e98-e77254b088c5")
        >>> model_catalog.delete_model_instance(alias="B1", version="1.0")
        """

        if instance_id == "" and (model_id == "" or not version) and (alias == "" or not version):
            raise Exception("instance_id or (model_id, version) or (alias, version) needs to be provided for finding a model instance.")

        if instance_id:
            id = instance_id    # as needed by API
        if alias:
            model_alias = alias # as needed by API

        if instance_id:
            if model_id:
                url = self.url + "/models/" + model_id + "/instances/" + instance_id
            else:
                url = self.url + "/models/query/instances/" + instance_id
        else:
            raise NotImplementedError("Need to retrieve instance to get id")
        model_instance_json = requests.delete(url, auth=self.auth, verify=self.verify)
        if model_instance_json.status_code == 403:
            handle_response_error("Only SuperUser accounts can delete data", model_instance_json)
        elif model_instance_json.status_code != 200:
            handle_response_error("Error in deleting model instance", model_instance_json)


def get_BPO_Model_WithCapabilities(list_req_caps=[], name="model", model_dir=None, SomaSecList_name=None, use_cell=None):
    class ModelLoader_BPO(sciunit.Model, *list_req_caps):
        def __init__(self, name=name, model_dir=model_dir, SomaSecList_name=SomaSecList_name, use_cell=use_cell):
            """ Constructor. """
            self.name = name
            self.SomaSecList_name = SomaSecList_name
            self.use_cell = use_cell

            self.morph_full_path = None
            self.find_section_lists = True

            self.setup_dirs(model_dir)
            self.setup_values()
            self.compile_mod_files_BPO()

            if not use_cell:
                raise Exception("`use_cell` parameter is not specified for this BluePyOpt model. Cannot proceed!")

        def compile_mod_files_BPO(self):

            if self.modelpath is None:
                raise Exception("Please give the path to the mod files (eg. model.modelpath = \"/home/models/CA1_pyr/mechanisms/\")")

            if os.path.isfile(self.modelpath + self.libpath) is False:
                os.system("cd " + self.modelpath + "; nrnivmodl")

        def load_mod_files(self):

            h.nrn_load_dll(str(self.modelpath + self.libpath))

        def setup_dirs(self, model_dir=""):

            base_path = os.path.join(model_dir, self.name)
            if os.path.exists(base_path) or os.path.exists(base_path+".zip"):     # If the model_dir is the outer directory, that contains the zip
                self.base_path = base_path
                if not os.path.exists(self.base_path):
                    file_ref = zipfile.ZipFile(self.base_path+".zip", 'r')
                    file_ref.extractall(model_dir)
                    file_ref.close()
            else:                                                                   # If model_dir is the inner directory (already unzipped)
                self.base_path = model_dir
                split_dir = model_dir.split('/')
                del split_dir[-1]
                outer_dir = '/'.join(split_dir)

            self.morph_path = "\"" + self.base_path + "/morphology\""

            for file_name in os.listdir(self.morph_path[1:-1]):
                self.morph_full_path = self.morph_path[1:-1]+ '/' + file_name
                break


            # path to mod files
            self.modelpath = self.base_path + "/mechanisms/"

            # if this doesn't exist mod files are automatically compiled
            self.libpath = "x86_64/.libs/libnrnmech.so.0"

            self.hocpath = self.base_path + "/checkpoints/" + str(self.use_cell)

            if not os.path.exists(self.hocpath):
                self.hocpath = None
                for file in os.listdir(self.base_path + "/checkpoints/"):
                    if file.startswith("cell") and file.endswith(".hoc"):
                        self.hocpath = self.base_path + "/checkpoints/" + file
                        print("Model = " + self.name + ": cell.hoc not found in /checkpoints; using " + file)
                        break
                if not os.path.exists(self.hocpath):
                    raise IOError("No appropriate .hoc file found in /checkpoints")

            self.base_directory = self.base_path +'/validation_results/'

        def setup_values(self):

            # get model template name
            # could also do this via other JSON, but morph.json seems dedicated for template info
            with open(os.path.join(self.base_path, "config", "morph.json")) as morph_file:
                template_name = list(json.load(morph_file, object_pairs_hook=collections.OrderedDict).keys())[0]

            self.template_name = template_name + "(" + self.morph_path+")"

            # access model config info
            with open(os.path.join(self.base_path, "config", "parameters.json")) as params_file:
                params_data = json.load(params_file, object_pairs_hook=collections.OrderedDict)

            # extract v_init and celsius (if available)
            v_init = None
            celsius = None
            try:
                for item in params_data[template_name]["fixed"]["global"]:
                    # would have been better if info was stored inside a dict (rather than a list)
                    if "v_init" in item:
                        item.remove("v_init")
                        v_init = float(item[0])
                    if "celsius" in item:
                        item.remove("celsius")
                        celsius = float(item[0])
            except:
                pass
            if v_init == None:
                self.v_init = -70.0
                print("Could not find model specific info for `v_init`; using default value of {} mV".format(str(self.v_init)))
            else:
                self.v_init = v_init
            if celsius == None:
                self.celsius = 34.0
                print("Could not find model specific info for `celsius`; using default value of {} degrees Celsius".format(str(self.celsius)))
            else:
                self.celsius = celsius
            self.trunk_origin = [0.5]

        def initialise(self):

            save_stdout=sys.stdout                   #To supress hoc output from Jupyter notebook 
            # sys.stdout=open("trash","w")
            sys.stdout=open('/dev/stdout', 'w')      #rather print it to the console 

            self.load_mod_files()

            if self.hocpath is None:
                raise Exception("Please give the path to the hoc file (eg. model.modelpath = \"/home/models/CA1_pyr/CA1_pyr_model.hoc\")")


            h.load_file("stdrun.hoc")
            h.load_file(str(self.hocpath))

            if self.soma is None and self.SomaSecList_name is None:
                raise Exception("Please give the name of the soma (eg. model.soma=\"soma[0]\"), or the name of the somatic section list (eg. model.SomaSecList_name=\"somatic\")")

            try:
                if self.template_name is not None and self.SomaSecList_name is not None:

                    h('objref testcell')
                    h('testcell = new ' + self.template_name)

                    exec('self.soma_ = h.testcell.'+ self.SomaSecList_name)

                    for s in self.soma_ :
                        self.soma = h.secname()

                elif self.template_name is not None and self.SomaSecList_name is None:
                    h('objref testcell')
                    h('testcell = new ' + self.template_name)
                    # in this case self.soma is set in the jupyter notebook
                elif self.template_name is None and self.SomaSecList_name is not None:
                    exec('self.soma_ = h.' +  self.SomaSecList_name)
                    for s in self.soma_ :
                        self.soma = h.secname()
                # if both is None, the model is loaded, self.soma will be used
            except AttributeError:
                print ("The provided model template is not accurate. Please verify!")
            except Exception:
                print ("If a model template is used, please give the name of the template to be instantiated (with parameters, if any). Eg. model.template_name=CCell(\"morph_path\")")
                raise


            sys.stdout=save_stdout    #setting output back to normal 

        def inject_current(self, amp, delay, dur, section_stim, loc_stim, section_rec, loc_rec):

            self.initialise()

            if self.cvode_active:
                h.cvode_active(1)
            else:
                h.cvode_active(0)

            stim_section_name = self.translate(section_stim, distance=0)
            rec_section_name = self.translate(section_rec, distance=0)
            #exec("self.sect_loc=h." + str(self.soma)+"("+str(0.5)+")")

            exec("self.sect_loc_stim=h." + str(stim_section_name)+"("+str(loc_stim)+")")

            print("- running amplitude: " + str(amp)  + " on model: " + self.name + " at: " + stim_section_name + "(" + str(loc_stim) + ")")

            self.stim = h.IClamp(self.sect_loc_stim)

            self.stim.amp = amp
            self.stim.delay = delay
            self.stim.dur = dur

            #print "- running model", self.name, "stimulus at: ", str(self.soma), "(", str(0.5), ")"

            exec("self.sect_loc_rec=h." + str(rec_section_name)+"("+str(loc_rec)+")")

            rec_t = h.Vector()
            rec_t.record(h._ref_t)

            rec_v = h.Vector()
            rec_v.record(self.sect_loc_rec._ref_v)

            h.stdinit()

            dt = 0.025
            h.dt = dt
            h.steps_per_ms = 1/dt
            h.v_init = self.v_init#-65

            h.celsius = self.celsius
            h.init()
            h.tstop = delay + dur + 200
            h.run()

            t = numpy.array(rec_t)
            v = numpy.array(rec_v)

            return t, v

        def inject_current_record_respons_multiple_loc(self, amp, delay, dur, section_stim, loc_stim, dend_locations):

            self.initialise()

            if self.cvode_active:
                h.cvode_active(1)
            else:
                h.cvode_active(0)

            stim_section_name = self.translate(section_stim, distance=0)
            #rec_section_name = self.translate(section_rec, distance=0)
            #exec("self.sect_loc=h." + str(self.soma)+"("+str(0.5)+")")

            exec("self.sect_loc_stim=h." + str(stim_section_name)+"("+str(loc_stim)+")")
            exec("self.sect_loc_rec=h." + str(stim_section_name)+"("+str(loc_stim)+")")

            print("- running amplitude: " + str(amp)  + " on model: " + self.name + " at: " + stim_section_name + "(" + str(loc_stim) + ")")

            self.stim = h.IClamp(self.sect_loc_stim)

            self.stim.amp = amp
            self.stim.delay = delay
            self.stim.dur = dur

            rec_t = h.Vector()
            rec_t.record(h._ref_t)

            rec_v_stim = h.Vector()
            rec_v_stim.record(self.sect_loc_rec._ref_v)

            rec_v = []
            v = collections.OrderedDict()
            self.dend_loc_rec =[]

            '''
            for i in range(0,len(dend_loc)):

                exec("self.dend_loc_rec.append(h." + str(dend_loc[i][0])+"("+str(dend_loc[i][1])+"))")
                rec_v.append(h.Vector())
                rec_v[i].record(self.dend_loc_rec[i]._ref_v)
                #print self.dend_loc[i]
            '''
            #print dend_locations
            for key, value in dend_locations.items():
                for i in range(len(dend_locations[key])):
                    exec("self.dend_loc_rec.append(h." + str(dend_locations[key][i][0])+"("+str(dend_locations[key][i][1])+"))")
                    rec_v.append(h.Vector())

            for i in range(len(self.dend_loc_rec)):
                rec_v[i].record(self.dend_loc_rec[i]._ref_v)
                #print self.dend_loc[i]

            h.stdinit()

            dt = 0.025
            h.dt = dt
            h.steps_per_ms = 1/dt
            h.v_init = self.v_init#-65

            h.celsius = self.celsius
            h.init()
            h.tstop = delay + dur + 200
            h.run()

            t = numpy.array(rec_t)
            v_stim = numpy.array(rec_v_stim)

            '''
            for i in range(0,len(dend_loc)):
                v.append(numpy.array(rec_v[i]))
            '''

            i = 0
            for key, value in dend_locations.items():
                v[key] = collections.OrderedDict()
                for j in range(len(dend_locations[key])):
                    loc_key = (dend_locations[key][j][0],dend_locations[key][j][1]) # list can not be a key, but tuple can
                    v[key][loc_key] = numpy.array(rec_v[i])     # the list that specifies dendritic location will be a key too.
                    i+=1

            return t, v_stim, v

        def classify_apical_point_sections(self, icell):

            import os
            import neurom as nm
            from hippounit import classify_apical_sections as cas

            '''
            for file_name in os.listdir(self.morph_path[1:-1]):
                filename = self.morph_path[1:-1]+ '/' + file_name
                break
            '''

            morph = nm.load_neuron(self.morph_full_path)

            apical_point_sections = cas.multiple_apical_points(morph)

            sections = cas.get_list_of_diff_section_types(morph, apical_point_sections)

            apical_trunk_isections = cas.get_neuron_isections(icell, sections['trunk'])
            #print sorted(apical_trunk_isections)

            apical_tuft_isections = cas.get_neuron_isections(icell, sections['tuft'])
            #print sorted(apical_tuft_isections)

            oblique_isections = cas.get_neuron_isections(icell, sections['obliques'])
            #print sorted(oblique_isections)

            return apical_trunk_isections, apical_tuft_isections, oblique_isections

        def find_trunk_locations(self, distances, tolerance, trunk_origin):

            if self.TrunkSecList_name is None and not self.find_section_lists:
                raise NotImplementedError("Please give the name of the section list containing the trunk sections. (eg. model.TrunkSecList_name=\"trunk\" or set model.find_section_lists to True)")

            #locations={}
            locations=collections.OrderedDict()
            actual_distances ={}
            dend_loc=[]

            if self.TrunkSecList_name is not None:
                self.initialise()

                if self.template_name is not None:
                    exec('self.trunk=h.testcell.' + self.TrunkSecList_name)
                else:
                    exec('self.trunk=h.' + self.TrunkSecList_name)


            if self.find_section_lists:

                self.initialise()

                if self.template_name is not None:
                    exec('self.icell=h.testcell')

                apical_trunk_isections, apical_tuft_isections, oblique_isections = self.classify_apical_point_sections(self.icell)

                self.trunk = []
                for i in range(len(apical_trunk_isections)):
                    exec('self.sec = h.testcell.apic[' + str(apical_trunk_isections[i]) + ']')
                    self.trunk.append(self.sec)

            for sec in self.trunk:
                #for seg in sec:
                if not trunk_origin:
                    h(self.soma + ' ' +'distance(0,1)') # For apical dendrites the default reference point is the end of the soma (point 1)
                elif len(trunk_origin) == 1:
                    h(self.soma + ' ' +'distance(0,'+str(trunk_origin[0]) + ')') # Trunk origin point (reference for distance measurement) can be
                elif len(trunk_origin) == 2:
                    h(trunk_origin[0] + ' ' +'distance(0,'+str(trunk_origin[1]) + ')') # Trunk origin point (reference for distance measurement) can be added by the user as an argument to the test
                #print sec.name()
                if self.find_section_lists:
                    h('access ' + sec.name())

                for seg in sec:
                    #print 'SEC: ', sec.name(),
                    #print 'SEG.X', seg.x
                    #print 'DIST', h.distance(seg.x)
                    #print 'DIST0', h.distance(0)
                    #print 'DIST1', h.distance(1)
                    for i in range(0, len(distances)):
                        locations.setdefault(distances[i], []) # if this key doesn't exist it is added with the value: [], if exists, value not altered
                        if h.distance(seg.x) < (distances[i] + tolerance) and h.distance(seg.x) > (distances[i]- tolerance): # if the seq is between distance +- 20
                            #print 'SEC: ', sec.name()
                            #print 'seg.x: ', seg.x
                            #print 'DIST: ', h.distance(seg.x)
                            locations[distances[i]].append([sec.name(), seg.x])
                            actual_distances[sec.name(), seg.x] = h.distance(seg.x)

            #print actual_distances
            return locations, actual_distances

        def get_random_locations(self, num, seed, dist_range, trunk_origin):

            if self.TrunkSecList_name is None and not self.find_section_lists:
                raise NotImplementedError("Please give the name of the section list containing the trunk sections. (eg. model.TrunkSecList_name=\"trunk\" or set model.find_section_lists to True)")

            locations=[]
            locations_distances = {}

            if self.TrunkSecList_name is not None:
                self.initialise()

                if self.template_name is not None:
                    exec('self.trunk=h.testcell.' + self.TrunkSecList_name)

                else:
                    exec('self.trunk=h.' + self.TrunkSecList_name)

            if self.find_section_lists:

                self.initialise()

                if self.template_name is not None:
                    exec('self.icell=h.testcell')

                apical_trunk_isections, apical_tuft_isections, oblique_isections = self.classify_apical_point_sections(self.icell)
                apical_trunk_isections = sorted(apical_trunk_isections) # important to keep reproducability

                self.trunk = []
                for i in range(len(apical_trunk_isections)):
                    exec('self.sec = h.testcell.apic[' + str(apical_trunk_isections[i]) + ']')
                    self.trunk.append(self.sec)
            else:
                self.trunk = list(self.trunk)

            kumm_length_list = []
            kumm_length = 0
            num_of_secs = 0


            for sec in self.trunk:
                #print sec.L
                num_of_secs += sec.nseg
                kumm_length += sec.L
                kumm_length_list.append(kumm_length)
            #print 'kumm' ,kumm_length_list
            #print num_of_secs

            if num > num_of_secs:
                for sec in self.trunk:
                    if not trunk_origin:
                        h(self.soma + ' ' +'distance(0,1)') # For apical dendrites the default reference point is the end of the soma (point 1)
                    elif len(trunk_origin) == 1:
                        h(self.soma + ' ' +'distance(0,'+str(trunk_origin[0]) + ')') # Trunk origin point (reference for distance measurement) can be
                    elif len(trunk_origin) == 2:
                        h(trunk_origin[0] + ' ' +'distance(0,'+str(trunk_origin[1]) + ')') # Trunk origin point (reference for distance measurement) can be added by the user as an argument to the test
                    h('access ' + sec.name())
                    for seg in sec:
                        if h.distance(seg.x) > dist_range[0] and h.distance(seg.x) < dist_range[1]:     # if they are out of the distance range they wont be used
                            locations.append([sec.name(), seg.x])
                            locations_distances[sec.name(), seg.x] = h.distance(seg.x)
                #print 'Dendritic locations to be tested (with their actual distances):', locations_distances

            else:

                norm_kumm_length_list = [i/kumm_length_list[-1] for i in kumm_length_list]
                #print 'norm kumm',  norm_kumm_length_list

                import random

                _num_ = num  # _num_ will be changed
                num_iterations = 0

                while len(locations) < num and num_iterations < 50 :
                    #print 'seed ', seed
                    random.seed(seed)
                    rand_list = [random.random() for j in range(_num_)]
                    #print rand_list

                    for rand in rand_list:
                        #print 'RAND', rand
                        for i in range(len(norm_kumm_length_list)):
                            if rand <= norm_kumm_length_list[i] and (rand > norm_kumm_length_list[i-1] or i==0):
                                #print norm_kumm_length_list[i-1]
                                #print norm_kumm_length_list[i]
                                seg_loc = (rand - norm_kumm_length_list[i-1]) / (norm_kumm_length_list[i] - norm_kumm_length_list[i-1])
                                #print 'seg_loc', seg_loc
                                segs = [seg.x for seg in self.trunk[i]]
                                d_seg = [abs(seg.x - seg_loc) for seg in self.trunk[i]]
                                min_d_seg = numpy.argmin(d_seg)
                                segment = segs[min_d_seg]
                                #print 'segment', segment
                                if not trunk_origin:
                                    h(self.soma + ' ' +'distance(0,1)') # For apical dendrites the default reference point is the end of the soma (point 1)
                                elif len(trunk_origin) == 1:
                                    h(self.soma + ' ' +'distance(0,'+str(trunk_origin[0]) + ')') # Trunk origin point (reference for distance measurement) can be
                                elif len(trunk_origin) == 2:
                                    h(trunk_origin[0] + ' ' +'distance(0,'+str(trunk_origin[1]) + ')') # Trunk origin point (reference for distance measurement) can be added by the user as an argument to the test
                                h('access ' + self.trunk[i].name())
                                if [self.trunk[i].name(), segment] not in locations and h.distance(segment) >= dist_range[0] and h.distance(segment) < dist_range[1]:
                                    locations.append([self.trunk[i].name(), segment])
                                    locations_distances[self.trunk[i].name(), segment] = h.distance(segment)
                    _num_ = num - len(locations)
                    #print '_num_', _num_
                    seed += 10
                    num_iterations += 1
                    #print len(locations)
            #print 'Dendritic locations to be tested (with their actual distances):', locations_distances

            return locations, locations_distances

        def find_good_obliques(self, trunk_origin):
            """Used in ObliqueIntegrationTest"""

            if (self.ObliqueSecList_name is None or self.TrunkSecList_name is None) and not self.find_section_lists:
                raise NotImplementedError("Please give the names of the section lists containing the oblique dendrites and the trunk sections. (eg. model.ObliqueSecList_name=\"obliques\", model.TrunkSecList_name=\"trunk\" or set model.find_section_lists to True)")


            #self.initialise()

            good_obliques = h.SectionList()
            dend_loc=[]

            if self.TrunkSecList_name is not None and self.ObliqueSecList_name is not None:
                self.initialise()

                if self.template_name is not None:

                    exec('self.oblique_dendrites=h.testcell.' + self.ObliqueSecList_name)   # so we can have the name of the section list as a string given by the user
                    #exec('oblique_dendrites = h.' + oblique_seclist_name)
                    exec('self.trunk=h.testcell.' + self.TrunkSecList_name)
                else:
                    exec('self.oblique_dendrites=h.' + self.ObliqueSecList_name)   # so we can have the name of the section list as a string given by the user
                    #exec('oblique_dendrites = h.' + oblique_seclist_name)
                    exec('self.trunk=h.' + self.TrunkSecList_name)

            if self.find_section_lists:

                self.initialise()

                if self.template_name is not None:
                    exec('self.icell=h.testcell')

                apical_trunk_isections, apical_tuft_isections, oblique_isections = self.classify_apical_point_sections(self.icell)

                self.trunk = []
                for i in range(len(apical_trunk_isections)):
                    exec('self.sec = h.testcell.apic[' + str(apical_trunk_isections[i]) + ']')
                    self.trunk.append(self.sec)

                self.oblique_dendrites = []
                for i in range(len(oblique_isections)):
                    exec('self.sec = h.testcell.apic[' + str(oblique_isections[i]) + ']')
                    self.oblique_dendrites.append(self.sec)

            good_obliques_added = 0

            while good_obliques_added == 0 and self.max_dist_from_soma <= 190:
                for sec in self.oblique_dendrites:
                    if not trunk_origin:
                        h(self.soma + ' ' +'distance(0,1)') # For apical dendrites the default reference point is the end of the soma (point 1)
                    elif len(trunk_origin) == 1:
                        h(self.soma + ' ' +'distance(0,'+str(trunk_origin[0]) + ')') # Trunk origin point (reference for distance measurement) can be
                    elif len(trunk_origin) == 2:
                        h(trunk_origin[0] + ' ' +'distance(0,'+str(trunk_origin[1]) + ')') # Trunk origin point (reference for distance measurement) can be added by the user as an argument to the test
                    if self.find_section_lists:
                        h('access ' + sec.name())
                    parent = h.SectionRef(sec).parent
                    child_num = h.SectionRef(sec).nchild()
                    dist = h.distance(0)
                    #print 'SEC: ', sec.name()
                    #print 'NCHILD: ', child_num
                    #print 'PARENT: ', parent.name()
                    #print 'DIST: ', h.distance(0)
                    """
                    for trunk_sec in trunk:
                        if self.find_section_lists:
                            h('access ' + trunk_sec.name())
                        if h.issection(parent.name()) and dist < self.max_dist_from_soma and child_num == 0:   # true if string (parent.name()) is contained in the name of the currently accessed section.trunk_sec is the accessed section,
                            #print sec.name(), parent.name()
                            h('access ' + sec.name())         # only currently accessed section can be added to hoc SectionList
                            good_obliques.append(sec.name())
                            good_obliques_added += 1
                    """
                    if dist < self.max_dist_from_soma and child_num == 0:   # now the oblique section can branch from another oblique section, but it has to be a tip (terminal) section
                        #print sec.name(), parent.name()
                        # print sec.name(), dist
                        h('access ' + sec.name())         # only currently accessed section can be added to hoc SectionList
                        good_obliques.append(sec.name())
                        good_obliques_added += 1
                if good_obliques_added == 0:
                    self.max_dist_from_soma += 15
                    print("Maximum distance from soma was increased by 15 um, new value: " + str(self.max_dist_from_soma))

            for sec in good_obliques:

                dend_loc_prox=[]
                dend_loc_dist=[]
                seg_list_prox=[]
                seg_list_dist=[]

                h(sec.name() + ' ' +'distance()')  #set the 0 point of the section as the origin
                # print(sec.name())


                for seg in sec:
                    # print(seg.x, h.distance(seg.x))
                    if h.distance(seg.x) > 5 and h.distance(seg.x) < 50:
                        seg_list_prox.append(seg.x)
                    if h.distance(seg.x) > 60 and h.distance(seg.x) < 126:
                        seg_list_dist.append(seg.x)

                #print seg_list_prox
                #print seg_list_dist

                if len(seg_list_prox) > 1:
                    s = int(numpy.ceil(len(seg_list_prox)/2.0))
                    dend_loc_prox.append(sec.name())
                    dend_loc_prox.append(seg_list_prox[s])
                    dend_loc_prox.append('prox')
                elif len(seg_list_prox) == 1:
                    dend_loc_prox.append(sec.name())
                    dend_loc_prox.append(seg_list_prox[0])
                    dend_loc_prox.append('prox')

                if len(seg_list_dist) > 1:
                    s = int(numpy.ceil(len(seg_list_dist)/2.0)-1)
                    dend_loc_dist.append(sec.name())
                    dend_loc_dist.append(seg_list_dist[s])
                    dend_loc_dist.append('dist')
                elif len(seg_list_dist) == 1:
                    dend_loc_dist.append(sec.name())
                    dend_loc_dist.append(seg_list_dist[0])
                    dend_loc_dist.append('dist')
                elif len(seg_list_dist) == 0:                # if the dendrite is not long enough to meet the criteria, we stimulate its end
                    dend_loc_dist.append(sec.name())
                    dend_loc_dist.append(0.9)
                    dend_loc_dist.append('dist')

                if dend_loc_prox:
                    dend_loc.append(dend_loc_prox)
                if dend_loc_dist:
                    dend_loc.append(dend_loc_dist)

            #print 'Dendrites and locations to be tested: ', dend_loc

            return dend_loc

        def set_ampa_nmda(self, dend_loc):
            """Currently not used - Used to be used in ObliqueIntegrationTest"""

            ndend, xloc, loc_type = dend_loc

            exec("self.dendrite=h." + ndend)

            self.ampa = h.Exp2Syn(xloc, sec=self.dendrite)
            self.ampa.tau1 = self.AMPA_tau1
            self.ampa.tau2 = self.AMPA_tau2

            exec("self.nmda = h."+self.NMDA_name+"(xloc, sec=self.dendrite)")

            self.ndend = ndend
            self.xloc = xloc

        def set_netstim_netcon(self, interval):
            """Currently not used - Used to be used in ObliqueIntegrationTest"""

            self.ns = h.NetStim()
            self.ns.interval = interval
            self.ns.number = 0
            self.ns.start = self.start

            self.ampa_nc = h.NetCon(self.ns, self.ampa, 0, 0, 0)
            self.nmda_nc = h.NetCon(self.ns, self.nmda, 0, 0, 0)

        def set_num_weight(self, number, AMPA_weight):
            """Currently not used - Used to be used in ObliqueIntegrationTest"""

            self.ns.number = number
            self.ampa_nc.weight[0] = AMPA_weight
            self.nmda_nc.weight[0] =AMPA_weight/self.AMPA_NMDA_ratio

        def run_syn(self, dend_loc, interval, number, AMPA_weight):
            """Currently not used - Used to be used in ObliqueIntegrationTest"""

            self.initialise()

            if self.cvode_active:
                h.cvode_active(1)
            else:
                h.cvode_active(0)

            self.set_ampa_nmda(dend_loc)
            self.set_netstim_netcon(interval)
            self.set_num_weight(number, AMPA_weight)

            exec("self.sect_loc=h." + str(self.soma)+"("+str(0.5)+")")

            # initiate recording
            rec_t = h.Vector()
            rec_t.record(h._ref_t)

            rec_v = h.Vector()
            rec_v.record(self.sect_loc._ref_v)

            rec_v_dend = h.Vector()
            rec_v_dend.record(self.dendrite(self.xloc)._ref_v)

            h.stdinit()

            dt = 0.025
            h.dt = dt
            h.steps_per_ms = 1/ dt
            h.v_init = self.v_init #-80

            h.celsius = self.celsius
            h.init()
            h.tstop = 500
            h.run()

            # get recordings
            t = numpy.array(rec_t)
            v = numpy.array(rec_v)
            v_dend = numpy.array(rec_v_dend)

            return t, v, v_dend

        def set_multiple_ampa_nmda(self, dend_loc, number):
            """Used in ObliqueIntegrationTest"""

            ndend, xloc, loc_type = dend_loc

            exec("self.dendrite=h." + ndend)

            for i in range(number):

                if self.AMPA_name: # if this is given, the AMPA model defined in a mod file is used, else the built in Exp2Syn
                    exec("self.ampa_list[i] = h."+self.AMPA_name+"(xloc, sec=self.dendrite)")
                else:
                    self.ampa_list[i] = h.Exp2Syn(xloc, sec=self.dendrite)
                    self.ampa_list[i].tau1 = self.AMPA_tau1
                    self.ampa_list[i].tau2 = self.AMPA_tau2
                    #print 'The built in Exp2Syn is used as the AMPA component. Tau1 = ', self.AMPA_tau1, ', Tau2 = ', self.AMPA_tau2 , '.'

                if self.NMDA_name: # if this is given, the NMDA model defined in a mod file is used, else the default NMDA model of HippoUnit
                    exec("self.nmda_list[i] = h."+self.NMDA_name+"(xloc, sec=self.dendrite)")
                else:
                    try:
                        exec("self.nmda_list[i] = h."+self.default_NMDA_name+"(xloc, sec=self.dendrite)")
                    except:
                        h.nrn_load_dll(self.default_NMDA_path + self.libpath)
                        exec("self.nmda_list[i] = h."+self.default_NMDA_name+"(xloc, sec=self.dendrite)")

            self.ndend = ndend
            self.xloc = xloc

        def set_multiple_netstim_netcon(self, interval, number, AMPA_weight):
            """Used in ObliqueIntegrationTest"""

            for i in range(number):
                self.ns_list[i] = h.NetStim()
                self.ns_list[i].number = 1
                self.ns_list[i].start = self.start + (i*interval)

                self.ampa_nc_list[i] = h.NetCon(self.ns_list[i], self.ampa_list[i], 0, 0, 0)
                self.nmda_nc_list[i] = h.NetCon(self.ns_list[i], self.nmda_list[i], 0, 0, 0)

                self.ampa_nc_list[i].weight[0] = AMPA_weight
                self.nmda_nc_list[i].weight[0] =AMPA_weight/self.AMPA_NMDA_ratio

        def run_multiple_syn(self, dend_loc, interval, number, weight):
            """Used in ObliqueIntegrationTest"""

            self.ampa_list = [None] * number
            self.nmda_list = [None] * number
            self.ns_list = [None] * number
            self.ampa_nc_list = [None] * number
            self.nmda_nc_list = [None] * number


            self.initialise()

            if self.cvode_active:
                h.cvode_active(1)
            else:
                h.cvode_active(0)

            self.set_multiple_ampa_nmda(dend_loc, number)

            self.set_multiple_netstim_netcon(interval, number, weight)


            exec("self.sect_loc=h." + str(self.soma)+"("+str(0.5)+")")

            # initiate recording
            rec_t = h.Vector()
            rec_t.record(h._ref_t)

            rec_v = h.Vector()
            rec_v.record(self.sect_loc._ref_v)

            rec_v_dend = h.Vector()
            rec_v_dend.record(self.dendrite(self.xloc)._ref_v)

            h.stdinit()

            dt = 0.025
            h.dt = dt
            h.steps_per_ms = 1/dt
            h.v_init = self.v_init #-80

            h.celsius = self.celsius
            h.init()
            h.tstop =500
            h.run()

            # get recordings
            t = numpy.array(rec_t)
            v = numpy.array(rec_v)
            v_dend = numpy.array(rec_v_dend)

            return t, v, v_dend

        def set_Exp2Syn(self, dend_loc, tau1, tau2):
            """Used in PSPAttenuationTest"""

            ndend, xloc = dend_loc

            exec("self.dendrite=h." + ndend)

            self.ampa = h.Exp2Syn(xloc, sec=self.dendrite)
            self.ampa.tau1 = tau1
            self.ampa.tau2 = tau2

            self.ndend = ndend
            self.xloc = xloc

        def set_netstim_netcon_Exp2Syn(self):
            """Used in PSPAttenuationTest"""
            self.start = 300

            self.ns = h.NetStim()
            #self.ns.interval = interval
            #self.ns.number = 0
            self.ns.start = self.start

            self.ampa_nc = h.NetCon(self.ns, self.ampa, 0, 0, 0)

        def set_weight_Exp2Syn(self, weight):
            """Used in PSPAttenuationTest"""

            self.ns.number = 1
            self.ampa_nc.weight[0] = weight

        def run_EPSCstim(self, dend_loc, weight, tau1, tau2):
            """Used in PSPAttenuationTest"""

            self.initialise()

            if self.cvode_active:
                h.cvode_active(1)
            else:
                h.cvode_active(0)

            self.set_Exp2Syn(dend_loc, tau1, tau2)
            self.set_netstim_netcon_Exp2Syn()
            self.set_weight_Exp2Syn(weight)

            exec("self.sect_loc=h." + str(self.soma)+"("+str(0.5)+")")

            # initiate recording
            rec_t = h.Vector()
            rec_t.record(h._ref_t)

            rec_v = h.Vector()
            rec_v.record(self.sect_loc._ref_v)

            rec_v_dend = h.Vector()
            rec_v_dend.record(self.dendrite(self.xloc)._ref_v)

            h.stdinit()

            dt = 0.025
            h.dt = dt
            h.steps_per_ms = 1/dt
            h.v_init = self.v_init #-80

            h.celsius = self.celsius
            h.init()
            h.tstop = 450
            h.run()

            # get recordings
            t = numpy.array(rec_t)
            v = numpy.array(rec_v)
            v_dend = numpy.array(rec_v_dend)

            return t, v, v_dend

    # needed to overcome issue with pickling local classes
    # for more, see: https://stackoverflow.com/a/52892359/7383605
    ModelLoader_BPO.__name__ = "ModelLoader_BPO" 
    ModelLoader_BPO.__qualname__ = "ModelLoader_BPO" 
    return ModelLoader_BPO


# needed to overcome issue with pickling local classes
# for more, see: https://stackoverflow.com/a/52892359/7383605
ModelLoader_BPO = get_BPO_Model_WithCapabilities()


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
