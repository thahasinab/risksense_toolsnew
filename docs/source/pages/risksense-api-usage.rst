.. include:: /main/.special.rst
.. raw:: html

    <style> .red {color:red} </style>

.. role:: red

.. _installation:

======================================
Risksense Usage
======================================
To use risksense lib package please ensure you import risksense api in your script

.. code:: python
     >>> import risksense_api as rsapi

To perform usage of the subject functions you must first create an object and use that object
for subject function definitions

.. code:: python
    >>> self.rs=rs_api.RiskSenseApi(self._rs_platform_url, api_key)
where self._rs_platform_url is the url of the platform and apikey is the user apikey

Now post the risksense object  creation, you can use this for function definitions

.. code:: python
    >>> rsapi.{subjectname}.{function}