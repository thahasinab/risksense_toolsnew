.. include:: /main/.special.rst
.. raw:: html

    <style> .red {color:red} </style>

.. role:: red


======================================
Risksense Usage
======================================
To use risksense lib package please ensure you import risksense api in your script

.. code-block:: console
     import risksense_api as rsapi

To perform usage of the subject functions you must first create an object and use that object
for subject function definitions

.. code-block:: console
    self.rs=rs_api.RiskSenseApi(self._rs_platform_url, api_key)
where self._rs_platform_url is the url of the platform and apikey is the user apikey

Now post the risksense object  creation, you can use this for function definitions

.. code-block:: console
    rsapi.{subjectname}.{function}