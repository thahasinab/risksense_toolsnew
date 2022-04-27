""" *******************************************************************************************************************
|
|  Name        :  __networks.py
|  Module      :  risksense_api
|  Description :  A class to be used for interacting with RiskSense platform networks.
|  Copyright   :  (c) RiskSense, Inc.
|  License     :  Apache-2.0
|
******************************************************************************************************************* """

import json
from .. import Subject
from ..._params import *
from ..._api_request_handler import *


class Notifications(Subject):

    """ Networks class """

    def __init__(self, profile):

        """
        Initialization of Networks object.

        :param profile:     Profile Object
        :type  profile:     _profile

        """

        self.subject_name = "rsNotifications"
        Subject.__init__(self, profile, self.subject_name)

    def listrules(self, clientid):

        """
        Create a new network.

        :param name:            The name for the new network.
        :type  name:            str

        :param network_type:    The network type.  The options are "IP" or "hostname"
        :type  network_type:    str.

        :param clientid:       Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  clientid:       int

        :return:    The new network ID.
        :rtype:     int

        :raises RequestFailed:
        """

        if clientid is None:
            clientid = self._use_default_clientid()[0]

        url = self.api_base_url.format(str(clientid))+"/rules"

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        
        return jsonified_response

    def updatenotifications(self, clientid, rules):

        """
        Update an existing network.

        :param network_id:  The network ID.
        :type  network_id:  int

        :param clientid:   Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  clientid:   int

        :keyword name:          A new name for the network.             (str)
        :keyword network_type:  The network type. "IP" or "hostname".   (str)

        :return:    The network ID
        :rtype:     int

        :raises RequestFailed:
        :raises ValueError:
        """

        if clientid is None:
            clientid = self._use_default_clientid()[0]

        url = self.api_base_url.format(str(clientid)) + "/rules"

        body = {
            "rules": rules
        }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response)

        return jsonified_response

    def markasread(self, clientid,notificationids,markasread):

        """
        Deletes a network.

        :param network_id:  The network ID to be deleted.
        :type  network_id:  str

        :param clientid:   Client ID.  If an ID isn't passed, will use the profile's default Client ID.
        :type  clientid:   int

        :return:    True/False indicating whether or not the operation was successful.
        :rtype:     bool

        :raises RequestFailed:
        """

        if clientid is None:
            clientid = self._use_default_clientid()[0]

        url = self.api_base_url.format(str(clientid)) + "/mark-as-read"
        
        body = {
                "notificationIds": notificationids,
                "markAsRead": markasread
                }

        try:
            self.request_handler.make_request(ApiRequestHandler.PUT, url,body=body)
        except RequestFailed:
            raise
        
        

    def create_delivery_channel(self, channelname, channeltype, webhookcontenttype,
                               addressDetails,clientid):

        """
        Searches for and returns networks based on the provided filter(s) and other parameters.

        :param search_filters:  A list of dictionaries containing filter parameters.
        :type  search_filters:  list"""

        if clientid is None:
            clientid = self._use_default_clientid()[0]

        url = self.api_base_url.format(str(clientid)) + "/channel"

        body = {
                "channelName": channelname,
                "channelType": channeltype,
                "webhookContentType": webhookcontenttype,
                "addressDetails": addressDetails
                }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def edit_delivery_channel(self,channelid, channelname, channeltype, webhookcontenttype,
                               addressDetails,clientid,disabled,shared):

        """
        Searches for and returns networks based on the provided filter(s) and other parameters.

        :param search_filters:  A list of dictionaries containing filter parameters.
        :type  search_filters:  list"""

        if clientid is None:
            clientid = self._use_default_clientid()[0]

        url = self.api_base_url.format(str(clientid)) + "/channel"

        body = {
                "id": channelid,
                "channelName": channelname,
                "channelType": channeltype,
                "webhookContentType": webhookcontenttype,
                "disabled": disabled,
                "shared": shared,
                "addressDetails": addressDetails
                }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def delete_delivery_channel(self, clientid,channelids):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + "/channel"

        body ={
                "channelIds": channelids
                }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.DELETE, url, body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response
    
    def list_channel(self, clientid,order):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + f"/channel/{order}"

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response
    def send_verification_code(self, clientid,channelname,channeladdress,channeltype):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + f"/sendverificationcode"

        body={
                "channelName": channelname,
                "channelDetails": [
                    {
                    "channelAddress": channeladdress,
                    "channelType": channeltype
                    }
                ]
                }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, url,body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def get_model(self, clientid):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + f"/model"
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def search_fields(self, clientid):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + f"/filter"

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def notification_search(self,clientid,filters):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + f"/search"
        body={
                "filters": filters
            }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, url,body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def search_fields(self,clientid):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + f"/quick-filters/count"
        body={
                "subject": "rsNotifications",
                "filterRequest": {
                    "filters": [
                    {
                        "field": "subject",
                        "exclusive": False,
                        "operator": "IN",
                        "value": "groups"
                    }
                    ]
                }
                }
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.POST, url,body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)
        return jsonified_response

    def edit_delivery_channel(self,clientid,id,channelname,channeltype,webhookcontenttype,disabled,shared,address,verification_code):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + "/channel/admin"
        body={
                "id": id,
                "channelName": channelname,
                "channelType": channeltype,
                "webhookContentType": webhookcontenttype,
                "disabled": disabled,
                "shared": shared,
                "addressDetails": [
                    {
                    "address": address,
                    "verification_code": verification_code
                    }
                ]
                }

        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.PUT, url,body=body)
        except RequestFailed:
            raise

        jsonified_response = json.loads(raw_response.text)

        return jsonified_response
    def edit_delivery_channel(self,clientid,order):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + f"/channel/admin/{order}"
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise
        jsonified_response = json.loads(raw_response.text)

        return jsonified_response
  
    def edit_delivery_channel(self,clientid,notification_id):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + f"/detail?notification_id={notification_id}"
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise
        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    def edit_delivery_channel(self,clientid):
        if clientid is None:
            clientid= self._use_default_clientid()

        url = self.api_base_url.format(str(clientid)) + f"/delivery-channel-template"
        try:
            raw_response = self.request_handler.make_request(ApiRequestHandler.GET, url)
        except RequestFailed:
            raise
        jsonified_response = json.loads(raw_response.text)

        return jsonified_response

    
    

"""
   Copyright 2021 RiskSense, Inc.
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:
   
   http://www.apache.org/licenses/LICENSE-2.0
   
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
