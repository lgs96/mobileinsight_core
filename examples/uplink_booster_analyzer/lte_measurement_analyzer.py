#!/usr/bin/python
# Filename: lte_measurement_analyzer.py
"""
An analyzer for LTE radio measurements

Author: Yuanjie Li
"""

#from .analyzer import *
from mobile_insight.analyzer.analyzer import *

import datetime


class LteMeasurementAnalyzer(Analyzer):
    """
    An analyzer for LTE radio measurements
    """

    def __init__(self):

        Analyzer.__init__(self)

        # init packet filters
        self.add_source_callback(self.ue_event_filter)

        self.timestamp = [] 
        self.serv_cell_rsrp = []  # rsrp measurements
        self.serv_cell_rsrq = []  # rsrq measurements
        
        self.dict_meas_pcell = {}

    def set_source(self, source):
        """
        Set the source of the trace.
        Enable device's LTE internal logs.

        :param source: the source trace collector
        :param type: trace collector
        """
        Analyzer.set_source(self, source)
        # enable user's internal events
        source.enable_log("LTE_PHY_Connected_Mode_Intra_Freq_Meas")
        source.enable_log("LTE_PHY_Serv_Cell_Measurement")
        source.enable_log("LTE_PHY_Connected_Mode_Neighbor_Measurement")
        source.enable_log("LTE_PHY_Inter_RAT_Measurement")
        source.enable_log("LTE_PHY_Inter_RAT_CDMA_Measurement")

    def ue_event_filter(self, msg):
        """
        callback to handle user events

        :param source: the source trace collector
        :param type: trace collector
        """
        # TODO: support more user events
        self.serving_cell_rsrp(msg)




    def serving_cell_rsrp(self, msg):
        if msg.type_id == "LTE_PHY_Serv_Cell_Measurement":
            log_item = msg.data.decode()
            if 'Subpackets' not in log_item:
                return
            servingCell = log_item['Subpackets'][0]
            
            if 'Serving Cell Index' in servingCell:
                servCellIdx = str(servingCell['Serving Cell Index'])
            else:
                servCellIdx = None
            if servCellIdx == 'PCell':
                rsrq0 = servingCell['RSRQ Rx[0]']
                rsrq1 = servingCell['RSRQ Rx[1]']
                rsrq = servingCell['RSRQ']
                rsrp = servingCell['RSRP']


                sys_fn = servingCell['Current SFN']
                sub_fn = servingCell['Current Subframe Number']
                self.dict_meas_pcell[(sys_fn, sub_fn)] = (float(rsrq), float(rsrp))
        
        if msg.type_id == "LTE_PHY_Connected_Mode_Intra_Freq_Meas":

            msg_dict = dict(msg.data.decode())
            #print(msg_dict)
            date = msg_dict['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')
            rsrp_log = (str(date) +
                        ":" +
                        self.__class__.__name__ +
                        ' RSRP=' +
                        str(msg_dict['RSRP(dBm)']) +
                        'dBm' +
                        ' RSRQ=' +
                        str(msg_dict['RSRQ(dB)']) +
                        'dB' +
                        ' # of neighbors=' +
                        str(msg_dict['Number of Neighbor Cells']) +
                        '\n')

            for item in msg_dict["Neighbor Cells"]:
                rsrp_log = (rsrp_log
                            + '    Cell_ID=' + str(item["Physical Cell ID"])
                            + ' RSRP=' + str(item["RSRP(dBm)"]) + 'dBm'
                            + ' RSRQ=' + str(item["RSRQ(dB)"]) + 'dB'
                            + '\n')

            self.log_debug(rsrp_log)
            
            # We only focus on uplink without carrier aggregation 
            if msg_dict['Serving Cell Index'] == 'PCell':
                self.timestamp.append(msg_dict['timestamp'])
                self.serv_cell_rsrp.append(msg_dict['RSRP(dBm)'])
                self.serv_cell_rsrq.append(msg_dict['RSRQ(dB)'])

        # if msg.type_id == "LTE_PHY_Inter_RAT_Measurement":
        #     msg_dict=dict(msg.data.decode())
        #     self.log_info(str(msg_dict))

        # if msg.type_id == "LTE_PHY_Inter_RAT_CDMA_Measurement":
        #     msg_dict=dict(msg.data.decode())
        #     self.log_info(str(msg_dict))

    def get_rsrp_list(self):
        """
        Get serving cell's RSRP measurement

        :returns: a list of serving cell's measurement
        :rtype: list
        """
        return self.serv_cell_rsrp

    def get_rsrq_list(self):
        """
        Get serving cell's RSRQ measurement

        :returns: a list of serving cell's measurement
        :rtype: list
        """
        return self.serv_cell_rsrq
