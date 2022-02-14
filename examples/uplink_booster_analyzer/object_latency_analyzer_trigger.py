#!/usr/bin/python3
# Filename: uplink_latency_analyzer.py
"""
uplink_latency_analyzer.py
An analyzer to monitor uplink packet waiting and processing latency
"""


__all__ = ["FirstByteAnalyzer"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from numpy.core.defchararray import decode
from mobile_insight.analyzer.analyzer import *


import time
import dis
import json
from datetime import datetime
import numpy as np


# import threading

cqi_to_bw = {
    0: 1.0911,
    1: 1.8289,
    2: 2.2541,
    3: 2.5779,
    4: 3.1557,
    5: 4.8534,
    6: 5.7557,
    7: 6.8142,
    8: 7.3716,
    9: 7.5516,
    10: 10.29,
    11: 36.089,
    12: 41.667,
    13: 38.477,
    14: 31.359,
    15: 23.774,
}


class ObjectLatencyAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.add_source_callback(self.__msg_callback)
        #self.register_coordinator_cb(self.__msg_callback)

        # Timers 
        self.fn = -1
        self.sfn = -1

        # PHY stats
        self.cum_err_block = {0: 0, 1: 0}  # {0:xx, 1:xx} 0 denotes uplink and 1 denotes downlink
        self.cum_block = {0: 0, 1: 0}  # {0:xx, 1:xx} 0 denotes uplink and 1 denotes downlink
        self.loss_block = 0

        # MAC buffer
        self.last_buffer = 0
        self.packet_queue = []

        # Stats
        self.all_packets = []
        self.tx_packets = []
        self.tmp_dict = {}

        ########### added ################
        self.init_timestamp = None

        # Record per-second downlink bandwidth
        self.lte_dl_bw = 0  # Downlink bandwidth (from PDSCH)
        self.lte_ul_bw = 0  # Uplink bandwidth (from PUSCH DCI grants)
        self.lte_ul_grant_utilized = 0  # Uplink grant utilization (in bits)
        self.prev_timestamp_dl = None  # Track timestamp to calculate avg DL bandwidth
        self.prev_timestamp_ul = None  # Track timestamp to calculate avg DL bandwidth
        self.avg_window = 1.0  # Average link BW time window (in seconds)

        # Statistics for PDSCH modulation
        self.mcs_qpsk_count = 0
        self.mcs_16qam_count = 0
        self.mcs_64qam_count = 0

        # Record last observed CQI (for DL bandwidth prediction)
        self.cur_cqi0 = 0
        self.cur_cqi1 = 0
        self.cur_tbs = None

        # Flag to show if it is the first sr event
        self.init_flag = False

        # Resource slot used by SR
        self.rb_slot1 = None
        self.rb_slot2 = None

        # Scheduled SR subframenumber
        self.sr_sfn = None

        self.grant_list = []
        self.sent_list = []

        # Get scheduling latency: 210526 Goodsol
        self.state = 1 # 0: scheduling request 1: others
        self.cell_id = []
      
        self.blank = []
        self.sr = []
        self.tx = []

        self.sr_start = 0
        self.tx_start = 0
        self.tx_end = 0

        self.total_tx = 0
        self.total_buffer = 0
        self.total_grant = 0
        self.my_last_buffer = 0
        self.total_utilized = 0
        self.log_time = 0
        self.my_last_tx = 0 
        self.total_tb = 0
        self.rlc_error = 0
        
        # Measure time
        self.second = 0
        self.last_f_time = 0
        self.counter = 0
        self.started = False
        self.rach_exist = False

        # record events
        self.record_time = 1000000
        self.record = np.zeros([self.record_time,3]) #0: sr, #1: tx start, #2: tx end
        self.whole_record = np.zeros([self.record_time, 5]) #0: sr occurence, #1: tx byte  #2: buffer size #3
        self.retx_buffer = np.zeros(self.record_time)
        self.buffer_record = np.zeros(self.record_time)
        self.rb_record = np.zeros(self.record_time)
        self.tx_power_record = -np.ones(self.record_time)
        self.fi_record = -np.ones(self.record_time)
        self.coding_record = np.zeros(self.record_time)
        self.mod_record = [[] for i in range(self.record_time)]
        self.mcs_record = np.zeros(self.record_time)
        self.cqi_record = np.zeros(self.record_time)
        self.meas_record = np.zeros([self.record_time, 2])
        self.dl_tbs_record = np.zeros(self.record_time)
        self.frame_tbs_record = np.zeros(self.record_time//10)
        self.bsr_trig_record = np.zeros(self.record_time)
        self.per_object_period = []
        self.sr_point = []
        self.sr_latency = []
        self.blank_latency = []
        self.tx_latency = []
        self.tx_time = 0
        self.num_of_objects = 0
        self.object_latency = []
        self.object_bsr_list = [] 

    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        #source.enable_log("LTE_PHY_PDSCH_Packet")
        source.enable_log("LTE_PHY_Serv_Cell_Measurement")
        source.enable_log("LTE_PHY_PUSCH_Tx_Report")
        source.enable_log("LTE_PHY_PUSCH_CSF")
        source.enable_log("LTE_PHY_PUSCH_Power_Control")
        source.enable_log("LTE_MAC_UL_Buffer_Status_Internal")
        source.enable_log("LTE_PHY_PUCCH_Tx_Report")
        #source.enable_log("LTE_PHY_PDCCH_Decoding_Result")
        source.enable_log("LTE_MAC_UL_Transport_Block")
        source.enable_log("LTE_MAC_UL_Tx_Statistics")
        source.enable_log("LTE_MAC_Rach_Trigger")
        source.enable_log("LTE_MAC_Rach_Attempt")
        source.enable_log("LTE_RLC_UL_Stats")
        source.enable_log("LTE_RLC_UL_AM_All_PDU")
        source.enable_log("LTE_RLC_DL_AM_All_PDU")
        
        # 5G
        '''
        source.enable_log('5G_NR_MAC_UL_TB_Stats')
        source.enable_log('5G_NR_ML1_Searcher_Measurement_Database_Update_Ext')
        source.enable_log('5G_NR_L2_UL_TB')
        source.enable_log('5G_NR_ML1_Serving_Cell_Beam_Management')
        '''
        
        #source.enable_log("LTE_MAC_Configuration")

    # get difference between two time value
    def __f_time_diff(self, t1, t2):
        if t1 > t2:
            print('bug', t1,t2)
            t_diff = t2 + 10240 - t1
        else:
            t_diff = t2 - t1 + 1
        return t_diff

    
    def __f_time_diff_object(self, t1, t2):
        if t1 > t2:
            t_diff = t1- t2 + 1
        else:
            t_diff = t2 - t1 + 1
        return t_diff

    # get absolute time
    def __f_time(self):
        return self.fn * 10 + self.sfn
    
    def predict_bw(self, timestamp):
        """
        Predict bandwidth based on CQI
        Currently it implements a naive solution based on pre-trained CQI->BW table

        """
        if self.cur_cqi0 in cqi_to_bw:
            bcast_dict = {}
            bcast_dict['bandwidth'] = str(cqi_to_bw[self.cur_cqi0])
            bcast_dict['timestamp'] = str(timestamp)
            self.broadcast_info('PREDICTED_DL_BW', bcast_dict)
            self.log_info('PREDICTED_DL_BW: ' + str(cqi_to_bw[self.cur_cqi0]) + 'Mbps')
            return cqi_to_bw[self.cur_cqi0]
        else:
            return None

    def __cmp_queues(self, type, data):
        if type == 1:
            for pkt in self.all_packets:
                if pkt[-2] == data[0]:
                    # print the stats

                    self.all_packets.remove(pkt)
                    return
            self.tx_packets.append(data)
        if type == 2:
            for pkt in self.tx_packets:
                if pkt[0] == data[-2]:
                    # print the stats
                    self.tx_packets.remove(pkt)
                    return
            self.all_packets.append(data)

    def __print_buffer(self):
        pass

    def __msg_callback(self, msg):

        if msg.type_id == "LTE_PHY_PDSCH_Packet":
            log_item = msg.data.decode()

            #print(log_item)

            if not self.init_timestamp:
                self.init_timestamp = log_item['timestamp']

            if not self.prev_timestamp_dl:
                self.prev_timestamp_dl = log_item['timestamp']

            # Log runtime PDSCH information
            # self.log_info(str((log_item['timestamp']-self.init_timestamp).total_seconds())+" "
            # + str(log_item["MCS 0"])+" "
            # + str(log_item["MCS 1"])+" "
            # + str(log_item["TBS 0"])+" "
            # + str(log_item["TBS 1"])+" "
            # + str(log_item["PDSCH RNTI Type"]))

            current_time = log_item['Subframe Number'] + 10*log_item['System Frame Number']
            self.dl_tbs_record[10240*self.second + current_time] =log_item['TBS 0'] + log_item['TBS 1']
            #self.frame_tbs_record[(10240*self.second + current_time)//10] += log_item['TBS 0'] + log_item['TBS 1']

            self.log_debug(str(log_item['timestamp']) + " "
                        + "MCS0=" + str(log_item["MCS 0"]) + " "
                        + "MCS1=" + str(log_item["MCS 1"]) + " "
                        + "TBS0=" + str(log_item["TBS 0"]) + "bits "
                        + "TBS1=" + str(log_item["TBS 1"]) + "bits "
                        + "C-RNTI=" + str(log_item["PDSCH RNTI Type"]))

            # Broadcast bandwidth to other apps
            if log_item["PDSCH RNTI Type"] == "C-RNTI":

                self.cur_tbs = (log_item["TBS 0"] + log_item["TBS 1"])
                self.lte_dl_bw += (log_item["TBS 0"] + log_item["TBS 1"])

                if log_item["MCS 0"] == "QPSK":
                    self.mcs_qpsk_count += 1
                elif log_item["MCS 0"] == "16QAM":
                    self.mcs_16qam_count += 1
                elif log_item["MCS 0"] == "64QAM":
                    self.mcs_64qam_count += 1

                if (log_item['timestamp'] -
                        self.prev_timestamp_dl).total_seconds() >= self.avg_window:
                    bcast_dict = {}
                    bandwidth = self.lte_dl_bw / \
                        ((log_item['timestamp'] - self.prev_timestamp_dl).total_seconds() * 1000000.0)
                    pred_bandwidth = self.predict_bw(log_item['timestamp'])
                    bcast_dict['Bandwidth (Mbps)'] = str(round(bandwidth, 2))

                    # """
                    # TEST PURPOSE
                    # """
                    # if pred_bandwidth:
                    #     bcast_dict['Bandwidth (Mbps)'] = str(round(pred_bandwidth,2)) #TEST
                    # else:
                    #     bcast_dict['Bandwidth (Mbps)'] = str(round(bandwidth,2))
                    # """
                    # END OF TEST PURPOSE
                    # """

                    if pred_bandwidth:
                        bcast_dict['Predicted Bandwidth (Mbps)'] = str(
                            round(pred_bandwidth, 2))
                    else:
                        # Use current PDSCH bandwidth as estimation
                        bcast_dict['Predicted Bandwidth (Mbps)'] = str(
                            round(bandwidth, 2))

                    bcast_dict['Modulation 0'] = str(log_item["MCS 0"])
                    bcast_dict['Modulation 1'] = str(log_item["MCS 1"])
                    bcast_dict['Modulation-QPSK'] = str(self.mcs_qpsk_count)
                    bcast_dict['Modulation-16QAM'] = str(self.mcs_16qam_count)
                    bcast_dict['Modulation-64QAM'] = str(self.mcs_64qam_count)

                    mod_dict = {}
                    mod_dict['Modulation 0'] = str(log_item["MCS 0"])
                    mod_dict['Modulation 1'] = str(log_item["MCS 1"])

                    # Log/notify average bandwidth
                    self.log_info(str(log_item['timestamp']) +
                                ' LTE_DL_Bandwidth=' +
                                bcast_dict['Bandwidth (Mbps)'] +
                                "Mbps")
                    self.broadcast_info('LTE_DL_BW', bcast_dict)
                    self.log_info('MODULATION_SCHEME: ' + str(mod_dict))
                    self.broadcast_info('MODULATION_SCHEME', mod_dict)

                    # Reset bandwidth statistics
                    self.prev_timestamp_dl = log_item['timestamp']
                    self.lte_dl_bw = 0
                    self.mcs_qpsk_count = 0
                    self.mcs_16qam_count = 0
                    self.mcs_64qam_count = 0
            

        if msg.type_id == "LTE_PHY_PUSCH_Tx_Report":
            log_item = msg.data.decode()
            #print(log_item)
            if 'Records' in log_item:
                for record in log_item['Records']:
                    current_time = record['Current SFN SF']
                    self.total_tb += record['PUSCH TB Size']
                    self.whole_record[10240*self.second + current_time][2] += record['PUSCH TB Size']
                    self.rb_record[10240*self.second + current_time] += record['Num of RB']
                    self.coding_record[10240*self.second + current_time] = str(record['Coding Rate'])
                    self.mod_record[10240*self.second + current_time] = record['PUSCH Mod Order']
                    self.frame_tbs_record[(10240*self.second + current_time)//10] += record['PUSCH TB Size']
                    bits = 0
                    if record['PUSCH Mod Order'] == 'QPSK':
                        bits = 2
                    if record['PUSCH Mod Order'] == '16-QAM':
                        bits = 4
                    if record['PUSCH Mod Order'] == '64-QAM':
                        bits = 6
                    self.mcs_record[10240*self.second + current_time] = bits*record['Coding Rate']
                    #print('PHY TB Size: ', record['Current SFN SF'], record['PUSCH TB Size'])
                    retx_time = record['Current SFN SF']
                    if retx_time < 0:
                        retx_time += 1024

                    if record['Re-tx Index'] == 'First':
                        self.cum_block[0] += 1
                    else:
                        # print(record['Re-tx Index'])
                        self.cum_err_block[0] += 1

                        ## should set retx time according to the Re-tx Index
                        if record['Re-tx Index'] == 'Second':
                            retx_latency = 8
                        if record['Re-tx Index'] == 'Third':
                            retx_latency = 16
                        if record['Re-tx Index'] == 'Fourth':
                            retx_latency = 24
                            #self.loss_block += 1
                        else:
                            retx_latency = 8
                        if retx_time in self.tmp_dict :
                            self.tmp_dict[retx_time]['Retx Latency'] = retx_latency
                        else:
                            self.tmp_dict[retx_time] = {'Retx Latency': retx_latency}
                            
                    self.log_info(str(log_item['timestamp']) + ' Time: ' + str(current_time) + ' Grant bytes: ' + str(record['PUSCH TB Size']))
                    
                    for t in list(self.tmp_dict):
                        # print t, retx_time
                        # print self.tmp_dict
                        if (t < retx_time or (t > 1000 and retx_time < 20)):
                            if 'Retx Latency' not in self.tmp_dict[t]:
                                self.tmp_dict[t]['Retx Latency'] = 0
                            
                            if len(self.tmp_dict[t]) == 3:
                                #print ('Waiting Latency:', self.tmp_dict[t]['Waiting Latency'], 'Tx Latency:', self.tmp_dict[t]['Tx Latency'], 'Retx Latency:', self.tmp_dict[t]['Retx Latency'])
                                self.all_packets.append(self.tmp_dict[t])
                                del(self.tmp_dict[t])
                    # self.__cmp_queues(1, (record['Current SFN SF'], record['Re-tx Index']))

        if msg.type_id == "LTE_MAC_UL_Buffer_Status_Internal":
            for packet in msg.data.decode()['Subpackets']:
                for sample in packet['Samples']:
                    #print('Buffer Status', sample)
                    SFN = sample['Sub FN']
                    FN = sample['Sys FN']
                    self.update_time(SFN, FN)
                    if (sample['LCIDs'] == []):
                        # print "error here!!"
                        continue
                    # print SFN, FN, self.sfn, self.fn
                    data = sample['LCIDs'][-1]
                    # print sample
                    
                    total_b = data['Total Bytes']
                    new_c = data['New Compressed Bytes']
                    retx_b = data['Retx bytes']
                    ctrl_b = data['Ctrl bytes']
                    
                    self.whole_record[10240*self.second + self.__f_time()][3] = total_b
                    self.retx_buffer[10240*self.second + self.__f_time()] = retx_b

                    ## 210526Goodsol second unit time measurement
                    if self.__f_time() < self.last_f_time and self.__f_time() >= 0 and self.started:
                        print('sec', self.__f_time(), self.last_f_time)
                        if self.last_f_time == 10239:
                            self.second = self.second + 1 
                    #print('sec2', self.__f_time(), self.last_f_time)
                    self.last_f_time = self.__f_time()

                    # if (total_b > new_c) and ctrl_b == 0:
                    if total_b > self.last_buffer: 
                        # size, remaining buffer, incoming time, first byte time
                        self.packet_queue.append([total_b - self.last_buffer, total_b - self.last_buffer, self.__f_time(), -1])
                    elif total_b < self.last_buffer:
                        outgoing_bufer = self.last_buffer - total_b
                        self.total_buffer += outgoing_bufer
                        
                        self.whole_record[10240*self.second + self.__f_time()][1] += outgoing_bufer
                        #print('Time: ', 10000*self.second + self.__f_time(), 'total outgoing: ', outgoing_bufer, 'total buffer: ', self.total_buffer)
                        #self.total_tx += outgoing_bufer
                        #print('Time: ', 10000*self.second + self.__f_time(), ' Transmit bytes: ', outgoing_bufer, 'State: ', self.state, ' Total Tx: ',self.total_tx)
                        while 1:
                            if self.packet_queue == []:
                                break
                            packet = self.packet_queue[0]
                            #print('Time: ', self.__f_time(), ' Buffer: ', packet[1], self.last_buffer)
                            #self.whole_record[2] = self.last_buffer
                            if self.my_last_buffer != packet[0]:
                                #self.total_buffer += packet[0] + self.my_last_tx
                                self.my_last_buffer = packet[0]
                            '''
                            print('Time: ', self.__f_time(), 'MAC UL Packet 0: ', packet[0], "1: ", packet[1], "2: ", packet[2], "3: ", packet[3], 
                                  ' My last tx: ', self.my_last_tx, 'Outgoing: ', outgoing_bufer, ' Total tx: ', self.total_tx)
                            '''
                            #      " total buffer: ", self.total_buffer, "\n")
                            self.total_tx += outgoing_bufer
                            if packet[3] == -1:
                                packet[3] = self.__f_time()
                            if packet[1] > outgoing_bufer:
                                packet[1] -= outgoing_bufer
                                #self.total_tx += outgoing_bufer
                                break
                            else:
                                # size, waiting latency, transmission latency
                                # print self.packet_queue, self.all_packets, outgoing_bufer
                                t_now = self.__f_time()
                                if (t_now not in self.tmp_dict):
                                    self.tmp_dict[t_now] = {}
                                #self.tmp_dict[t_now]['Waiting Latency'] = self.__f_time_diff(packet[2], packet[3])
                                #self.tmp_dict[t_now]['Tx Latency'] = self.__f_time_diff(packet[3], self.__f_time())
                                
                                #print ([self.__f_time(), packet[0], self.__f_time_diff(packet[2], packet[3]), self.__f_time_diff(packet[3], self.__f_time())])
                                #self.my_last_tx = outgoing_bufer
                                '''
                                print('Time: ', self.__f_time(), ' Tx: ', outgoing_bufer, ' Packet size: ', packet[0], 
                                ' Remaining buffer: ', packet[1], ' Incoming time: ',packet[2],
                                ' Packet tx time: ', packet[3])
                                '''

                                outgoing_bufer -= packet[1]
                                #self.total_tx += outgoing_bufer
                                self.my_last_tx = packet[1]
                                del self.packet_queue[0]
                                #self.__cmp_queues(2, (packet[0], self.__f_time_diff(packet[2], packet[3]), self.__f_time_diff(packet[2], t_now), t_now, self.last_buffer - new_c) )
                
                    self.last_buffer = total_b

        if msg.type_id == "LTE_PHY_PUCCH_Tx_Report":
            self.callback_pucch(msg)
        if msg.type_id == "LTE_PHY_PDCCH_Decoding_Result":
            self.callback_pdcch(msg)
        if msg.type_id == "LTE_MAC_UL_Transport_Block":
            self.callback_ul_transport(msg)
        if msg.type_id == "LTE_MAC_UL_Tx_Statistics":
            self.callback_pusch_grant(msg)
        if msg.type_id == "LTE_MAC_Rach_Trigger":
            self.callback_rach_trigger(msg)
        if msg.type_id == "LTE_MAC_Rach_Attempt":
            self.callback_rach_attempt(msg)
        if msg.type_id == "LTE_MAC_Configuration":
            self.callback_mac_configuration(msg)
        if msg.type_id == "LTE_PHY_PUSCH_CSF":
            self.callback_pusch_csf(msg)
        if msg.type_id == "LTE_PHY_PUSCH_Power_Control":
            self.callback_pusch_power(msg)   
        if msg.type_id == "LTE_PHY_Serv_Cell_Measurement":
            self.callback_serv_cell(msg)
        if msg.type_id == "LTE_RLC_UL_Stats":
            self.callback_rlc_ul_stats(msg)
        if msg.type_id == "LTE_RLC_DL_AM_All_PDU":
            self.callback_rlc_ul_pdu(msg)
        ## 5G
        if msg.type_id == "5G_NR_MAC_UL_TB_Stats":
            self.callback_5g_mac_ul_tb_stats(msg)
        if msg.type_id == "5G_NR_ML1_Searcher_Measurement_Database_Update_Ext":
            self.callback_5g_ml1_searcher(msg)
        if msg.type_id == "5G_NR_L2_UL_TB":
            self.callbcak_5g_l2_ul_tb(msg)
        if msg.type_id == "5G_NR_ML1_Serving_Cell_Beam_Management":
            self.callback_5g_beam(msg)
            
    def callback_5g_mac_ul_tb_stats(self, msg):
        print("5G TB Stats: ", msg)
        
    def callback_5g_m1_searcher(self, msg):
        print("5G ml1 searcher: ", msg)    
    
    def callbcak_5g_l2_ul_tb(self, msg):
        print("5G L2 TB: ", msg)
        
    def callback_5g_beam(self, msg):
        print("5G Beam: ", msg)
            


    def update_time(self, SFN, FN):
        if self.sfn >= 0:      
            self.sfn += 1
            if self.sfn == 10:
                self.sfn = 0
                self.fn += 1
            if self.fn == 1024:
                self.fn = 0
        if SFN < 10:
            self.sfn = SFN
            self.fn = FN


    ###############added#####################

    def callback_pucch(self, msg):
        """
        Dump PUCCH scheduling request information
        :param msg: raw LTE_PHY_PUCCH_Tx_Report packet
        :return:
        """
        log_item = msg.data.decode()
        records = log_item['Records']
        timestamp = str(log_item['timestamp'])

        for record in records:
            pucch_tx_power = record['PUCCH Tx Power (dBm)']
            bcast_dict = {}
            bcast_dict['tx power'] = pucch_tx_power
            bcast_dict['timestamp'] = timestamp
            self.broadcast_info("PUCCH_TX_POWER", bcast_dict)
            self.log_debug("PUCCH_TX_POWER: " + str(bcast_dict))
            uciformat = record['Format']
            if uciformat == 'Format 1':
                self.init_flag = True
                self.rb_slot1 = record['Start RB Slot 0']
                self.rb_slot2 = record['Start RB Slot 1']
                self.sr_sfn = record['Current SFN SF'] % 10  # subframenumber
                sr_dict = {}
                sr_dict['timestamp'] = timestamp
                sr_dict['fn and subfn'] = record['Current SFN SF']
                self.broadcast_info("SR_EVENT", sr_dict)
                self.log_info("SR_EVENT: " + str(sr_dict))
                #print('SR time1: ',10240*self.second + sr_dict['fn and subfn'])
                # 210526Goodsol
                self.whole_record[10240*self.second + sr_dict['fn and subfn']][0] = 1
                
                if self.state != 0:
                    #self.tx.append([self.tx_start, self.tx_end])
                    #self.blank.append([self.tx_end, 10000*self.second + sr_dict['fn and subfn']])
                    self.started = True

            elif uciformat == 'Format 1B' or uciformat == 'Format 1A':
                # TODO: reset init_flag for new logs
                if self.init_flag:
                    if int(record['Start RB Slot 1']) == self.rb_slot2 and int(record['Start RB Slot 0']) == self.rb_slot1 \
                            and record['Current SFN SF'] % 10 == self.sr_sfn:
                        sr_dict = {}
                        sr_dict['timestamp'] = timestamp
                        sr_dict['fn and subfn'] = record['Current SFN SF']
                        self.broadcast_info("SR_EVENT", sr_dict)
                        self.log_info("SR_EVENT: " + str(sr_dict))
                        #print('SR time2: ', 10240*self.second +sr_dict['fn and subfn'])    
                        # 210526Goodsol
                        self.whole_record[10240*self.second + sr_dict['fn and subfn']][0] = 1
                        '''
                        if self.state != 0:
                            #self.tx.append([self.tx_start, self.tx_end])
                            #self.blank.append([self.tx_end, 10000*self.second + sr_dict['fn and subfn']])
                            self.started = True
                            self.state = 0
                            self.sr_start = 10000*self.second + sr_dict['fn and subfn']
                            ##recording method
                            self.record[self.sr_start][0] = 1
                        '''

            elif uciformat == "Format 3":
                # TODO: Deal with SR event in format 3
                pass

    def callback_pdcch(self, msg):
        log_item = msg.data.decode()
        print('PDCCH: ', log_item)

    def callback_ul_transport(self, msg):
        log_item = msg.data.decode()
        subpackets = log_item['Subpackets']
        
        for subpacket in subpackets:
            samples = subpacket['Samples']
            for sample in samples:
                sfn = sample['SFN']
                subfn = sample['Sub-FN']
                grant = sample['Grant (bytes)']
                bsr = sample['BSR trig']
                if bsr == 'S-BSR' or 'L-BSR':
                    self.bsr_trig_record[10240*self.second + 10*sfn + subfn] = 1
                
                #self.log_info(str(log_item['timestamp']) + ' Time: ' + str(10000*self.second + sfn*10+subfn) + ' Grant bytes: ' + str(grant))

    def callback_pusch_grant(self, msg):

        log_item = msg.data.decode()
        #print('PUSCH_Tx_statistics callback: ', log_item,"\n")
        if not self.init_timestamp:
            self.init_timestamp = log_item['timestamp']

        if not self.prev_timestamp_ul:
            self.prev_timestamp_ul = log_item['timestamp']

        # Calculate PUSCH uplink utilization
        grant_received = 0
        grant_utilized = 0
        grant_utilization = 0

        for i in range(0, len(log_item['Subpackets'])):
            grant_received += log_item['Subpackets'][i]['Sample']['Grant received']
            grant_utilized += log_item['Subpackets'][i]['Sample']['Grant utilized']

        if grant_received != 0:
            grant_utilization = round(
                100.0 * grant_utilized / grant_received, 2)

        self.total_utilized += grant_utilized
        self.total_grant += grant_received
        self.log_time += 1
        
        self.log_info(str(log_item['timestamp']) +
                       " PUSCH UL grant: received=" +
                       str(grant_received) +
                       " bytes" +
                       " used=" +
                       str(grant_utilized) +
                       " bytes" +
                       " utilization=" +
                       str(grant_utilization) +
                       "%" + 
                       " total utilized"+ 
                       str(self.total_utilized))
        
        '''
        print("Stats: ", self.log_time ," "+ str(log_item['timestamp']) +
                       " PUSCH UL grant: received=" +
                       str(grant_received) +
                       " bytes" +
                       " used=" +
                       str(grant_utilized) +
                       " bytes" +
                       " utilization=" +
                       str(grant_utilization)+
                       "% total utilized",  
                       self.total_utilized)
        '''
        self.grant_list.append(grant_received)
        self.sent_list.append(grant_utilized)

        self.lte_ul_grant_utilized += grant_utilized * 8
        self.lte_ul_bw += grant_received * 8

        if (log_item['timestamp'] -
                self.prev_timestamp_ul).total_seconds() >= self.avg_window:

            bcast_dict = {}
            bandwidth = self.lte_ul_bw / \
                ((log_item['timestamp'] - self.prev_timestamp_ul).total_seconds() * 1000000.0)
            grant_utilization = self.lte_ul_grant_utilized / \
                ((log_item['timestamp'] - self.prev_timestamp_ul).total_seconds() * 1000000.0)
            bcast_dict['Bandwidth (Mbps)'] = str(round(bandwidth, 2))
            bcast_dict['Utilized (Mbps)'] = str(round(grant_utilization, 2))
            if self.lte_ul_bw:
                bcast_dict['Utilization (%)'] = str(
                    round(self.lte_ul_grant_utilized * 100.0 / self.lte_ul_bw, 2))
            else:
                bcast_dict['Utilization (%)'] = '0'

            # self.log_info(str(log_item['timestamp']) + ' LTE_UL_Bandwidth=' + bcast_dict['Bandwidth (Mbps)'] + "Kbps "
            #              + "UL_utilized="+bcast_dict['Utilized (Mbps)']+"Kbps "
            #              + "Utilization="+bcast_dict['Utilization (%)']+"%")

            self.log_debug(str(log_item['timestamp']) +
                           ' UL ' +
                           bcast_dict['Bandwidth (Mbps)'] +
                           " " +
                           bcast_dict['Utilized (Mbps)'] +
                           " " +
                           bcast_dict['Utilization (%)'] +
                           "")

            self.broadcast_info('LTE_UL_BW', bcast_dict)
            # Reset bandwidth statistics
            self.prev_timestamp_ul = log_item['timestamp']
            self.lte_ul_bw = 0
            self.lte_ul_grant_utilized = 0
    
    def callback_serv_cell(self,msg):
        log_item = msg.data.decode()
        #print(log_item)
        if 'Subpackets' not in log_item:
            return
        servingCell = log_item['Subpackets'][0]
        if 'Serving Cell Index' in servingCell:
            servCellIdx = str(servingCell['Serving Cell Index'])
        else:
            servCellIdx = None
        if servCellIdx == 'PCell':
            
            if not servingCell['Physical Cell ID'] in self.cell_id:
                self.cell_id.append(servingCell['Physical Cell ID'])
            
            rsrq0 = servingCell['RSRQ Rx[0]']
            rsrq1 = servingCell['RSRQ Rx[1]']
            rsrq = servingCell['RSRQ']
            rsrp = servingCell['RSRP']


            sys_fn = servingCell['Current SFN']
            sub_fn = servingCell['Current Subframe Number']
            current_time = sys_fn*10 + sub_fn
            self.meas_record[10240*self.second + current_time,0] = rsrp
            self.meas_record[10240*self.second + current_time,1] = rsrq

    def callback_rach_trigger(self, msg):
        log_item = msg.data.decode()
        print(log_item['timestamp'])
        print('Rach trigger: ')
        
    def callback_rach_attempt(self, msg):
        log_item = msg.data.decode()
        print(log_item['timestamp'])
        print('Rach attempt: ')
        
    def callback_mac_configuration(self, msg):
        log_item = msg.data.decode()
        print('Mac configuration: ', log_item)
    
    def callback_pusch_csf(self, msg):
        record = msg.data.decode()
        self.cqi_record[10240*self.second + 10*record['Start System Frame Number']] = max(record['WideBand CQI CW0'], record['WideBand CQI CW1'])
        print('CQI:  ', record['Start System Frame Number'], record['WideBand CQI CW0'], record['WideBand CQI CW1'])
        
    def callback_pusch_power(self, msg):
        log_item = msg.data.decode()
        for record in log_item['Records']:
            current_time = 10*record['SFN'] + record['Sub-FN']
            self.tx_power_record[10240*self.second + current_time] = str(record['PUSCH Actual Tx Power'])
            self.fi_record[10240*self.second + current_time] = str(record['F(i)'])
            #print('SFN/Sub-FN, Tx power, F(i), TPC, Max Power, Bits per RB ,RB:  ', record['SFN'],record['Sub-FN'], record['PUSCH Actual Tx Power'], record['F(i)'], record['TPC'], record['Max Power'], round(record['Transport Block Size']/record['Num RBs'],2), record['Num RBs'])
        
    
    def callback_rlc_ul_stats(self, msg):
        log_item = msg.data.decode()
        try:
            self.rlc_error += int(log_item['RLCUL Error Count'])
        except:
            pass
    
    def callback_rlc_ul_pdu(self, msg):
        log_item = msg.data.decode()
        try:
            self.rlc_error += int(log_item['RLCUL Error Count'])
        except:
            pass
    
    def replay_record(self, is_tcp, object_size, trigger_size):
        object_size = object_size - 1000
        trigger_size = trigger_size - 1000
        
        
        total_tx = 0
        total_grant = 0
        
        ## event flag
        state = -1
        waiting = 0
        scheduling = 1
        transmitting = 2
        tx_stack = 0
        
        wait_start = 0
        wait_end = 0
        sched_start = 0
        sched_end = 0
        tx_start = 0 
        tx_end = 0
        last_sr = 0
        last_buffer = -1
        
        ## for BULLET
        bullet_init_start = 0
        bullet_init_end = 0
        bullet_tx_start = 0
        bullet_tx_end = 0
        
        ## record object components latency
        object_trigger_list = []    
        object_init_list = []
        
        object_sched_list = []
        
        object_tx_list = []
        
        object_pure_tx_list = []
        object_dummy_list = []
        
        self.object_start_list = []
        self.object_end_list = []
        
        init_start = 0
        init_end = 0
        object_sched_start = 0
        object_sched_end = 0
        object_tx_start = 0
        object_tx_end = 0
        
        ## object flag
        object_state = 3
        object_init = 0
        object_sched = 1
        object_tx = 2
        object_idle = 3
        idle_stack = 0
        object_tx_byte = 0
        
        trigger_on_tx = False
        trigger_cert = 0
        object_on_tx = False
        
        for time, event in enumerate(self.whole_record):
            event_sr = event[0]
            event_tx = event[1]
            event_grant = event[2] 
            event_buffer = event[3]
            
            # event_tx is recorded as 0 if buffer increases.. therefore we set event_tx = event_grant 
            # when there is tx packet while buffer size increases 
            if event_buffer > event_grant and event_tx ==0:
                if event_buffer == self.whole_record[time - 1][3]:
                    event_tx = 0
                else:
                    event_tx = event_grant
            
            total_tx += event_tx
            total_grant += event_grant
            
            ## start to transmit (SYN packet)
            if event_buffer >= 60 and state == -1:
                if is_tcp:
                    print('SYN packet')
                    state = waiting
                    wait_start = time
                else:
                    if event_buffer >= 1300:
                        print('UDP start')
                        state = scheduling
                        sched_start = time
                        
                        
                        
            ## init event
            if event_buffer > 5000 and object_state == object_idle:   
                self.num_of_objects += 1 
                print('Start of object/trigger ', self.num_of_objects)  
                self.object_start_list.append(time)           
                object_init_list = []
                object_sched_list = []
                object_tx_list = []
                object_trigger_list = []
                object_pure_tx_list = []
                init_start = time
                object_state = object_init
                object_tx_byte = 0
                if self.num_of_objects > 1:
                    trigger_on_tx = True
                    object_on_tx = True
                    trigger_cert = 0
            
                
            ## Object injection discriminator
            if event_buffer  > self.whole_record[time - 1][3] + 1000 and trigger_cert == 1:
                bullet_init_start = time   
                print('BULLET init time: ', self.num_of_objects) 
                trigger_cert = 2
            
            
            ## Trigger certificate
            if event_buffer > trigger_size and trigger_on_tx == True and trigger_cert == 0:
                trigger_cert = 1
                
            ## SR event
            if event_sr: 
                print(time//10240, time%10240, 'SR')
                last_sr = time
                if state == 0:
                    state = scheduling
                    wait_end = time
                    self.blank.append([wait_start, wait_end])
                    sched_start = time
                if object_state == object_tx:
                    object_tx_list.append([object_tx_start, time])
                    object_state = object_sched
            
            ## Tx event (object transmission)
            if event_tx and state >= 0:
                self.tx_time += 1
                if event_tx > 200:
                    if state==scheduling:
                        tx_stack += 1
                        if tx_stack >= 3:
                            state = transmitting
                            tx_stack = 0
                            sched_end = time - 2
                            self.sr.append([last_sr, sched_end])
                            tx_start = time - 2     
                            if object_state == object_init:  
                                object_state = object_tx
                                object_init_list.append([last_sr, time - 2])
                                object_tx_start = time -2
                            if object_state == object_sched:
                                object_state = object_tx
                                if last_buffer != -1:
                                    object_sched_list.append([last_buffer, time - 2])
                                    last_buffer = -1
                                else:
                                    object_sched_list.append([last_sr, time - 2])
                                object_tx_start = time - 2
                    elif state==waiting:
                        tx_stack += 1
                        if tx_stack >= 4:
                            state = transmitting
                            tx_stack = 0
                            wait_end = time - 4
                            self.blank.append([wait_start, wait_end])
                            tx_start = time - 4
                else:
                    tx_stack = 0
            ## no buffer event (on transmitting state)
            if (event_buffer < 500 and event_grant < 500) and object_state == object_tx:
                idle_stack += 1
                idle_time = 5
                if idle_stack >= idle_time:
                    last_buffer = time - idle_stack
                    if object_tx_byte > object_size:
                        idle_stack = 0
                        #object_tx_list.append([object_tx_start, time - idle_time])
                        #self.object_latency.append([object_init_list, object_sched_list, object_tx_list])
                        object_state = object_idle
                        #self.object_end_list.append(time - idle_time)
                        print('End of dummy + object ', self.num_of_objects)
            else:
                idle_stack = 0
            if (event_buffer < 100) and state == transmitting:
                tx_stack = 0
                state = waiting
                tx_end = time
                self.tx.append([tx_start, tx_end])
                wait_start = time
            ## Print all grant/tx event
            if event_grant > 0 or event_tx > 0 or event_buffer > 0:
                object_tx_byte += event_tx
                if object_tx_byte > trigger_size + 1500 and trigger_on_tx == True:
                    object_trigger_list.append([bullet_init_start-1, time])
                    print('Trigger end: ', self.num_of_objects, time - bullet_init_start)
                    trigger_on_tx = False
                    bullet_tx_start = time
                if object_tx_byte > object_size + trigger_size and object_on_tx == True:
                    object_pure_tx_list.append([bullet_tx_start, time])
                    self.object_latency.append([object_trigger_list, [], object_pure_tx_list])
                    self.object_end_list.append(time)
                    print('End of object ', self.num_of_objects, object_trigger_list, object_pure_tx_list)
                    object_on_tx = False
                print(time//10240, time%10240, ' Granted size: ', event_grant, ' Txed size: ', event_tx, 
                      ' Buffer size: ', event_buffer, ' Retx Buffer size: ', self.retx_buffer[time],' RB: ', self.rb_record[time], ' Tx power: ', self.tx_power_record[time], 
                      ' Mod order: ', self.mod_record[time], ' Coding: ', self.coding_record[time],
                      ' State: ', state, ' Object state: ', object_state, idle_stack, object_tx_byte)
            ## Cumulate grant size
            if time==0:
                self.whole_record[time][4] = event_grant
            if time!= 0:
                self.whole_record[time][4] = self.whole_record[time-1][4] + event_grant
                
                
    def calc_bsr_grant(self):
        bsr_rb_list = []
        bsr_grant_list = []
        for i,bsr_trig in enumerate(self.bsr_trig_record):
            if bsr_trig:
                bsr_rb_list.append([self.whole_record[i,3], np.sum(self.rb_record[i+5:i+10])]) 
                bsr_grant_list.append([self.whole_record[i,3], np.sum(self.whole_record[i+5:i+10,2])])

        return bsr_rb_list, bsr_grant_list

    def calc_delay (self, start_time = 100, fin_time = 100000, object_size = 80*1024, trigger_size = 0):
        self.replay_record(False, object_size, trigger_size)

        first_delay = 0
        blank_delay = 0
        scheduling_delay = 0
        tx_delay = 0

        end_point = 0
        
        sr_start = -1
        sr_end = 0

        blank_start = -1
        blank_end = 0

        object_start = -1
        object_end = -1
        
        for i, t in enumerate(self.tx):
            if i==0:
                object_start = t[0]
            elif (self.tx[i][0] - self.tx[i-1][1]) >= 10:
                object_end = self.tx[i-1][1]
                self.per_object_period.append([object_start, object_end])
                object_start = self.tx[i][0]
            if t[0] >= start_time and t[1] <= fin_time:
                end_point = t[1]
                tx_delay += self.__f_time_diff(t[0], t[1])
                self.tx_latency.append(self.__f_time_diff(t[0], t[1]))
        #self.per_object_period.append([object_start, self.tx[-1][1]])

        for i, t in enumerate(self.blank):
            if t[0] >= self.tx[-1][0]:
                break 
            if i!= 0 and i!=len(self.blank) and t[0] >= start_time and t[1] <= fin_time:
                blank_delay += self.__f_time_diff(t[0], t[1])
                self.blank_latency.append(self.__f_time_diff(t[0], t[1]))
            if i == 0 and t[0] >= start_time and t[1] <= fin_time:
                if blank_start == -1:
                    blank_start = i
                blank_end = i
                #first_delay = self.__f_time_diff(t[0], t[1])
            elif i!= 0 and t[0] >= start_time and t[1] <= fin_time:
                if blank_start == -1:
                    blank_start = i
                blank_end = i
                #scheduling_delay += self.__f_time_diff(t[0], t[1])
                #self.sr_latency.append(self.__f_time_diff(t[0], t[1]))

        for i, t in enumerate(self.sr):
            if t[0] > self.tx[-1][0]:
                break 
            if i == 0 and t[0] >= start_time and t[1] <= fin_time:
                if sr_start == -1:
                    sr_start = i
                sr_end = i
                first_delay = self.__f_time_diff(t[0], t[1])
            elif i!= 0 and t[0] >= start_time and t[1] <= fin_time:
                if sr_start == -1:
                    sr_start = i
                sr_end = i
                scheduling_delay += self.__f_time_diff(t[0], t[1])
                self.sr_latency.append(self.__f_time_diff(t[0], t[1]))
                
                #print('Sched: ',self.__f_time_diff(t[0], t[1]), scheduling_delay)



        #print('Blank set: ',self.blank)
        #print('Scheduling set: ',self.sr)
        #print('Tx set: ',self.tx)

        print('Total TX: ', np.sum(self.whole_record[0:fin_time, 1]))
        print('Total TB: ', np.sum(self.whole_record[0:fin_time, 2]))
        print('Total utiilized: ', self.total_utilized)
        print('Total grant: ', self.total_grant)
        print('Retx: ' ,self.cum_err_block[0], self.rlc_error)
        print('Three retx num: ', self.loss_block)

        print('SYN + First delay: ', first_delay)
        print('Blank delay: ', blank_delay)
        print('Scheduling delay: ', scheduling_delay)
        print('Tx delay: ', tx_delay)
        
        start_point = self.sr[sr_start][0]
        
        self.rlc_buffer = self.whole_record[start_point:end_point, 3]
        self.resource_block = self.rb_record[start_point:end_point]
        self.tx_power_toShow = self.tx_power_record[start_point:end_point]
        self.tx_power_toShow[np.where(self.tx_power_toShow > 23)] = -1
        self.fi_toShow = self.fi_record[start_point:end_point]
        self.all_grant = self.whole_record[start_point:end_point, 2]
        self.rsrp_toShow = self.meas_record[start_point:end_point,0]
        self.rsrq_toShow = self.meas_record[start_point:end_point,1]
        self.mcs_toShow = self.mcs_record[start_point:end_point]
        self.cqi_toShow = self.cqi_record[start_point:end_point]
        self.dl_tbs_toShow = self.dl_tbs_record[start_point:end_point]
        self.frame_tbs_toShow = self.frame_tbs_record[start_point//10:end_point//10]
        #self.rlc_buffer = self.whole_record[7180:7200, 3]
        self.blank_start = [x[0] - start_point for x in self.blank[blank_start:blank_end+1]]
        self.blank_end = [x[1] - start_point for x in self.blank[blank_start:blank_end+1]]
        self.sr_point = [x[0] - start_point for x in self.sr[sr_start:sr_end+1]]
        self.sr_end_point = [x[1] - start_point for x in self.sr[sr_start:sr_end+1]] 
        self.object_start_list = np.array(self.object_start_list) - start_point
        self.object_end_list = np.array(self.object_end_list) - start_point
        #self.sr_point = [x - self.sr[0][1] for x in self.sr_point[1:]]
        
        start_point = 99999
        start_stack = 0
        fin_point = 0
        fin_stack = 0
        for i in range(len(self.grant_list)):
            if self.sent_list[i] > 300 and start_stack == 0:
                start_point = i
                start_stack = 1
            if start_stack == 1:
                if self.sent_list[i] == 0:
                    #print('fin stack: ', i)
                    fin_stack += 1
                    if fin_stack == 3:
                        fin_point = i - 3
                        break
                else:
                    fin_stack = 0
                    
        if fin_point == 0:
            fin_point = len(self.grant_list)
                    
        #print(self.sent_list[start_point:])
        #print(start_point, fin_point)
        
        self.grant_show_list = [x*80/(1024*1024) for x in self.grant_list[start_point:fin_point]]
        self.sent_show_list = [x*80/(1024*1024) for x in self.sent_list[start_point:fin_point]]
        
        #print(self.whole_record[(start_point-1)*100:(fin_point+1)*100, 2])
        #self.pusch_list = self.whole_record[(start_point-1)*100:(fin_point+1)*100, 2]
        self.pusch_list = self.whole_record[start_point:end_point,4]
        #self.pusch_list = self.whole_record[7180:7200, 4]

        return blank_delay, scheduling_delay, tx_delay
    
    
    def analyze_object_delay(self):
        object_analysis = []
        
        for i in range(self.num_of_objects):
            per_object_latency = []
            try:
                init = self.object_latency[i][0]
                sched = self.object_latency[i][1]
                tx = self.object_latency[i][2]
                # 1. Mean of latency components
                # init
                init_latency = []
                for j in init:
                    init_latency.append(self.__f_time_diff_object(j[0], j[1]))
                # sched
                sched_latency = []
                for j in sched:
                    sched_latency.append(self.__f_time_diff_object(j[0],j[1]))
                # tx
                tx_latency = []
                tx_grant = []
                for j in tx:
                    tx_latency.append(self.__f_time_diff_object(j[0],j[1]))
                    tx_grant += self.whole_record[j[0]:j[1],2].tolist()
                    
                init_sum = np.sum(init_latency)
                sched_sum = np.sum(sched_latency)
                tx_sum = np.sum(tx_latency)
                overall_object_latency = init_sum + sched_sum + tx_sum
                
                # 2. Grant during t_tx
                # 3. Grant after sched (20ms)
                init_grant = []
                for j in init:
                    init_grant += self.whole_record[j[1]:j[1]+20,2].tolist()
                tx_rb = []
                tx_mcs = []
                for j in tx:
                    tx_rb += self.rb_record[j[0]:j[1]].tolist()
                    tx_mcs += self.mcs_record[j[0]:j[1]].tolist()
                per_object_latency.append([overall_object_latency, init_sum, sched_sum, tx_sum, tx_grant, init_grant, tx_rb, tx_mcs])
                object_analysis.append(per_object_latency)
            except:
                pass

        overall_mean = 0
        init_mean = 0
        sched_mean = 0
        tx_mean = 0
        grant_mean = 0
        initial_grant_mean = 0
        sched_grant_mean = 0
        
        overall_arr = []
        init_arr = []
        sched_arr = []
        tx_arr = []
        grant_arr = []    
        rb_arr = []
        mcs_arr = []
            
        for i,object in enumerate(object_analysis[1:]):
            print('=======================================')
            print('Overall latency of Object ',i+1 , ': ',object[0][0])
            print('Init latency of Object ', i+1 , ': ',object[0][1])
            print('Sched latency of Object ', i+1 , ': ',object[0][2])
            print('Tx latency of Object ', i+1 , ': ',object[0][3])      
            print('Mean grant of Object ', i+1 , ': ', np.mean(object[0][4]))
            print('Initial grant of Object ', i+1 , ': ', np.mean(object[0][5]))
            print('RB of Object ', i+1 , ': ', np.mean(object[0][6]))
            print('=======================================')
            overall_mean += object[0][0]/len(object_analysis[1:])
            overall_arr.append(object[0][0])
            init_mean += object[0][1]/len(object_analysis[1:])
            init_arr.append(object[0][1])
            sched_mean += object[0][2]/len(object_analysis[1:])
            sched_arr.append(object[0][2])
            tx_mean += object[0][3]/len(object_analysis[1:])
            tx_arr.append(object[0][3])
            grant_mean+= np.mean(object[0][4])/len(object_analysis[1:])
            grant_arr.append(object[0][4])
            initial_grant_mean += np.mean(object[0][5])/len(object_analysis[1:])
            sched_grant_mean += np.mean(object[0][6])/len(object_analysis[1:])
            rb_arr.append(np.array(object[0][6]))
            mcs_arr.append(np.array(object[0][7]))
          
        analysis_dict = {}
        analysis_dict['overall'] = overall_arr
        analysis_dict['init'] = init_arr
        analysis_dict['sched'] = sched_arr
        analysis_dict['tx'] = tx_arr
        analysis_dict['grant'] = grant_arr
        analysis_dict['rb'] = rb_arr
        analysis_dict['mcs'] = mcs_arr
            
        # Calculate 95th delay (for t_sched)
        overall_arr = np.array(overall_arr)
        sched_arr = np.array(sched_arr)
        sched_ratio = sched_arr/overall_arr
        try:
            sched_95 = np.percentile(sched_arr, 95, interpolation = 'nearest')
            overall_95 = overall_arr[np.where(sched_arr == sched_95)[0]][0]
            sched_ratio_95 = sched_95/overall_95
        except: 
            sched_ratio_95 = 0
        
        ## Summary
        print('==============Summary==================')
        try:
            print('Overall latency of Object : ',overall_mean)
            print('Init latency of Object : ',init_mean, init_mean/overall_mean)
            print('Sched latency of Object : ',sched_mean, sched_mean/overall_mean, sched_ratio_95, np.std(sched_arr))
            print('Sched statistics: ',  np.percentile(sched_arr, 0, interpolation = 'nearest'),
                  np.percentile(sched_arr, 25, interpolation = 'nearest'), np.percentile(sched_arr, 50, interpolation = 'nearest'), 
                  np.percentile(sched_arr, 75, interpolation = 'nearest'),
                   np.percentile(sched_arr, 100, interpolation = 'nearest'))
            print('Tx latency of Object : ',tx_mean, tx_mean/overall_mean)
            print('Mean grant of Object : ', np.mean(grant_arr), np.std(grant_arr))
            print('Initial grant of Object : ', initial_grant_mean)
            print('RB of Object : ', np.mean(rb_arr), np.std(rb_arr))
            print('=======================================')
        except:
            print('Error, check is the log about object transmission (not full buffer traffic)')
            
        return analysis_dict, overall_mean, init_mean, sched_mean, tx_mean, grant_mean, init_arr, sched_arr, grant_arr, overall_arr, rb_arr, mcs_arr
            
    def analyze_bullet_object_delay(self):
        return
