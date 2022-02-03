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


# import threading


class FirstByteAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.add_source_callback(self.__msg_callback)

        # Timers 
        self.fn = -1
        self.sfn = -1

        # PHY stats
        self.cum_err_block = {0: 0, 1: 0}  # {0:xx, 1:xx} 0 denotes uplink and 1 denotes downlink
        self.cum_block = {0: 0, 1: 0}  # {0:xx, 1:xx} 0 denotes uplink and 1 denotes downlink

        # MAC buffer
        self.last_buffer = 0
        self.packet_queue = []

        # Stats
        self.all_packets = []
        self.tx_packets = []
        self.tmp_dict = {}

        # First byte latency (Goodsol)
        self.first_byte_latency = [] 
        self.three_way_latency = []
        self.tx_latency = []
        self.pend_latency = []
        self.blank_latency = []

        self.temp_fbl = [0, 0]
        self.temp_twl = [0, 0]
        self.temp_tl = [0, 0]
        self.temp_pend = [0, 0]
        self.temp_blank = [0, 0]

        self.fb_progress = False
        self.tw_progress = True
        self.tx_progress = False
        self.pend_progress = False
        self.blank_progress = False

        self.total_tb = 0
        self.sent_bytes = 0

        self.get_grant = False

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

    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        source.enable_log("LTE_PHY_PUSCH_Tx_Report")
        source.enable_log("LTE_MAC_UL_Buffer_Status_Internal")
        source.enable_log("LTE_PHY_PUCCH_Tx_Report")
        source.enable_log("LTE_MAC_UL_Transport_Block")

    # get difference between two time value
    def __f_time_diff(self, t1, t2):
        if t1 > t2:
            t_diff = t2 + 10240 - t1
        else:
            t_diff = t2 - t1 + 1
        return t_diff

    # get absolute time
    def __f_time(self):
        return self.fn * 10 + self.sfn

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

        if msg.type_id == "LTE_PHY_PUSCH_Tx_Report":
            log_item = msg.data.decode()
            #print('PUSCH_Tx_Report callback: ', log_item,"\n")
            if 'Records' in log_item:
                for record in log_item['Records']:
                    self.total_tb += record['PUSCH TB Size']
                    #print('TB Size: ', record['Current SFN SF'], record['PUSCH TB Size'], self.total_tb)
                    retx_time = record['Current SFN SF']
                    if retx_time < 0:
                        retx_time += 1024

                    if record['Re-tx Index'] == 'First':
                        self.cum_block[0] += 1
                    else:
                        # print(record['Re-tx Index'])
                        self.cum_err_block[0] += 1

                        if retx_time in self.tmp_dict :
                            self.tmp_dict[retx_time]['Retx Latency'] = 8
                        else:
                            self.tmp_dict[retx_time] = {'Retx Latency': 8}
                    
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


                    # if (total_b > new_c) and ctrl_b == 0:
                    if total_b > self.last_buffer: 
                        # size, remaining buffer, incoming time, first byte time
                        self.packet_queue.append([total_b - self.last_buffer, total_b - self.last_buffer, self.__f_time(), -1])
                    elif total_b < self.last_buffer:
                        outgoing_bufer = self.last_buffer - total_b
                        while 1:
                            if self.packet_queue == []:
                                break
                            packet = self.packet_queue[0]
                            
                            #print('MAC UL Packet 0: ', packet[0], "1: ", packet[1], "2: ", packet[2], "3: ", packet[3], "\n")
                            if packet[3] == -1:
                                packet[3] = self.__f_time()
                            if packet[1] > outgoing_bufer:
                                packet[1] -= outgoing_bufer
                                break
                            else:
                                # size, waiting latency, transmission latency
                                # print self.packet_queue, self.all_packets, outgoing_bufer
                                t_now = self.__f_time()
                                if (t_now not in self.tmp_dict):
                                    self.tmp_dict[t_now] = {}
                                self.tmp_dict[t_now]['Waiting Latency'] = self.__f_time_diff(packet[2], packet[3])
                                self.tmp_dict[t_now]['Tx Latency'] = self.__f_time_diff(packet[3], self.__f_time())
                                
                                #print ([self.__f_time(), packet[0], self.__f_time_diff(packet[2], packet[3]), self.__f_time_diff(packet[3], self.__f_time())])
                                
                                print('Current time: ', self.__f_time(), ' Packet size: ', packet[0], 
                                ' Remaining buffer: ', packet[1], ' Incoming time: ',packet[2],
                                 ' Packet tx time: ', packet[3])
                                
                                self.temp_pend[0] = t_now
                                if self.blank_progress == True:
                                    self.blank_progress = False
                                    #self.blank_latency.append([t_now, packet[2]])
                                '''
                                if self.last_buffer > 0 and self.fb_progress == False and self.tx_progress == False:
                                    print('Grant: ', t_now, self.fb_progress, self.tx_progress)
                                    self.tx_progress = True
                                    self.temp_tl[0] = packet[3]
                                    self.temp_tl[1] = t_now
                                '''
                                if packet[0] > 300 and self.fb_progress == True and packet[3] >= self.temp_fbl[0]:
                                    self.temp_fbl[1] = packet[3]
                                    self.temp_tl[0] = packet[3]   
                                    self.temp_tl[1] = t_now
                                    self.tx_progress = True
                                    #print('SR progress is False')
                                    if self.tw_progress == True:
                                        self.tw_progress = False
                                        self.fb_progress = False
                                        self.pend_progress = True
                                        self.three_way_latency.append([self.temp_fbl[0], self.temp_fbl[1]])
                                        print('Three way: ',self.temp_fbl)
                                    elif self.fb_progress == True:
                                        self.fb_progress = False
                                        self.first_byte_latency.append([self.temp_fbl[0], self.temp_fbl[1]])
                                        print('First byte: ',self.temp_fbl)
                                elif self.tx_progress == True:
                                    if self.temp_tl[1] == packet[3]:
                                        self.temp_tl[1] = t_now
                                    else:
                                        self.tx_latency.append([self.temp_tl[0], self.temp_tl[1]])
                                        print('Tx: ',self.temp_tl)#, [packet[3], t_now])
                                        self.fb_progress = False
                                        self.pend_progress = True
                                        self.blank_progress = True
                                        self.tx_progress = False

                                outgoing_bufer -= packet[1]
                                del self.packet_queue[0]
                                #self.__cmp_queues(2, (packet[0], self.__f_time_diff(packet[2], packet[3]), self.__f_time_diff(packet[2], t_now), t_now, self.last_buffer - new_c) )
                
                    self.last_buffer = total_b

        if msg.type_id == "LTE_PHY_PUCCH_Tx_Report":
            self.callback_pucch(msg)
        if msg.type_id == "LTE_MAC_UL_Transport_Block":
            self.callback_ul_transport(msg)


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
                print('SR1 time: ', sr_dict['fn and subfn'], self.fb_progress, self.pend_progress, self.tx_progress)
                if self.fb_progress == False:
                    self.temp_fbl[0] = sr_dict['fn and subfn']
                    self.fb_progress = True
                    #print('SR progress is True')
                    if self.pend_progress == True:
                        self.temp_pend[1] = sr_dict['fn and subfn']
                        self.pend_latency.append([self.temp_pend[0], self.temp_pend[1]])
                        print('Pend: ', self.temp_pend)
                        self.pend_progress = False
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
                        #print('SR2 time: ', sr_dict['fn and subfn'], self.fb_progress, self.pend_progress)
                        if self.fb_progress ==False:
                            self.temp_fbl[0] = sr_dict['fn and subfn']
                            self.fb_progress = True
                            if self.pend_progress == True:
                                self.temp_pend[1] = sr_dict['fn and subfn']
                                self.pend_latency.append([self.temp_pend[0], self.temp_pend[1]])
                                print('Pend: ', self.temp_pend)
                                self.pend_progress = False
            elif uciformat == "Format 3":
                # TODO: Deal with SR event in format 3
                pass

    def callback_ul_transport(self, msg):
        log_item = msg.data.decode()
        print('UL transport: ', log_item)

    def calc_latency(self):
        total_fbl = 0
        total_pend = 0
        total_tx = 0
        total_blank = 0

        new_list = []

        for v in self.tx_latency:
            if v not in new_list:
                new_list.append(v)

        self.tx_latency = new_list

        for i in self.tx_latency:
            total_tx += self.__f_time_diff(i[0],i[1])
        if self.tx_latency[-1][0] > self.tx_latency[-1][1]:
            last_tx = self.tx_latency[-1][1] + 10240
        else:
            last_tx = self.tx_latency[-1][1]
        print(last_tx)
        for i in self.first_byte_latency:
            if i[0] < last_tx:
                total_fbl += self.__f_time_diff(i[0], i[1])
        for i in self.pend_latency:
            if i[0] < last_tx:
                total_pend += self.__f_time_diff(i[0], i[1])
        for i in self.blank_latency:
            if i[0] < last_tx:
                total_blank += self.__f_time_diff(i[0], i[1])

        print('Three way latency: ', self.__f_time_diff(self.three_way_latency[0][0], self.three_way_latency[0][1]))
        print('Total blank latency: ', total_blank)
        print('Total pending latency: ', total_pend - total_blank)
        print('Total first byte latency: ', total_fbl)
        print('Total tx latency: ', total_tx)
        print('Three way: ',self.three_way_latency)
        print('First byte: ',self.first_byte_latency)
        print('Pending: ',self.pend_latency)
        print('Blank: ', self.blank_latency)
        print('Tx: ', self.tx_latency)
        print('Total TB size: ', self.total_tb)