#!/usr/bin/python
# Filename: msg_logger.py
"""
A simple message dumper in stdio and/or file

Author: Yuanjie Li, Zengwen Yuan
"""


from mobile_insight.analyzer import Analyzer
from kivy.logger import Logger
from jnius import autoclass
from service import mi2app_utils as util

try:
    import xml.etree.cElementTree as ET
    
except ImportError:
    import xml.etree.ElementTree as ET
    
import io
from datetime import datetime
import json
import time
import os

## Goodsol 1101
import mmap

__all__ = ["MsgLogger"]

overlink_msg1_name = '/sdcard/cellular_link.txt'
overlink_msg2_name = '/sdcard/cellular_buffer.txt'
overlink_msg_time = 0
overlink_tbs = 0
overlink_rb = 0
overlink_rb_std = 0
overlink_first_buffer_size = 0
overlink_final_buffer_size = 0 

bullet_timeout_checker = 12


class MsgLogger(Analyzer):
    """
    A simple dumper to print messages
    """

    def __init__(self):
        Analyzer.__init__(self)
        # a message dump has no analyzer in from/to_list
        # it only has a single callback for the source

        with open(overlink_msg1_name, 'w+b') as f:
            f.write(bytes(256))
        with open(overlink_msg2_name, 'w+b') as f:
            f.write(bytes(256))

        self.__msg_log = []  # in-memory message log
        self.add_source_callback(self.__dump_message)
        self.decode_type = 0
        self._save_file_path = None
        self._save_file = None
        self._dump_type = self.ALL

        self.fn = -1
        self.sfn = -1

    # get absolute time
    def __f_time(self):
        return self.fn * 10 + self.sfn

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

    def __dump_message(self, msg):
        if not msg.data:
            return
        #self.__msg_log.append(msg)
        self.overlink_get_info(msg)


    def overlink_get_info(self, msg):
        global overlink_msg_time
        global overlink_tbs
        global overlink_rb
        global overlink_buffer_size
        global bullet_timeout_checker

        #overlink_tbs = 0
        #overlink_rb = 0
        overlink_first_buffer_size = 0
        overlink_final_buffer_size = 0

        current_tbs = 0
        current_rb = 0

        if msg.type_id == "LTE_PHY_PUSCH_Tx_Report":
            log_item = msg.data.decode()
            if 'Records' in log_item:
                for record in log_item['Records']:
                    #overlink_msg_time = record['Current SFN SF']
                    current_tbs += record['PUSCH TB Size']
                    current_rb += record['Num of RB']
                    #self.log_info('TBS:'+str(overlink_tbs))
                    if bullet_timeout_checker == 10:
                        overlink_tbs = record['PUSCH TB Size']
                        overlink_rb = record['Num of RB']
                        bullet_timeout_checker = 0
                    elif bullet_timeout_checker == 0:
                        overlink_tbs = 0.25*record['PUSCH TB Size'] + 0.75*overlink_tbs
                        overlink_rb = 0.25*record['Num of RB'] + 0.75*overlink_rb
                self.write_msg1_file(str(log_item['timestamp'])+'$'+str(current_tbs)+'$'+str(current_rb)+'$'+str(int(overlink_tbs*10))+'$'+str(int(overlink_rb*10))+'$')
        if msg.type_id == "LTE_MAC_UL_Buffer_Status_Internal":
            log_item = msg.data.decode()
            for packet in log_item['Subpackets']:
                first_sample = packet['Samples'][0]
                final_sample = packet['Samples'][-1]
                #SFN = final_sample['Sub FN']
                #FN = final_sample['Sys FN']
                #self.update_time(SFN, FN)
                #overlink_msg_time = self.__f_time()
                try:
                    first_data = first_sample['LCIDs'][-1]
                    overlink_first_buffer_size = first_data['Total Bytes']
                except:
                    pass
                try:
                    final_data = final_sample['LCIDs'][-1]
                    overlink_final_buffer_size = final_data['Total Bytes']
                except:
                    pass
                if overlink_first_buffer_size < 1000 and overlink_final_buffer_size < 1000:
                    bullet_timeout_checker += 1 
                else:
                    bullet_timeout_checker = 0
            self.write_msg2_file(str(log_item['timestamp'])+'$'+str(overlink_first_buffer_size)+'$'+str(overlink_final_buffer_size)+'$')
        #self.log_info(str(datetime.now())+':'+str(log_item['timestamp'])+':'+str(overlink_final_buffer_size)+':'+str(overlink_tbs))
        

    def write_msg1_file(self, data):
        with open(overlink_msg1_name, 'r+b') as f:
            with mmap.mmap(f.fileno(), length = 0, access = mmap.ACCESS_WRITE) as mm:
                data_byte = str(data).encode('utf-8')
                mm.write(data_byte)

    def write_msg2_file(self, data):
        with open(overlink_msg2_name, 'r+b') as f:
            with mmap.mmap(f.fileno(), length = 0, access = mmap.ACCESS_WRITE) as mm:
                data_byte = str(data).encode('utf-8')
                mm.write(data_byte)


    # Decoding scheme

    NO_DECODING = 0
    XML = 1
    JSON = 2
    DICT = 3

    # Dump type
    STDIO_ONLY = 4
    FILE_ONLY = 5
    ALL = 6

    def set_decoding(self, decode_type):
        """
        Specify how to decode the messages

        :param decode_type: specify how to decode messages. It can be MsgLogger.NO_DECODING, MsgLogger.XML or MsgLogger.JSON
        :type decode_type: int
        """

        self.decode_type = decode_type

    def __del__(self):
        if self._save_file:
            self._save_file.close()

    def set_dump_type(self, dump_type):
        """
        Specify if dump message to stdio and/or file

        :param dump_type: the dump type
        :type dump_type: STDIO_ONLY, FILE_ONLY, ALL
        """
        if dump_type != self.STDIO_ONLY \
                and dump_type != self.FILE_ONLY \
                and dump_type != self.ALL:
            return
        self._dump_type = dump_type

    def set_decode_format(self, msg_format):
        """
        Configure the format of decoded message. If not set, the message will not be decoded

        :param msg_format: the format of the decoded message
        :type msg_format: NO_DECODING, XML, JSON or DICT
        """
        if msg_format != self.NO_DECODING \
                and msg_format != self.XML \
                and msg_format != self.JSON \
                and msg_format != self.DICT:
            return

        self.decode_type = msg_format

    def save_decoded_msg_as(self, filepath):
        """
        Save decoded messages as a plain-text file.
        If not called, by default MsgLogger will not save decoded results as file.

        :param filepath: the path of the file to be saved
        :type filepath: string
        """

        if not isinstance(filepath, str):
            return

        self._save_file_path = filepath

        try:
            if self._save_file:
                self._save_file.close()
                self._save_file = None

            self._save_file = open(self._save_file_path, 'w')
        except OSError as err:
            self.log_error("I/O error: {0}".format(err))

    