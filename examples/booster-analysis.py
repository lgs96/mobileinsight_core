#!/usr/bin/python

import os
import sys
import shutil
import traceback

import matplotlib.pyplot as plt
import numpy as np
import logging

from mobile_insight.monitor import OfflineReplayer
from uplink_booster_analyzer import lte_measurement_analyzer
from uplink_booster_analyzer import goodsol_analyzer
from uplink_booster_analyzer import uplink_latency_analyzer
from uplink_booster_analyzer import ul_mac_latency_analyzer
from uplink_booster_analyzer import lte_wireless_error_analyzer
from uplink_booster_analyzer import object_latency_analyzer
from uplink_booster_analyzer import lte_mac_analyzer
from uplink_booster_analyzer import lte_rlc_analyzer
from uplink_booster_analyzer import lte_rrc_analyzer
from uplink_booster_analyzer import bsr_table
from uplink_booster_analyzer import lte_pdcp_ulgap_analyzer
    

def lte_phy_analysis():
  src = OfflineReplayer()
  #src.set_input_path("./logs/latency_sample.mi2log")
  src.set_input_path(sys.argv[1])
  # print (sys.argv[1])

  phy_analyzer = goodsol_analyzer.MyAnalyzer()
  #phy_analyzer.set_source(src)

  meas_analyzer = lte_measurement_analyzer.LteMeasurementAnalyzer()
  meas_analyzer.set_source(src)

  uplink_analyzer = uplink_latency_analyzer.UplinkLatencyAnalyzer()
  #uplink_analyzer.set_source(src)

  mac_analyzer = lte_mac_analyzer.LteMacAnalyzer()
  #mac_analyzer.set_source(src)
  
  rlc_analyzer = lte_rlc_analyzer.LteRlcAnalyzer()
  rlc_analyzer.set_source(src)

  error_analyzer = lte_wireless_error_analyzer.LteWirelessErrorAnalyzer()
  #error_analyzer.set_source(src)

  fb_analyzer = object_latency_analyzer.ObjectLatencyAnalyzer()
  fb_analyzer.set_source(src)

  pdcp_analyer = lte_pdcp_ulgap_analyzer.LtePdcpUlGapAnalyzer()
  #pdcp_analyer.set_source(src)

  #mac_analyzer = lte_mac_analyzer.LteMacAnalyzer()
  #mac_analyzer.set_source(src)
  
  rrc_analyzer = lte_rrc_analyzer.LteRrcAnalyzer()
  #rrc_analyzer.set_source(src)

  src.run()

  return phy_analyzer, meas_analyzer, mac_analyzer, rlc_analyzer, fb_analyzer, pdcp_analyer


phy, meas, mac, rlc, fb, pdcp = lte_phy_analysis()
# print stats.all_packets
# print stats.cum_err_block
# print stats.cum_block

#print('Total Tx (MAC analyzer) ', mac.total_tx)

start_second = 0
start_subframe = 100
end_second = 100000
end_subframe = 0

fb.calc_delay(start_time = 10240*start_second + start_subframe, 
              fin_time = 10240*end_second + end_subframe, object_size = int(sys.argv[2])*1024)


print('Total data Tx (RLC analyzer): ', rlc.total_data_pdu)
print('Total ctrl Tx (RLC analyzer): ', rlc.total_ctrl_pdu)
#print('PDCP loss: ', pdcp.loss_sum)

rsrp_list = meas.serv_cell_rsrp
rsrq_list = meas.serv_cell_rsrq
print('RSRP list: ', meas.serv_cell_rsrp)
print('RSRQ list: ', meas.serv_cell_rsrq)

print('RSRP mean, std: ', np.mean(rsrp_list), np.std(rsrp_list))
print('RSRQ mean, std: ', np.mean(rsrq_list), np.std(rsrq_list))

for i, rsrp_sample in enumerate(fb.rsrp_toShow):
    if i!= 0 and rsrp_sample >= 0:
      fb.rsrp_toShow[i] = fb.rsrp_toShow[i - 1]
      
for i, rsrq_sample in enumerate(fb.rsrq_toShow):
    if i!= 0 and rsrq_sample >= 0:
      fb.rsrq_toShow[i] = fb.rsrq_toShow[i - 1]
 
mask = fb.rsrp_toShow < 0     
rsrp = fb.rsrp_toShow[mask]
mask = fb.rsrq_toShow < 0   
rsrq = fb.rsrq_toShow[mask]

print('Cell Id: ', fb.cell_id)
print('Num object: ', fb.num_of_objects)
print('RSRP mean, std: ', np.mean(rsrp), np.std(rsrp))
print('RSRQ mean, std: ', np.mean(rsrq), np.std(rsrq))

print('Blank: ', fb.blank)
print('Scheduling: ', fb.sr)
print('Tx burst: ', fb.tx)
print('Object: ', fb.object_latency)
_, _, _, _, _, _, init_arr, sched_arr, grant_arr, overall_arr, rb_arr, mcs_arr = fb.analyze_object_delay()

np.save('./overlink_data/init_arr', init_arr)
np.save('./overlink_data/sched_arr', sched_arr)
np.save('./overlink_data/grant_arr', grant_arr)
np.save('./overlink_data/bsr_grant_arr', np.array(fb.object_bsr_list))
np.save('./overlink_data/overall_arr', overall_arr)
np.save('./overlink_data/object_rb_arr', rb_arr)
np.save('./overlink_data/object_mcs_arr', mcs_arr)

print('Scheduling mean, std: ', np.mean(fb.sr_latency), np.std(fb.sr_latency))
print('Blank mean, std: ',np.mean(fb.blank_latency), np.std(fb.blank_latency))
print('Tx mean, std: ',np.mean(fb.tx_latency), np.std(fb.tx_latency))


cor_index = fb.rlc_buffer >= 0
cor_buffer = fb.rlc_buffer[cor_index]
cor_bsr = np.zeros(len(cor_buffer))
for i, _ in enumerate(cor_buffer):
  try:
    cor_bsr[i] = bsr_table.bsr_table(cor_buffer[i-5])
  except:
    print('B size: ' ,cor_buffer[i-5])
    cor_bsr[i] = 0
cor_bytes = fb.all_grant[cor_index]
cor_power = fb.tx_power_toShow[cor_index]
cor_rb = fb.resource_block[cor_index]
cor_mcs = fb.mcs_toShow[cor_index]

print('========Correlation========')
print('Tx power/RB: ', np.corrcoef(cor_power, cor_rb)[0,1])
print('Grant bytes/RB: ', np.corrcoef(cor_bytes, cor_rb)[0,1])
print('Grant bytes/Tx power: ', np.corrcoef(cor_power, cor_rb)[0,1])
print('Grant bytes/BSR: ', np.corrcoef(cor_bytes, cor_bsr)[0,1])
print('RB/BSR: ', np.corrcoef(cor_rb, cor_bsr)[0,1])
print('Tx power/BSR: ', np.corrcoef(cor_power, cor_bsr)[0,1])
print('Grant bytes/MCS: ', np.corrcoef(cor_bytes, cor_mcs)[0,1])
#print('Frame TBS: ', fb.frame_tbs_toShow[:])


mask_rsrp = fb.rsrp_toShow < 0 
mask_tbs = fb.mcs_toShow > 0
mask = np.in1d(mask_rsrp, mask_tbs)
masked_rsrp = fb.rsrp_toShow[mask]
masked_mcs = fb.mcs_toShow[mask]
rsrp_mcs = [masked_rsrp, masked_mcs]

np.save('./overlink_data/rlc_buffer', fb.rlc_buffer)
np.save('./overlink_data/sr_point', fb.sr_point)
np.save('./overlink_data/sr_end_point', fb.sr_end_point)
np.save('./overlink_data/all_grant', fb.all_grant)
np.save('./overlink_data/sched_latency', fb.sr_latency)
np.save('./overlink_data/object_start', np.array(fb.object_start_list))
np.save('./overlink_data/object_end', np.array(fb.object_end_list))
np.save('./overlink_data/rsrp_mcs', np.array(rsrp_mcs))
np.save('./overlink_data/mcs', np.array(fb.mcs_toShow))
np.save('./overlink_data/rb', np.array(fb.resource_block))

enableFig = True
if enableFig:
  #fig1 = plt.figure(1)
  fig1, ax1 = plt.subplots()
  plt.title('RLC buffer/TBS')
  plt.xlabel('Time (ms)')
  
  ax1.plot(fb.rlc_buffer[:], c = 'blue')
  ax1.set_ylabel('Buffer size (Bytes)')
  
  ax2 = ax1.twinx()
  ax2.plot(np.arange(len(fb.all_grant)),fb.all_grant, c = 'orange', linestyle = 'dotted')
  ax2.set_ylabel('TBS')
  plt.legend(['Granted', 'Utilized'])
  
  
  for i in range(len(fb.blank_start)):
    plt.scatter(fb.blank_start[i], 0, marker = '*',  c = 'black', s = 100)
    plt.plot([fb.blank_start[i], fb.blank_end[i]], [0,0], c = 'magenta', linestyle ='-.')
  
  for i in range(len(fb.sr_point)):
    plt.scatter(fb.sr_point[i], 0, marker = 'x',  c = 'r', s = 100)
    plt.scatter(fb.sr_end_point[i], 0, marker = 'o',  c = 'g', s = 100)
    plt.plot([fb.sr_point[i], fb.sr_end_point[i]], [0,0], c = 'r', linestyle ='--')
    
  grant_x = np.arange(len(fb.grant_show_list))*100

  plt.figure(2)
  plt.title('Wireless throughput')
  plt.xlabel('Time (ms)')
  plt.ylabel('Mbps')
  plt.plot(grant_x, fb.grant_show_list)
  plt.plot(grant_x, fb.sent_show_list)
  plt.legend(['Granted', 'Utilized'])

  plt.figure(3)
  plt.title('Cumulative UL TBS')
  plt.xlabel('Time (ms)')
  plt.ylabel('Bytes')
  plt.plot(fb.pusch_list[:])

  plt.figure(4)
  plt.title('RSRQ')
  plt.xlabel('Time')
  plt.ylabel('dBm')
  plt.plot(rsrq)
  
  plt.figure(5)
  plt.title('RSRP')
  plt.xlabel('Time')
  plt.ylabel('dBm')
  plt.plot(rsrp)
  
  plt.figure(6)
  plt.title('UL TBS')
  plt.xlabel('Time (ms)')
  plt.ylabel('Bytes')
  plt.plot(fb.all_grant)
  
  plt.figure(7)
  plt.title('Tx power')
  plt.xlabel('Time (ms)')
  plt.ylabel('dBm')
  plt.plot(fb.tx_power_toShow)
  
  plt.figure(8)
  plt.title('F(i)')
  plt.xlabel('Time (ms)')
  plt.ylabel('dBm')
  plt.plot(fb.fi_toShow)
  
  plt.figure(9)
  plt.title('BSR')
  plt.xlabel('Time (ms)')
  plt.ylabel('#')
  plt.plot(cor_bsr)
  
  plt.figure(10)
  plt.title('MCS')
  plt.xlabel('Time (ms)')
  plt.ylabel('bits per resource element')
  plt.ylim([0,8])
  plt.plot(fb.mcs_toShow)
  
  plt.figure(11)
  plt.title('Frame TBS')
  plt.xlabel('Time (ms)')
  plt.ylabel('Bytes')
  plt.plot(fb.frame_tbs_toShow)

  plt.figure(12)
  plt.title('RSRP-MCS')
  plt.xlabel('RSRP (-dBm)')
  plt.ylabel('Bits per subcarrier')
  plt.scatter(masked_rsrp, masked_mcs)
  
  plt.show()
#plt.savefig('buffer.png')
