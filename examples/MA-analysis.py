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

fb.calc_delay(start_time = 100, fin_time = 100000)


print('Total data Tx (RLC analyzer): ', rlc.total_data_pdu)
print('Total ctrl Tx (RLC analyzer): ', rlc.total_ctrl_pdu)
#print('PDCP loss: ', pdcp.loss_sum)

rsrp_list = meas.serv_cell_rsrp
rsrq_list = meas.serv_cell_rsrq
print('RSRP list: ', rsrp_list)
print('RSRQ list: ', rsrq_list)

print('RSRP mean, std: ', np.mean(rsrp_list), np.std(rsrp_list))
print('RSRQ mean, std: ', np.mean(rsrq_list), np.std(rsrq_list))

mask = fb.rsrp_toShow < 0
rsrp = fb.rsrp_toShow[mask]
mask = fb.rsrq_toShow < 0
rsrq = fb.rsrq_toShow[mask]

print('Cell Id: ', fb.cell_id)
print('RSRP mean, std: ', np.mean(rsrp), np.std(rsrp))
print('RSRQ mean, std: ', np.mean(rsrq), np.std(rsrq))

print('Blank: ', fb.blank)
print('Scheduling: ', fb.sr)
print('Tx burst: ', fb.tx)

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
print('Frame TBS: ', fb.frame_tbs_toShow[:])

np.save('./overlink_data/rlc_buffer', fb.rlc_buffer)
np.save('./overlink_data/sr_point', fb.sr_point)
np.save('./overlink_data/sr_end_point', fb.sr_end_point)
np.save('./overlink_data/all_grant', fb.all_grant)

alpha = 0.1
def moving_average(list):
    new_list = np.zeros(len(list))
    for i in range(len(new_list)-1):
      if i==0:
        continue
      elif i==1:
        new_list[i+1] = fb.frame_tbs_toShow[0]
      else:
        new_list[i+1] = alpha*new_list[i-1] + (1-alpha)*list[i]

    return new_list

ma_list = moving_average(fb.frame_tbs_toShow[:])

print('Figure on')

plt.figure(0)
plt.title('Frame TBS')
plt.xlabel('Time (ms)')
plt.ylabel('Bytes')
plt.plot(fb.frame_tbs_toShow)
plt.plot(ma_list)

plt.figure(1)
plt.title('Frame TBS')
plt.xlabel('Time (ms)')
plt.ylabel('Error ratio')
plt.plot((fb.frame_tbs_toShow - ma_list)/fb.frame_tbs_toShow)

plt.show()