#-*- coding:utf-8 -*-
import pandas as pd 
import matplotlib.pyplot as plt

def read_data(path):
    return pd.read_csv(path, index_col = False, sep = " ")

def draw_send_rate(exp, df1, df2):
    def cal_rate(times, bytes):
        last_time = 0 
        last_byte = 0
        rate  = []
        for time, byte in zip(times, bytes):
            rate.append((byte-last_byte)/(time - last_time + 1e-7))
            last_time = time 
            last_byte = byte 
        return rate 

    assert isinstance(df1, pd.DataFrame)
    fig_name = "./%s/bytes.pdf"%exp
    time_ax1 = df1["timestamp_ns"]
    time_ax1 = time_ax1.apply(lambda x : int((x - time_ax1.min())/1000))
    
    time_ax2 = df2["timestamp_ns"]
    time_ax2 = time_ax2.apply(lambda x : int((x - time_ax2.min())/1000))

    bytes_sent1 = df1["bytes_sent"]
    bytes_sent2 = df2["bytes_sent"]
    
    #rates_sent = cal_rate(time_ax, bytes_sent)



    # print(DRAW.dictTemp)
    plt.figure(figsize=(40, 30))
    plt.rcParams['xtick.direction'] = 'in'
    plt.rcParams['ytick.direction'] = 'in'
    bwith = 2
    ax = plt.gca()
    ax.spines['bottom'].set_linewidth(bwith)
    ax.spines['left'].set_linewidth(bwith)
    ax.spines['top'].set_linewidth(bwith)
    ax.spines['right'].set_linewidth(bwith)

    # 折线 eMPTCP
    plt.plot(time_ax1, bytes_sent1, lw=10, zorder=2,  label="bytes_sent1",markersize=30,color="orange",alpha=.99)
    plt.plot(time_ax2, bytes_sent2, lw=10, zorder=2,  label="bytes_sent2",markersize=30,color="blue",alpha=.99)
    # 折线 MPTCP
    #plt.plot(DRAW, TCP, lw=10, zorder=2,  label="eMPTCP", marker="*",markersize=30,color="green",alpha=.99)

    plt.ylabel('bytes', fontsize=35, labelpad=0.5)
    plt.xlabel('time_us', fontsize=35, labelpad=0.5)
    # plt.xticks(rotation=-10)
    plt.xticks(size=24)
    plt.yticks(size=20)

    plt.grid(axis='y', linestyle='-', zorder=0, linewidth=1)
    plt.grid(axis='x', linestyle='-', zorder=0, linewidth=1)

    plt.tight_layout()

    # 网格线加粗
    ax.axvline("10000", linestyle='--', color='k',linewidth=6)
    plt.legend(fontsize=40, edgecolor='black', facecolor='white', framealpha=1.0,
               fancybox=False)

    # plt.show()
    plt.savefig(fig_name)

def draw_wnd(exp, df1, df2):
    assert isinstance(df1, pd.DataFrame)
    fig_name = "./%s/window.pdf"%exp
    time_ax1 = df1["timestamp_ns"]
    time_ax1 = time_ax1.apply(lambda x : int((x - time_ax1.min())/1000))
    
    time_ax2 = df2["timestamp_ns"]
    time_ax2 = time_ax2.apply(lambda x : int((x - time_ax2.min())/1000))

    snd_cwnd1 = df1["snd_cwnd"]
    snd_ssthresh1 = df1["snd_ssthresh"]

    snd_cwnd2 = df2["snd_cwnd"]
    snd_ssthresh2 = df2["snd_ssthresh"]

    #rates_sent = cal_rate(time_ax, bytes_sent)

    # print(DRAW.dictTemp)
    plt.figure(figsize=(40, 30))
    plt.rcParams['xtick.direction'] = 'in'
    plt.rcParams['ytick.direction'] = 'in'
    bwith = 2
    ax = plt.gca()
    ax.spines['bottom'].set_linewidth(bwith)
    ax.spines['left'].set_linewidth(bwith)
    ax.spines['top'].set_linewidth(bwith)
    ax.spines['right'].set_linewidth(bwith)


    #ax2 = ax.twinx()
    # 折线 eMPTCP
    plt.plot(time_ax1, snd_cwnd1, lw=10, zorder=2,  label="snd_cwnd1",linestyle="solid",color="yellow",alpha=.99)
    #ax2.plot(time_ax1, snd_wnd1, lw=10, zorder=2,  label="snd_wnd1",linestyle='dotted',color="red",alpha=.99)
    #plt.plot(time_ax1, snd_ssthresh1, lw=10, zorder=2,  label="snd_ssthresh1",linestyle="dashed",color="red",alpha=.99)
    plt.plot(time_ax2, snd_cwnd2, lw=10, zorder=2,  label="snd_cwnd2",linestyle="solid",color="blue",alpha=.99)
    #ax2.plot(time_ax2, snd_wnd2, lw=10, zorder=2,  label="snd_wnd2",linestyle='dotted',color="green",alpha=.99)
    #plt.plot(time_ax2, snd_ssthresh2, lw=10, zorder=2,  label="snd_ssthresh2",linestyle='dashed',color="grey",alpha=.99)

    # 折线 MPTCP
    #plt.plot(DRAW, TCP, lw=10, zorder=2,  label="eMPTCP", marker="*",markersize=30,color="green",alpha=.99)

    plt.ylabel('size', fontsize=35, labelpad=0.5)
    plt.xlabel('time_us', fontsize=35, labelpad=0.5)
    # plt.xticks(rotation=-10)
    plt.xticks(size=24)
    plt.yticks(size=30)

    plt.grid(axis='y', linestyle='-', zorder=0, linewidth=1)
    plt.grid(axis='x', linestyle='-', zorder=0, linewidth=1)

    plt.tight_layout()

    # 网格线加粗
    ax.axvline("10000", linestyle='--', color='k',linewidth=6)
    plt.legend(fontsize=40, edgecolor='black', facecolor='white', framealpha=1.0,
               fancybox=False)

    # plt.show()
    plt.savefig(fig_name)

def draw_snd_wnd(exp, df1, df2):
    assert isinstance(df1, pd.DataFrame) and isinstance(df2, pd.DataFrame) 
    fig_name = "./%s/snd_wnd.pdf"%exp
    time_ax1 = df1["timestamp_ns"]
    time_ax1 = time_ax1.apply(lambda x : int((x - time_ax1.min())/1000))
    
    time_ax2 = df2["timestamp_ns"]
    time_ax2 = time_ax2.apply(lambda x : int((x - time_ax2.min())/1000))

    snd_wnd1 = df1["snd_wnd"]

    snd_wnd2 = df2["snd_wnd"]

    #rates_sent = cal_rate(time_ax, bytes_sent)

    # print(DRAW.dictTemp)
    plt.figure(figsize=(40, 30))
    plt.rcParams['xtick.direction'] = 'in'
    plt.rcParams['ytick.direction'] = 'in'
    bwith = 2
    ax = plt.gca()
    ax.spines['bottom'].set_linewidth(bwith)
    ax.spines['left'].set_linewidth(bwith)
    ax.spines['top'].set_linewidth(bwith)
    ax.spines['right'].set_linewidth(bwith)


    #ax2 = ax.twinx()
    # 折线 eMPTCP
    #plt.plot(time_ax1, snd_cwnd1, lw=10, zorder=2,  label="snd_cwnd1",linestyle="solid",color="yellow",alpha=.99)
    plt.plot(time_ax1, snd_wnd1, lw=10, zorder=2,  label="snd_wnd1",linestyle='dotted',color="red",alpha=.99)
    #plt.plot(time_ax1, snd_ssthresh1, lw=10, zorder=2,  label="snd_ssthresh1",linestyle="dashed",color="red",alpha=.99)
    #plt.plot(time_ax2, snd_cwnd2, lw=10, zorder=2,  label="snd_cwnd2",linestyle="solid",color="blue",alpha=.99)
    plt.plot(time_ax2, snd_wnd2, lw=10, zorder=2,  label="snd_wnd2",linestyle='dotted',color="green",alpha=.99)
    #plt.plot(time_ax2, snd_ssthresh2, lw=10, zorder=2,  label="snd_ssthresh2",linestyle='dashed',color="grey",alpha=.99)

    # 折线 MPTCP
    #plt.plot(DRAW, TCP, lw=10, zorder=2,  label="eMPTCP", marker="*",markersize=30,color="green",alpha=.99)

    plt.ylabel('bytes', fontsize=35, labelpad=0.5)
    plt.xlabel('time_us', fontsize=35, labelpad=0.5)
    # plt.xticks(rotation=-10)
    plt.xticks(size=24)
    plt.yticks(size=30)

    plt.grid(axis='y', linestyle='-', zorder=0, linewidth=1)
    plt.grid(axis='x', linestyle='-', zorder=0, linewidth=1)

    plt.tight_layout()

    # 网格线加粗
    ax.axvline("10000", linestyle='--', color='k',linewidth=6)
    plt.legend(fontsize=40, edgecolor='black', facecolor='white', framealpha=1.0,
               fancybox=False)

    # plt.show()
    plt.savefig(fig_name)

def draw_send_buf(exp, df1, df2):
    assert isinstance(df1, pd.DataFrame)
    fig_name = "./%s/snd_buf.pdf"%exp
    time_ax1 = df1["timestamp_ns"]
    time_ax1 = time_ax1.apply(lambda x : int((x - time_ax1.min())/1000))
    
    time_ax2 = df2["timestamp_ns"]
    time_ax2 = time_ax2.apply(lambda x : int((x - time_ax2.min())/1000))

    #sk_sndbuf1 = df1["sk_sndbuf"]
    sk_wmem_queued1 = df1["sk_wmem_queued"]
    
    #sk_sndbuf2 = df2["sk_sndbuf"]
    sk_wmem_queued2 = df2["sk_wmem_queued"]
    
    #rates_sent = cal_rate(time_ax, bytes_sent)



    # print(DRAW.dictTemp)
    plt.figure(figsize=(40, 30))
    plt.rcParams['xtick.direction'] = 'in'
    plt.rcParams['ytick.direction'] = 'in'
    bwith = 2
    ax = plt.gca()
    ax.spines['bottom'].set_linewidth(bwith)
    ax.spines['left'].set_linewidth(bwith)
    ax.spines['top'].set_linewidth(bwith)
    ax.spines['right'].set_linewidth(bwith)

    # 折线 eMPTCP
    #plt.plot(time_ax1, sk_sndbuf1, lw=10, zorder=2,  label="sk_sndbuf1", linestyle="solid",color="orange",alpha=.99)
    plt.plot(time_ax1, sk_wmem_queued1, lw=10, zorder=2,  label="sk_wmem_queued1",linestyle="dashed",color="red",alpha=.99)
    #plt.plot(time_ax2, sk_sndbuf2, lw=10, zorder=2,  label="sk_sndbuf2",linestyle="solid",color="blue",alpha=.99)
    plt.plot(time_ax2, sk_wmem_queued2, lw=10, zorder=2,  label="sk_wmem_queued2",linestyle="dashed",color="grey",alpha=.99)
    # 折线 MPTCP
    #plt.plot(DRAW, TCP, lw=10, zorder=2,  label="eMPTCP", marker="*",markersize=30,color="green",alpha=.99)

    plt.ylabel('bytes', fontsize=35, labelpad=0.5)
    plt.xlabel('time_us', fontsize=35, labelpad=0.5)
    # plt.xticks(rotation=-10)
    plt.xticks(size=24)
    plt.yticks(size=20)

    plt.grid(axis='y', linestyle='-', zorder=0, linewidth=1)
    plt.grid(axis='x', linestyle='-', zorder=0, linewidth=1)

    plt.tight_layout()

    # 网格线加粗
    ax.axvline("10000", linestyle='--', color='k',linewidth=6)
    plt.legend(fontsize=40, edgecolor='black', facecolor='white', framealpha=1.0,
               fancybox=False)

    # plt.show()
    plt.savefig(fig_name)

if __name__ == '__main__':
    import sys 
    import os 
    expname = sys.argv[1]
    if not os.path.exists("./%s"%expname):
        os.mkdir("./%s"%expname)
    df1 = read_data("./%s_sub1.txt"%expname)
    df2 = read_data("./%s_sub2.txt"%expname)
    draw_send_rate(expname, df1, df2)
    draw_wnd(expname, df1, df2)
    draw_snd_wnd(expname, df1, df2)
    draw_send_buf(expname, df1, df2)