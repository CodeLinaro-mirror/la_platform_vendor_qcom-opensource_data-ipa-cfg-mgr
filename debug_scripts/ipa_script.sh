#!/bin/bash
#Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#SPDX-License-Identifier: BSD-3-Clause-Clear

if [ ! -d "/data/logs" ]; then
    echo "logs directory not found. creating logs directory..."
    mkdir -p "/data/logs"
fi

ifconfig > /data/logs/ifconfig.txt

iface=""

while read -r line; do
    var=$(echo "$line" | awk '{print $1}' | sed 's/://')
    token=$(echo "$line" | awk '{print $2}')
    if [[ "$token" == "flags"* ]] || [[ "$token" == "flags" ]]; then
        iface="$iface $var"
    elif [[ "$token" == "Link" ]] || [[ "$token" == "Link"* ]]; then
        iface="$iface $var"
    fi
done < /data/logs/ifconfig.txt

iface=$(echo "$iface" | xargs)

echo "Interfaces found:"
for i in $iface; do
    echo "$i"
done

# Function to collect tcpdumps
collect_tcpdumps() {
    local target_dir="$1"
    local is_auto_collection="$2" # "auto" if called from auto log collection

    mkdir -p "$target_dir"
    echo "Collecting tcpdumps into $target_dir"
    for i in $iface; do
        echo "Collecting 500 packets on $i into $target_dir/$i.pcap"
        temp="tcpdump -vnei $i -c500 -w $target_dir/$i.pcap &> /dev/null &" # -c500 provides a packet count limit
        eval "$temp"
        pid=$!
        if [ "$is_auto_collection" == "auto" ]; then
            echo $pid >> /data/logs/auto_tcpdump.pid
        else
            echo $pid >> /data/logs/manual_tcpdump.pid
        fi
    done
}

collect_initial_logs() {
    local target_dir="$1"
    local is_auto_collection="$2"
    mkdir -p "$target_dir"
    echo "Collecting logs into $target_dir"

    DIR="/sys/kernel/debug/"

    if [ -d "$DIR" ]; then
        echo "Running timeouts for collecting debug stats in multiple iterations..."

        cat /sys/kernel/debug/ipa/stats >> "$target_dir/ipa_stats.txt"
        sleep 5
        cat /sys/kernel/debug/ipa/stats >> "$target_dir/ipa_stats1.txt"
        sleep 5
        cat /sys/kernel/debug/ipa/stats >> "$target_dir/ipa_stats2.txt"
        sleep 5
        cat /sys/kernel/debug/ipa/stats >> "$target_dir/ipa_stats3.txt"
        sleep 5
        cat /sys/kernel/debug/ipa/pm_stats >> "$target_dir/pm_stats.txt"
        sleep 5
        cat /sys/kernel/debug/ipa/mhip_gsi_stats >> "$target_dir/mhip_gsi_stats.txt"
        sleep 5
        cat /sys/kernel/debug/ipa/odlstats >> "$target_dir/odlstats.txt"
        sleep 5
        cat /sys/kernel/debug/ipa/usb_gsi_stats >> "$target_dir/usb_gsi_stats.txt"
        sleep 5
        cat /sys/kernel/debug/ipa/wdi_gsi_stats >> "$target_dir/wdi_gsi_stats.txt"
        sleep 5
        cat /sys/kernel/debug/ipa/wdi3_gsi_stats >> "$target_dir/wdi3_gsi_stats.txt"
        sleep 5

        cat /sys/kernel/debug/ipa/msg >> "$target_dir/ipa_msg.txt"
        cat /sys/kernel/debug/ipc_logging/ipa/log > "$target_dir/ipa_ipc_logs.txt"
        cat /sys/kernel/debug/ipc_logging/gsi/log > "$target_dir/gsi_ipc_logs.txt"
        cat /sys/kernel/debug/ipc_logging/ipa_clk/log > "$target_dir/ipa_clk_logs.txt"

        dmesg -c >> "$target_dir/dmesg.txt"
        cat /sys/kernel/debug/ipa/hdr
        dmesg -c >> "$target_dir/ipa_hdr.txt"
        cat /sys/kernel/debug/ipa/proc_ctx
        dmesg -c >> "$target_dir/proc_ctx.txt"
        cat /sys/kernel/debug/ipa/msg >> "$target_dir/ipa_msg.txt"
        cat /sys/kernel/debug/ipa/status_stats
        dmesg -c >> "$target_dir/ipa_status_stats1.txt"
        cat /sys/kernel/debug/ipa/status_stats
        dmesg -c >> "$target_dir/ipa_status_stats2.txt"
        cat /sys/kernel/debug/ipa/ipv6ct
        dmesg -c >> "$target_dir/ipv6ct.txt"
        cat /sys/kernel/debug/ipa/ip4_flt
        dmesg -c >> "$target_dir/ipa_ip4_flt.txt"
        cat /sys/kernel/debug/ipa/ip4_flt_hw
        dmesg -c >> "$target_dir/ipa_ip4_flt_hw.txt"
        cat /sys/kernel/debug/ipa/ip4_rt
        dmesg -c >> "$target_dir/ipa_ip4_rt.txt"
        cat /sys/kernel/debug/ipa/ip4_nat
        dmesg -c >> "$target_dir/ipa_ip4_nat.txt"
        cat /sys/kernel/debug/ipa/ip6_flt
        dmesg -c >> "$target_dir/ipa_ip6_flt.txt"
        cat /sys/kernel/debug/ipa/ip6_flt_hw
        dmesg -c >> "$target_dir/ipa_ip6_flt_hw.txt"
        cat /sys/kernel/debug/ipa/ip6_rt
        dmesg -c >> "$target_dir/ipa_ip6_rt.txt"

        cat /sys/kernel/debug/ipa/stats >> "$target_dir/ipa_stats_final.txt"
        cat /sys/kernel/debug/ipa/ipsec_active_sa >> "$target_dir/ipsec_active_sa.txt"

        j=0
        while [ $j -le 10 ]; do
            echo -n $j > /sys/kernel/debug/ipa/ipsec_set_sa_info_index
            cat /sys/kernel/debug/ipa/ipsec_encap_sa_info >> "$target_dir/ipsec_encap$j.txt"
            cat /sys/kernel/debug/ipa/ipsec_decap_sa_info >> "$target_dir/ipsec_decap$j.txt"
            j=$((j + 1))
        done

        cat /sys/kernel/debug/ipa/hw_stats/tethering >> "$target_dir/hw_stats.txt"
        cat /sys/kernel/debug/ipa/hw_stats/drop >> "$target_dir/drop_stats.txt"
        cat /sys/kernel/debug/ipa/eth/IEMAC_0_qos_stats >> "$target_dir/eth_iemac0.txt"
        cat /sys/kernel/debug/ipa/eth/IEMAC_1_qos_stats >> "$target_dir/eth_iemac1.txt"

    else
        echo "Running timeouts for collecting non-debug stats in multiple iterations..."

        cat /sys/kernel/ipa/stats >> "$target_dir/ipa_stats.txt"
        sleep 5
        cat /sys/kernel/ipa/stats >> "$target_dir/ipa_stats1.txt"
        sleep 5
        cat /sys/kernel/ipa/stats >> "$target_dir/ipa_stats2.txt"
        sleep 5
        cat /sys/kernel/ipa/stats >> "$target_dir/ipa_stats3.txt"
        sleep 5
        cat /sys/kernel/ipa/pm_stats >> "$target_dir/pm_stats.txt"
        sleep 5
        cat /sys/kernel/ipa/mhip_gsi_stats >> "$target_dir/mhip_gsi_stats.txt"
        sleep 5
        cat /sys/kernel/ipa/odlstats >> "$target_dir/odlstats.txt"
        sleep 5
        cat /sys/kernel/ipa/usb_gsi_stats >> "$target_dir/usb_gsi_stats.txt"
        sleep 5
        cat /sys/kernel/ipa/wdi_gsi_stats >> "$target_dir/wdi_gsi_stats.txt"
        sleep 5
        cat /sys/kernel/ipa/wdi3_gsi_stats >> "$target_dir/wdi3_gsi_stats.txt"
        sleep 5
        cat /sys/kernel/ipa/ntn >> "$target_dir/ntn.txt"
        sleep 5

        cat /sys/kernel/ipa/ipa_dscp_pcp_mapping_cache >> "$target_dir/ipa_dscp_pcp_mapping_cache.txt"
        cat /sys/kernel/ipa/aqc_0_err_status >> "$target_dir/aqc_0_err_status.txt"
        cat /sys/kernel/ipa/enable_clock_scaling >> "$target_dir/enable_clock_scaling.txt"
        cat /sys/kernel/ipa/ntn_perf_status >> "$target_dir/ntn_perf_status.txt"
        cat /sys/kernel/ipa/tx_wrapper_cache_max_size >> "$target_dir/tx_wrapper_cache_max_size.txt"
        cat /sys/kernel/ipa/rtk_0_err_status >> "$target_dir/rtk_0_err_status.txt"
        cat /sys/kernel/ipa/page_poll_threshold >> "$target_dir/page_poll_threshold.txt"
        cat /sys/kernel/ipa/keep_awake >> "$target_dir/keep_awake.txt"
        cat /sys/kernel/ipa/page_recycle_stats >> "$target_dir/page_recycle_stats.txt"
        cat /sys/kernel/ipa/clock_scaling_bw_threshold_turbo_mbps >> "$target_dir/clock_scaling_bw_threshold_turbo_mbps.txt"
        cat /sys/kernel/ipa/clock_scaling_bw_threshold_nominal_mbps >> "$target_dir/clock_scaling_bw_threshold_nominal_mbps.txt"
        cat /sys/kernel/ipa/lan_coal_stats >> "$target_dir/lan_coal_stats.txt"
        cat /sys/kernel/ipa/enable_napi_chain >> "$target_dir/enable_napi_chain.txt"
        cat /sys/kernel/ipa/page_wq_reschd_time >> "$target_dir/page_wq_reschd_time.txt"
        cat /sys/kernel/ipa/iemac_1_err_status >> "$target_dir/iemac_1_err_status.txt"
        cat /sys/kernel/ipa/mpm_ring_size_dl >> "$target_dir/mpm_ring_size_dl.txt"
        cat /sys/kernel/ipa/ipa_max_napi_sort_page_thrshld >> "$target_dir/ipa_max_napi_sort_page_thrshld.txt"
        cat /sys/kernel/ipa/ntn_1_err_status >> "$target_dir/ntn_1_err_status.txt"
        cat /sys/kernel/ipa/mpm_ring_size_ul >> "$target_dir/mpm_ring_size_ul.txt"
        cat /sys/kernel/ipa/ntn3_1_err_status >> "$target_dir/ntn3_1_err_status.txt"
        cat /sys/kernel/ipa/msg >> "$target_dir/msg.txt"
        cat /sys/kernel/ipa/mpm_teth_aggr_size >> "$target_dir/mpm_teth_aggr_size.txt"
        cat /sys/kernel/ipa/cache_recycle_stats >> "$target_dir/cache_recycle_stats.txt"
        cat /sys/kernel/ipa/pm_ex_stats >> "$target_dir/pm_ex_stats.txt"
        cat /sys/kernel/ipa/ep_reg >> "$target_dir/ep_reg.txt"
        cat /sys/kernel/ipa/aqc_1_err_status >> "$target_dir/aqc_1_err_status.txt"
        cat /sys/kernel/ipa/hw_type >> "$target_dir/hw_type.txt"
        cat /sys/kernel/ipa/clk_rate >> "$target_dir/clk_rate.txt"
        cat /sys/kernel/ipa/rtk_1_err_status >> "$target_dir/rtk_1_err_status.txt"
        cat /sys/kernel/ipa/iemac_0_err_status >> "$target_dir/iemac_0_err_status.txt"
        cat /sys/kernel/ipa/wdi >> "$target_dir/wdi.txt"
        cat /sys/kernel/ipa/gen_reg >> "$target_dir/gen_reg.txt"
        cat /sys/kernel/ipa/ntn_0_err_status >> "$target_dir/ntn_0_err_status.txt"
        cat /sys/kernel/ipa/ntn3_0_err_status >> "$target_dir/ntn3_0_err_status.txt"
        cat /sys/kernel/ipa/wstats >> "$target_dir/wstats.txt"
        cat /sys/kernel/ipa/mpm_uc_thresh >> "$target_dir/mpm_uc_thresh.txt"
        cat /sys/kernel/ipa/app_clk_vote_cnt >> "$target_dir/app_clk_vote_cnt.txt"
        cat /sys/kernel/ipa/eth/eth_status >> "$target_dir/eth_status.txt"

        cat /sys/kernel/hw_stats/tethering >> "$target_dir/hw_tethering_stats.txt"
        cat /sys/kernel/hw_stats/drop >> "$target_dir/drop_stats.txt"
        cat /sys/kernel/ipa/eth/IEMAC_0_qos_stats >> "$target_dir/eth_iemac0.txt"
        cat /sys/kernel/ipa/eth/IEMAC_1_qos_stats >> "$target_dir/eth_iemac1.txt"

        cat /sys/kernel/gsi/gsi_fw_version >> "$target_dir/gsi_fw_version.txt"
        cat /sys/kernel/gsi/gsi_hw_profiling_stats >> "$target_dir/gsi_hw_profiling_stats.txt"

        dmesg -c >> "$target_dir/dmesg.txt"
        cat /sys/kernel/ipa/hdr
        dmesg -c >> "$target_dir/ipa_hdr.txt"
        cat /sys/kernel/ipa/ipa_dump_regs
        dmesg -c >> "$target_dir/ipa_dump_regs.txt"
        cat /sys/kernel/ipa/ip4_rt
        dmesg -c >> "$target_dir/ipa_ip4_rt.txt"
        cat /sys/kernel/ipa/ip4_nat
        dmesg -c >> "$target_dir/ipa_ip4_nat.txt"
        cat /sys/kernel/ipa/ip4_flt
        dmesg -c >> "$target_dir/ipa_ip4_flt.txt"
        cat /sys/kernel/ipa/ip4_rt_hw
        dmesg -c >> "$target_dir/ipa_ip4_rt_hw.txt"
        cat /sys/kernel/ipa/ip4_flt_hw
        dmesg -c >> "$target_dir/ipa_ip4_flt_hw.txt"
        cat /sys/kernel/ipa/proc_ctx
        dmesg -c >> "$target_dir/proc_ctx.txt"
        cat /sys/kernel/ipa/status_stats
        dmesg -c >> "$target_dir/ipa_status_stats1.txt"
        cat /sys/kernel/ipa/status_stats
        dmesg -c >> "$target_dir/ipa_status_stats2.txt"
        cat /sys/kernel/ipa/ip6_rt
        dmesg -c >> "$target_dir/ipa_ip6_rt.txt"
        cat /sys/kernel/ipa/ipv6ct
        dmesg -c >> "$target_dir/ipv6ct.txt"
        cat /sys/kernel/ipa/ip6_flt
        dmesg -c >> "$target_dir/ipa_ip6_flt.txt"
        cat /sys/kernel/ipa/ip6_rt_hw
        dmesg -c >> "$target_dir/ipa_ip6_rt_hw.txt"
        cat /sys/kernel/ipa/ip6_flt_hw
        dmesg -c >> "$target_dir/ipa_ip6_flt_hw.txt"
        dmesg -c >> "$target_dir/dmesg1.txt"
        cat /sys/kernel/ipa/stats >> "$target_dir/ipa_stats_final.txt"

        if [ -e /sys/kernel/debug/ipa/ipsec_active_sa ]; then
            cat /sys/kernel/debug/ipa/ipsec_active_sa >> "$target_dir/ipsec_active_sa.txt"
        fi

        if [ -e /sys/kernel/ipa/ipsec_set_sa_info_index ]; then
            j=0
            while [ $j -le 10 ]; do
                echo -n $j > /sys/kernel/ipa/ipsec_set_sa_info_index
                cat /sys/kernel/ipa/ipsec_encap_sa_info >> "$target_dir/ipsec_encap$j.txt"
                cat /sys/kernel/ipa/ipsec_decap_sa_info >> "$target_dir/ipsec_decap$j.txt"
                j=$((j + 1))
            done
        fi
    fi
}

# Function to collect other logs
collect_other_logs() {
    local target_dir="$1"
    local is_auto_collection="$2"
    mkdir -p "$target_dir"
    echo "Collecting other logs into $target_dir"

    iptables-save | tee -a "$target_dir/iptables_save.txt" > /dev/null
    iptables -L -vn | tee -a "$target_dir/iptables.txt" > /dev/null
    ip6tables -L -vn | tee -a "$target_dir/ip6tables.txt" > /dev/null
    ip r s | tee -a "$target_dir/iproutes.txt" > /dev/null
    ip -6 r s | tee -a "$target_dir/ip6routes.txt" > /dev/null
    ip n s | tee -a "$target_dir/ipneighs.txt" > /dev/null
    ip -6 n s | tee -a "$target_dir/ip6neighs.txt" > /dev/null
    brctl show | tee -a "$target_dir/brctl.txt" > /dev/null
    conntrack -L | tee -a "$target_dir/conntrack.txt" > /dev/null
    conntrack -L --family ipv6 | tee -a "$target_dir/conntrack_v6.txt" > /dev/null

    eth-qos show eth0 >> "$target_dir/eth_qos_eth0.txt"
    eth-qos show eth1 >> "$target_dir/eth_qos_eth1.txt"

    if [ -f /firmware/verinfo/ver_info.txt ]; then
        cat /firmware/verinfo/ver_info.txt > "$target_dir/ver_info.txt"
    elif [ -f /firmware/verinfo/Ver_Info.txt ]; then
        cat /firmware/verinfo/Ver_Info.txt > "$target_dir/ver_info.txt"
    elif [ -f /firmware/image/Ver_Info.txt ]; then
        cat /firmware/image/Ver_Info.txt > "$target_dir/ver_info.txt"
    else
        echo "No matching file found."
    fi

    bridge fdb show | tee -a "$target_dir/fdb_show.txt" > /dev/null
    cat /etc/data/ipa/IPACM_cfg.xml >> "$target_dir/ipacm_cfg.xml"
    cat /etc/data/mobileap_cfg.xml >> "$target_dir/mobile_cfg.xml"

    cat /etc/data/ipa_config.txt >> "$target_dir/ipa_config.txt"
    cat /data/ipacm_log.txt > "$target_dir/ipacm_log.txt"
    cat /data/data_ipa/ipacm_log.txt >> "$target_dir/ipacm_log.txt"
    cat /var/run/data/ipa/ipacm_log.txt ipacm.txt >> "$target_dir/ipacm_log.txt"

    if [ "$is_auto_collection" == "auto" ]; then
        if [ -f "/data/logs/auto_tcpdump.pid" ]; then
            echo "Stopping auto-started tcpdump processes..."
            while IFS= read -r pid; do
                if kill -0 "$pid" > /dev/null 2>&1; then
                    kill "$pid"
                fi
            done < "/data/logs/auto_tcpdump.pid"
            rm -f "/data/logs/auto_tcpdump.pid"
        else
            echo "No auto-started tcpdump processes found."
        fi
    else
        echo "Killing manual tcpdump processes..."
        if [ -f /data/logs/manual_tcpdump.pid ]; then
            while IFS= read -r pid; do
                if kill -0 "$pid" 2>/dev/null; then
                    kill -9 "$pid"
                fi
            done < /data/logs/manual_tcpdump.pid
            rm -f /data/logs/manual_tcpdump.pid
        else
            echo "No manual tcpdump processes found."
        fi
    fi

    echo "Log collection complete in "$target_dir""
}

# Function to check conntracks and log exceptions
check_and_log_conntrack_exceptions() {
    # This function appends conntrack entries where packet_count > 1000.
    echo "$(date +"%Y-%m-%d %H:%M:%S") Conntrack entries with packet_count > 1000:" >> /data/logs/ipa_conntrack_exceptions.txt

    conntrack -L | awk '
    {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^packets=/) {
                # Extract the number after "packets="
                split($i, a, "=")
                packet_count = a[2]
                if (packet_count > 1000) {
                    print $0
                }
                break # Stop checking fields in this line once "packets=" is found
            }
        }
    }' >> /data/logs/ipa_conntrack_exceptions.txt 2>/dev/null

    conntrack -L --family ipv6 | awk '
    {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^packets=/) {
                # Extract the number after "packets="
                split($i, a, "=")
                packet_count = a[2]
                if (packet_count > 1000) {
                    print $0
                }
                break # Stop checking fields in this line once "packets=" is found
            }
        }
    }' >> /data/logs/ipa_conntrack_exceptions.txt 2>/dev/null
}

# Function to start auto log collection (calls collect_tcpdumps and collect_other_logs)
start_auto_log_collection() {
    local AUTO_LOG_DIR="/data/logs/auto_collected_logs_$(date +"%Y%m%d_%H%M%S")"

    # Clear previous auto_tcpdump.pid file before starting new collection
    > /data/logs/auto_tcpdump.pid

    collect_tcpdumps "$AUTO_LOG_DIR" "auto" # Pass "auto" flag

    ( collect_initial_logs "$AUTO_LOG_DIR" "auto" &)
    pid_initial_logs=$!

    ( collect_other_logs "$AUTO_LOG_DIR" "auto" &)
    pid_other_logs=$!

    # Wait only for the specific background jobs started in this function
    wait $pid_initial_logs
    wait $pid_other_logs

    # Tarball for this log collection instance
    tar -cvf "/data/logs/ipa_logs_auto_$(date +'%Y%m%d_%H%M%S').tar" -C "/data/logs" "$(basename "$AUTO_LOG_DIR")"
}

monitor_ipa_stats() {
    local STATS_FILE=""
    if [ -f "/sys/kernel/debug/ipa/stats" ]; then
        STATS_FILE="/sys/kernel/debug/ipa/stats"
    elif [ -f "/sys/kernel/ipa/stats" ]; then
        STATS_FILE="/sys/kernel/ipa/stats"
    else
        echo "Error: IPA stats file not found at /sys/kernel/debug/ipa/stats or /sys/kernel/ipa/stats"
        return 1
    fi

    local pid_file="/data/logs/ipa_monitor.pid"

    # Temporary files used by this function. They should be cleaned up on stop.
    local previous_stats_files=(
        "/data/logs/ipa_stats_history_0.tmp" # Current previous (t-5s)
        "/data/logs/ipa_stats_history_1.tmp" # (t-10s)
        "/data/logs/ipa_stats_history_2.tmp" # (t-15s)
    )
    local current_stats_temp_file="/data/logs/ipa_current_stats.tmp"

    local auto_collect_logs=$1 # 'true' or 'false'
    local auto_trigger_max=${2:-1}
    local auto_triggered_count=0
    local consecutive_increase_count=0 # Track consecutive increases (5s window)

    # Initialize history files if they don't exist
    for f in "${previous_stats_files[@]}"; do
        [ ! -f "$f" ] && > "$f"
    done

    while true; do
        local current_iteration_stat_exceptions="" # Buffer for 5s window exceptions
        local current_iteration_stat_exceptions_15s="" # Buffer for 15s window exceptions

        cat "$STATS_FILE" > "$current_stats_temp_file"

        local current_iteration_has_exception=false # Flag for any exception in 5s window
        local current_iteration_has_exception_15s=false # Flag for any exception in 15s window

        # Process 5-second window (current vs previous_stats_files[0])
        if [ -s "${previous_stats_files[0]}" ]; then # Check if file is not empty
            while IFS= read -r current_line; do
                local stat_name="${current_line%=*}"
                local curr_val_str="${current_line#*=}"

                if [[ "$curr_val_str" =~ ^0x ]]; then
                    local curr_val=$((16#${curr_val_str#0x}))
                else
                    local curr_val="$curr_val_str"
                fi

                local search_pattern_for_grep="${stat_name}="
                local prev_line=$(grep -F "$search_pattern_for_grep" "${previous_stats_files[0]}" | head -n 1)
                local prev_val=0
                if [[ -n "$prev_line" ]]; then
                    local prev_val_str="${prev_line#*=}"
                    if [[ "$prev_val_str" =~ ^0x ]]; then
                        prev_val=$((16#${prev_val_str#0x}))
                    else
                        prev_val="$prev_val_str"
                    fi
                fi

                if [[ "$prev_val" =~ ^[0-9]+$ ]] && [[ "$curr_val" =~ ^[0-9]+$ ]]; then
                    local diff=0
                    if (( curr_val < prev_val )); then
                        diff=0
                    else
                        diff=$((curr_val - prev_val))
                    fi

                    if (( diff > 1000 )); then
                        current_iteration_stat_exceptions+="$(date +"%Y-%m-%d %H:%M:%S") STAT EXCEPTION (5s window): $stat_name increased from $prev_val to $curr_val (diff: $diff)\n"
                        current_iteration_has_exception=true
                    fi
                fi
            done < "$current_stats_temp_file"
        fi

        # Process 15-second window (current vs previous_stats_files[2])
        if [ -s "${previous_stats_files[2]}" ]; then # Check if file is not empty (i.e., we have enough history)
            while IFS= read -r current_line; do
                local stat_name="${current_line%=*}"
                local curr_val_str="${current_line#*=}"

                if [[ "$curr_val_str" =~ ^0x ]]; then
                    local curr_val=$((16#${curr_val_str#0x}))
                else
                    local curr_val="$curr_val_str"
                fi

                local search_pattern_for_grep="${stat_name}="
                local prev_line_15s=$(grep -F "$search_pattern_for_grep" "${previous_stats_files[2]}" | head -n 1)
                local prev_val_15s=0
                if [[ -n "$prev_line_15s" ]]; then
                    local prev_val_str_15s="${prev_line_15s#*=}"
                    if [[ "$prev_val_str_15s" =~ ^0x ]]; then
                        prev_val_15s=$((16#${prev_val_str_15s#0x}))
                    else
                        prev_val_15s="$prev_val_str_15s"
                    fi
                fi

                if [[ "$prev_val_15s" =~ ^[0-9]+$ ]] && [[ "$curr_val" =~ ^[0-9]+$ ]]; then
                    local diff_15s=0
                    if (( curr_val < prev_val_15s )); then
                        diff_15s=0
                    else
                        diff_15s=$((curr_val - prev_val_15s))
                    fi

                    if (( diff_15s > 1000 )); then
                        current_iteration_stat_exceptions_15s+="$(date +"%Y-%m-%d %H:%M:%S") STAT EXCEPTION (15s window): $stat_name increased from $prev_val_15s to $curr_val (diff: $diff_15s)\n"
                        current_iteration_has_exception_15s=true
                    fi
                fi
            done < "$current_stats_temp_file"
        fi

        # Overwrite ipa_stat_exceptions.txt with exceptions from both windows
        (
            echo -e "$current_iteration_stat_exceptions"
            echo -e "$current_iteration_stat_exceptions_15s"
        ) | grep -v '^\s*$' > /data/logs/ipa_stat_exceptions.txt # Filter out empty lines if no exceptions

        # Conntrack check and log if any exception occurred in either window
        if [ "$current_iteration_has_exception" == "true" ] || [ "$current_iteration_has_exception_15s" == "true" ]; then
            check_and_log_conntrack_exceptions
        fi

        # Logic for consecutive increases (still based on 5s window for existing logic)
        if [ "$current_iteration_has_exception" == "true" ]; then
            consecutive_increase_count=$((consecutive_increase_count + 1))
        else
            consecutive_increase_count=0
        fi

        if [ "$auto_collect_logs" == "true" ] && [ "$auto_triggered_count" -lt "$auto_trigger_max" ] && \
            ([ "$consecutive_increase_count" -ge 3 ] || [ "$current_iteration_has_exception_15s" == "true" ]); then
            echo "$(date +"%Y-%m-%d %H:%M:%S") Triggering automatic log collection due to stat exceptions (count $((auto_triggered_count+1)) of $auto_trigger_max)..." >> /data/logs/ipa_stat_exceptions.txt
            start_auto_log_collection & # Run in background
            auto_triggered_count=$((auto_triggered_count + 1))
        fi

        # Shift history: new [0] becomes old [1], old [1] becomes old [2], current becomes new [0]
        mv "${previous_stats_files[1]}" "${previous_stats_files[2]}" 2>/dev/null
        mv "${previous_stats_files[0]}" "${previous_stats_files[1]}" 2>/dev/null
        cp "$current_stats_temp_file" "${previous_stats_files[0]}"

        sleep 5
    done
}


stop_ipa_monitoring() {
    local pid_file="/data/logs/ipa_monitor.pid"
    local current_stats_temp_file="/data/logs/ipa_current_stats.tmp"
    local previous_stats_files=(
        "/data/logs/ipa_stats_history_0.tmp"
        "/data/logs/ipa_stats_history_1.tmp"
        "/data/logs/ipa_stats_history_2.tmp"
    )

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" > /dev/null 2>&1; then
            kill "$pid"
            echo "IPA stats monitoring process (PID: $pid) stopped."
            sleep 1
        else
            echo "No active IPA stats monitoring process found with PID: $pid."
        fi
        rm -f "$pid_file"
    else
        echo "No IPA stats monitoring process is currently running in the background."
    fi
    # Clean up any tcpdump processes started by auto log collection
    if [ -f "/data/logs/auto_tcpdump.pid" ]; then
        echo "Stopping auto-started tcpdump processes..."
        while IFS= read -r pid; do
            if kill -0 "$pid" > /dev/null 2>&1; then
                kill "$pid"
            fi
        done < "/data/logs/auto_tcpdump.pid"
        rm -f "/data/logs/auto_tcpdump.pid"
    fi

    # Clean up temporary files here
    rm -f "$current_stats_temp_file" "${previous_stats_files[@]}"
    # No changes to persistent exception files on stop, as they are overwritten per iteration.
}

while true; do
    echo "Choose an option:"
    echo "1. Start collecting tcpdumps and logs"
    echo "2. Stop tcpdumps and Collect other logs"
    echo "3. Stop manual tcpdump collection"
    echo "4. Delete existing log files"
    echo "5. Monitor stats"
    echo "6. Stop monitoring stats"
    echo "7. Check tuple against conntrack exceptions"
    echo "8. Exit"

    read -p "Enter your choice (1/2/3/4/5/6/7/8): " user_choice

    case $user_choice in
        1)
            collect_tcpdumps "/data/logs" "" # Manual call, no auto flag
            ( collect_initial_logs "/data/logs" "" ) &
            pid_collect_initial_logs=$!
            echo $pid_collect_initial_logs > /data/logs/manual_initial_logs.pid
            echo "tcpdump collection runs until 500 packets are captured. tcpdump collection can be stopped using option 3."
            ;;
        2)
            ( collect_other_logs "/data/logs" "" ) &
            pid_collect_other_logs=$!
            wait $pid_collect_initial_logs

            timestamp=$(date +"%Y%m%d_%H%M%S")
            tar_file="ipa_logs_$timestamp.tar"
            # Wait in a loop if manual_initial_logs.pid exists
            if [ -f /data/logs/manual_initial_logs.pid ]; then
                pid_initial_logs=$(cat /data/logs/manual_initial_logs.pid)
                echo "Checking for completion of collect_initial_logs from option-1 before tarball creation..."
                while kill -0 "$pid_initial_logs" 2>/dev/null; do
                    sleep 1
                done
                echo "collect_initial_logs is complete."
                rm -f /data/logs/manual_initial_logs.pid
            fi

            find /data/logs -type f -print0 | xargs -0 tar -cvf /data/$tar_file
            ;;
        3)
            echo "Killing manual tcpdump processes..."
            if [ -f /data/logs/manual_tcpdump.pid ]; then
                while IFS= read -r pid; do
                    if kill -0 "$pid" 2>/dev/null; then
                        kill -9 "$pid"
                    fi
                done < /data/logs/manual_tcpdump.pid
                rm -f /data/logs/manual_tcpdump.pid
                echo "Manual tcpdump processes terminated."
            else
                echo "No manual tcpdump processes found."
            fi
            sleep 5
            ;;
        4)
            rm -rf /data/logs/*
            rm -f /data/ipa_logs_*.tar
            echo "All log files deleted."
            ;;
        5)
            read -p "Do you want to enable automatic log collection when an exception is found? (y/n): " auto_collect_choice
            if [[ "$auto_collect_choice" =~ ^[Yy]$ ]]; then
                read -p "How many times (max 3) should log collection be triggered when exception is found?: " auto_trigger_count
                if ! [[ "$auto_trigger_count" =~ ^[1-3]$ ]]; then
                    echo "Invalid count. Setting to 1."
                    auto_trigger_count=1
                fi
                monitor_ipa_stats "true" "$auto_trigger_count" &
            else
                monitor_ipa_stats "false" "0" &
            fi
            echo $! > /data/logs/ipa_monitor.pid
            ;;
        6)
            stop_ipa_monitoring
            ;;
        7)
            # Option to check if a tuple is in conntrack exceptions
            echo "Enter tuple info to check(Make sure that tuple info entered is correct):"
            read -p "Source IP: " src_ip
            read -p "Destination IP: " dst_ip
            read -p "Protocol: " proto
            read -p "Source Port: " src_port
            read -p "Destination Port: " dst_port

            # Check for empty input fields
            if [[ -z "$src_ip" || -z "$dst_ip" || -z "$proto" || -z "$src_port" || -z "$dst_port" ]]; then
                echo "Error: Please provide all the inputs"
            else
                exceptions_file="/data/logs/ipa_conntrack_exceptions.txt"
                if [ ! -f "$exceptions_file" ] || ! grep -q . "$exceptions_file"; then
                    echo "No conntrack exceptions present. Please run log collection or exception check first."
                else
                    last_match=$(awk -v sip="$src_ip" -v dip="$dst_ip" -v p="$proto" -v sport="$src_port" -v dport="$dst_port" '
BEGIN {
    prev3_pkt = ""; prev_pkt = ""; cur_pkt = "";
    match_count = 0; found = 0; latest_entry = "";
}
{
    # Skip lines that are just timestamps or headers
    if ($0 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}/ || $0 ~ /Conntrack entries with packet_count/) next;

    proto_found = 0; src_val=""; dst_val=""; sport_val=""; dport_val=""; packet_count = "";
    for (i=1;i<=NF;i++) {
        val = $i
        gsub(/^[ \t]+|[ \t]+$/, "", val);

        # Check if match for tuple exists in conntrack entries
        if (match(val, /(udp|tcp|icmp|icmpv6|sctp|dccp)/)) {
            proto=substr(val, RSTART, RLENGTH)
            if (proto==p) proto_found=1;
        }
        if (match(val, /^src=/)) src_val=substr(val,5)
        if (match(val, /^dst=/)) dst_val=substr(val,5)
        if (match(val, /^sport=/)) sport_val=substr(val,7)
        if (match(val, /^dport=/)) dport_val=substr(val,7)
        if (match(val, /^packets=/)) packet_count=substr(val,9)

        if (proto_found && src_val!="" && dst_val!="" && sport_val!="" && dport_val!="" && packet_count!="") {
            if ((src_val==sip && dst_val==dip && sport_val==sport && dport_val==dport) ||
                (src_val==dip && dst_val==sip && sport_val==dport && dport_val==sport)) {
                match_count++
                prev3_pkt_save = prev3_pkt
                prev3_pkt = prev_pkt
                prev_pkt = cur_pkt
                cur_pkt = packet_count+0 # force numeric

                if (match_count > 1 && cur_pkt-prev_pkt>=1000) found=1;
                if (match_count > 3 && cur_pkt-prev3_pkt_save>=1000) found=1;

                latest_entry = $0;
            }
            proto_found=0; src_val=""; dst_val=""; sport_val=""; dport_val=""; packet_count="";
        }
    }
}
END {
    if (found && latest_entry!="") print latest_entry
}
' "$exceptions_file")
                    tmp_last=$(echo "$last_match" | xargs)
                    echo "------------------"
                    if [[ -n "$tmp_last" ]]; then
                        echo "Taking SW path"
                        echo "$last_match"
                    else
                        echo "Not taking SW path"
                        echo "Please check the conntrack details for Confirmation"
                    fi
                    echo "------------------"
                fi
            fi
            ;;
        8)
            stop_ipa_monitoring
            echo "Exiting and stopping all tcpdump processes..."
            killall -9 tcpdump
            exit 0
            ;;
        *)
            echo "Invalid choice. Please enter 1, 2, 3, 4, 5, 6, 7, or 8"
            ;;
    esac
done
