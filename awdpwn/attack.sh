!/bin/bash

attack_times=20
round_wait_time=900 #half time
wait_submit_time=5
log_file="logs"
run_time=120 #timeout
next_attack_time=2.5 
max_concurrent_attacks=10 # Max number of concurrent attacks

log(){
    t=$(date "+%H:%M:%S")
    m="[$t]$1" # Fixed missing parameter usage
    info="\033[43;37m $m \033[0m"
    echo -e "$info"
    echo -e "$m" >> $log_file
}

attack() {
    echo "-- round $1 -- " >> all_flags
    cat flags >> all_flags
    rm flags
    local jobs=0
    for line in $(cat hosts); do
        timeout --foreground $run_time python3 ./exp.py "$line" &
        sleep $next_attack_time
        ((jobs++))
        if [ "$jobs" -ge "$max_concurrent_attacks" ]; then
            wait # Wait for all background jobs to finish
            jobs=0
        fi
    done
    wait # Ensure all attacks are complete before moving on
    echo -e "\x1b[47;30m Waiting $wait_submit_time s to submit flag\x1b[0m"
    sleep $wait_submit_time
    echo -e "\x1b[47;30m Submitting flag\x1b[0m"
    python3 ./submit_flag.py
}

for ((i=1; i <= attack_times; i++)); do
    m="-------- round $i --------"
    log "$m"
    attack $i
    echo -e "\x1b[47;30m Waiting next round\x1b[0m"
    sleep $round_wait_time
done
