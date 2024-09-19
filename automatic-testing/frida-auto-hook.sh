#!/bin/sh

# /data/local/tmp/frida-server &

rm /data/local/tmp/output.txt
rm /data/local/tmp/log.txt
rm /data/local/tmp/error.txt


#date >> data/local/tmp/log.txt

echo "Waiting for process to come online" >> /data/local/tmp/log.txt

while [[ -z "$(ps | pgrep rild | sed -n '1p')" ]]
#while true
do
#    su -c /data/local/tmp/frida-inject -p "$(ps | pgrep cbd | sed -n '1p')" -s /data/local/tmp/cbd.js >> /data/local/tmp/output.txt 2> /data/local/tmp/error.txt
    continue
done

#date >> data/local/tmp/log.txt

# finish waiting
#
#echo "Target process online!" >> /data/local/tmp/log.txt
#echo "$(ps | pgrep cbd | sed -n '1p')" >> /data/local/tmp/log.txt

#su -c /data/local/tmp/frida-inject -p "$(ps | pgrep cbd | sed -n '1p')" -s /data/local/tmp/cbd.js >> /data/local/tmp/output.txt 2> /data/local/tmp/error.txt

#su -c /data/local/tmp/frida-inject -p "$(ps | pgrep rild | sed -n '1p')" -s /data/local/tmp/init.js >> /data/local/tmp/output.txt 2> /data/local/tmp/error.txt


#settings put global airplane_mode_on 1
#am broadcast -a android.intent.action.AIRPLANE_MODE