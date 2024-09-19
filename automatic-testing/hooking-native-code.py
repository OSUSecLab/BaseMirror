import frida
import sys
import os

package_name = "com.android.phone"
program_name = "/vendor/bin/hw/rild"
process_name = "rild"
# process_name = "cbd"
pid = -1
cur_dir = os.path.dirname(os.path.abspath(__file__))

def callback(message, data):
    if message.keys().__contains__('payload'):
        print(message['payload'])
    else:
        print(message)


def load_script():
    # with open(os.path.join(cur_dir, "scripts/native.js"), 'r') as i:
    # with open(os.path.join(cur_dir, "scripts/cbd.js"), 'r') as i:
    with open(os.path.join(cur_dir, "scripts/init.js"), 'r') as i:
        return "".join(i.readlines())


ps = frida.get_device_manager().enumerate_devices()[-1].enumerate_processes()
for p in ps:
    if p.name == process_name:
        print(p.parameters)
        pid = p.pid
        print("Process %s found, pid=%d" % (process_name, pid))
        break

if pid == -1:
    print("Process %s not found" % process_name)
    exit(-1)
# pid = 29612
device = frida.get_usb_device()
# pid = device.spawn([program_name])
process = device.attach(pid)
script = process.create_script(load_script())
script.on('message', callback)
script.load()
# device.resume(pid)
sys.stdin.read()
