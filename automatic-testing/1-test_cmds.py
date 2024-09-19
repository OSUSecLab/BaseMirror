import subprocess
import os
import re
import time

# configuration
test_cmd_type = "static-input" # static-input or hybird-input
test_cmd_start = 0
test_cmd_len = 10

firmware = "cmds_logs"
max_phone_checker = 10
max_modem_checker = 10

cur_dir = os.path.dirname(os.path.abspath(__file__))

logs_dir = "logs"
frida_server_command = ["adb", "shell", "su", "-c", "/data/local/tmp/frida-server-16.2.1-android-arm64"]
frida_reader_command = ["python3", os.path.join(cur_dir, "hooking-native-code.py")]
test_command = ["adb", "shell", "su", "-c", "/data/local/tmp/test_cmd"]
dump_sys_command = ["dumpsys", "telephony.registry"]

bad_status = [
    "OUT_OF_SERVICE",
    "mChannelNumber=-1", 
    # "mCellBandwidths=[]",
    "Unknown",
    "NOT_REG_OR_SEARCHING",
    "UNKNOWN",
    "availableServices=[]"
]


def get_connected_devices():
    devices = []
    try:
        result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
        output_lines = result.stdout.strip().split('\n')
        # Skip the first line which contains header information
        for line in output_lines[1:]:
            device_info = line.split('\t')
            if len(device_info) == 2 and device_info[1] == 'device':
                devices.append(device_info[0])
    except FileNotFoundError:
        print("ADB command not found. Please make sure ADB is installed and added to your PATH.")
    # if devices:
    #     print("Connected devices:")
    #     for device in devices:
    #         print(device)
    # else:
    #     print("No devices connected.")
    return devices

def execute_adb_command(command, device_serial=None, su=False):
    adb_cmd = ['adb']
    if device_serial:
        adb_cmd.extend(['-s', device_serial])
    if su:
        adb_cmd.extend(['shell', 'su -c'])
    adb_cmd.extend(command)

    process = subprocess.Popen(adb_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode(), stderr.decode(), process.returncode

def compile_test_cmd():
    # return True
    command = 'aarch64-linux-android23-clang -fPIE -pie -ldl -o test_cmd{,.c}'
    os.system(command)

def push_test_cmd(device_serial=None):
    # already pushed
    return True
    push_command = ['push', os.path.join(cur_dir, 'test_cmd'), '/data/local/tmp']
    stdout, stderr, returncode = execute_adb_command(push_command, device_serial)
    if returncode != 0:
        print("Error push test_cmd:", stderr)
        exit(-1)
    chmod_command = ['chmod', '+x', '/data/local/tmp/test_cmd']
    stdout, stderr, returncode = execute_adb_command(chmod_command, True)
    if returncode != 0:
        print("Error chmod test_cmd:", stderr)
        exit(-1)

def create_directory_if_not_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Directory {directory} created")
    else:
        print(f"Directory {directory} existed")

def get_files_absolute_paths(directory):
    file_paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_paths.append(file_path)
    return file_paths

def is_bad_status(line):
    for status in bad_status:
        if status in line:
            print("Bad Status:" + status)
            return True
    return False

def dump_sys(cmd_file, timepoint, device_serial):
    dump_try = 10
    while True:
        stdout, stderr, returncode = execute_adb_command(dump_sys_command, device_serial, True)
        sys_output = stdout
        sys_output_file = cmd_file
        if timepoint == 0:
            sys_output_file += ".sysout.before"
        else:
            sys_output_file += ".sysout.after"

        # write output to file
        with open(sys_output_file, "w") as file:
            file.write(sys_output)

        # return service state
        lines = sys_output.splitlines()
        for line in lines:
            if "mServiceState" in line:
                if is_bad_status(line):
                    return True
                else:
                    return False
        print("No mServiceState Try: " + str(dump_try))
        dump_try -= 1
        if dump_try <= 0:
            return True
        else:
            time.sleep(30)


def test_cmds(device_serial):
    parent_dir = os.path.join(os.path.join(cur_dir, firmware), test_cmd_type)
    counter = 0
    for i in range(test_cmd_len):
        cmd_dir = os.path.join(parent_dir, '{:03d}'.format(test_cmd_start + i))
        cmd_files = get_files_absolute_paths(cmd_dir)
        for cmd_file in cmd_files:
            if cmd_file.endswith(".input"):
                print("======================")
                print("Working on " + cmd_file)
                check_round = max_modem_checker
                while True:
                    dump_alert = dump_sys(cmd_file, 0, device_serial)
                    if dump_alert:
                        print("Unrecoverable Modem Crash at Last cmd at Try " + str(max_modem_checker-check_round))
                        if check_round == 0:
                            exit(-1) # unable to recover and need human help
                        else:
                            check_round -= 1
                            time.sleep(30)
                            continue
                    else:
                        break

                push_command = ['push', cmd_file, '/data/local/tmp/']
                stdout, stderr, returncode = execute_adb_command(push_command, device_serial)
                if returncode != 0:
                    print("Error push :" + cmd_file + ".input", stderr)
                    continue

                rename_command = ["mv", "/data/local/tmp/" + os.path.basename(cmd_file), "/data/local/tmp/hex_data.txt"]
                stdout, stderr, returncode = execute_adb_command(rename_command, device_serial, True)
                if returncode != 0:
                    print("Error rename :" + os.path.basename(cmd_file), stderr)
                    continue

                # prepare logs
                log_file_path = cmd_file + ".log"
                frida_server_process = subprocess.Popen(frida_server_command)
                time.sleep(10)
                with open(log_file_path, "w") as log_file:
                    frida_read_process = subprocess.Popen(frida_reader_command, stdout=log_file)
                time.sleep(20)
                test_process = subprocess.Popen(test_command)
                time.sleep(10)
                test_process.wait()
                frida_server_process.terminate()
                frida_read_process.terminate()

                dump_crash = dump_sys(cmd_file, 1, device_serial)
                if dump_crash:
                    print("Modem Crash at " + str(counter) + ": " + cmd_file)
                    with open(cmd_file + ".crash", "w") as file:
                        file.write("Modem Crash\n")
                    
                # Reboot the device and then remount the system partition as read-write
                commands = ['reboot']
                stdout, stderr, returncode = execute_adb_command(commands, device_serial, True)

                phone_status_checker = 0
                while True:
                    device_serials = get_connected_devices()
                    if(not device_serials):
                        time.sleep(30)
                    else:
                        # wait for modem
                        time.sleep(30)
                        break
                    phone_status_checker += 1
                    if phone_status_checker > max_phone_checker:
                        print("Phone Crash at" + str(counter) + ": " + cmd_file)
                        with open(cmd_file + ".crash", "w") as file:
                            file.write("Phone Crash\n")
                        exit(-1)
                counter += 1
                print("Finish " + str(counter) + ": " + cmd_file)


def main():
    if(compile_test_cmd()):
        # Replace 'your_device_serial' with the actual serial number of your device,
        # or leave it as None to execute the command on any connected device.
        device_serials = get_connected_devices()
        if(device_serials):
            device_tar = device_serials[0]
            # push test_cmd to device
            push_test_cmd(device_tar)
            test_cmds(device_tar)
            print("Everything is done")

if __name__ == "__main__":
    main()
