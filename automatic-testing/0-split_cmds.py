import os
import re
import sys

# configuration
file_num_in_dir = 10
static_counter = 0
hybird_counter = 0
firmware = "cmds_logs"

cur_dir = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.join(cur_dir, firmware)
static_inputs_dir = "static-input"
hybird_inputs_dir = "hybird-input"
static_input_dir_path = os.path.join(output_dir, static_inputs_dir)
hybird_input_dir_path = os.path.join(output_dir, hybird_inputs_dir)



def create_directory_if_not_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Directory {directory} created")
    else:
        print(f"Directory {directory} existed")

def is_static_cmd(value):
    if "," in value:
        int_values = [int(x, 16) for x in value.split(',')]
        if len(int_values) == int_values[0]:
            return True
    return False

def write_cmd(value, command, line_num):
    global static_counter
    global hybird_counter
    parent_dir = ""
    if is_static_cmd(value):
        static_counter += 1
        parent_dir = os.path.join(static_input_dir_path, '{:03d}'.format(int(static_counter/file_num_in_dir)))
    else:
        hybird_counter += 1
        parent_dir = os.path.join(hybird_input_dir_path, '{:03d}'.format(int(hybird_counter/file_num_in_dir)))
    create_directory_if_not_exists(parent_dir)
    file_path = os.path.join(parent_dir, '{:03d}'.format(line_num) + "-" + command + ".input")
    with open(file_path, 'w') as output_file:
        output_file.write(value)

def generate_test_cmds(abs_path):
    files = [os.path.join(abs_path, f) for f in os.listdir(abs_path) if os.path.isfile(os.path.join(abs_path, f))]

    for file_name in files:
        result_file = file_name + ".raw"
        grep_command = "grep taintFinish {} > {}".format(file_name, result_file)
        os.system(grep_command)
        print("Results written to", result_file)
        # generate cmd input test seeds
        line_num = 1
        with open(result_file, 'r') as f:
            lines = f.readlines()
            for i in range(0, len(lines), 2):
                line1 = lines[i].strip()
                line2 = lines[i+1].strip()

                command_match = re.findall(r"\((.*?)\)", line1)
                value_match = re.findall(r'\[(.*?)\]', line2)

                if command_match and value_match:
                    command = command_match[-1].replace("::", "__")
                    value = value_match[-1]
                    if value != 'taintFinish':
                        write_cmd(value, command, line_num)
                    # else:
                    #     print("???")
                line_num += 2

if __name__ == "__main__":
    abs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "raw_logs")
    print("Absolute path:", abs_path)
    generate_test_cmds(abs_path)
    print("All commands are splited")
