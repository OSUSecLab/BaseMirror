import os

output_dir = 'output'
dirs = [os.path.join(output_dir, d) for d in os.listdir(output_dir)
        if os.path.isdir(os.path.join(output_dir, d)) and d.endswith('_LOG')]

for dir_path in dirs:
    for filename in os.listdir(dir_path):
        if filename.startswith('LOG.txt') and "write" in filename:
            file_path = os.path.join(dir_path, filename)
            with open(file_path, 'r') as file:
                for line in file:
                    if 'taintFinish' in line and ('IpcTx' in line or 'Key:' in line or 'StaticFlag:' in line):
                        if 'Solved taintPath' in line:
                            print()
                        print(line.strip().removeprefix("[INFO] [taintFinish] "))