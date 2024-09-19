import os

output_dir = 'output'
dirs = [os.path.join(output_dir, d) for d in os.listdir(output_dir)
        if os.path.isdir(os.path.join(output_dir, d)) and d.endswith('_LOG')]

for dir_path in dirs:
    for filename in os.listdir(dir_path):
        if filename.startswith('LOG.txt') and "read" in filename:
            file_path = os.path.join(dir_path, filename)
            print("Commands in " + file_path)
            cmds = set()
            with open(file_path, 'r') as file:
                command = ""
                for line in file:
                    if 'forwardFinished' in line:
                        if 'backward path' in line:
                            if "IoChannel::Read" in line:
                                command = line.strip().removeprefix("[DEBUG] [forwardFinished] ").removesuffix(" =>")
                        elif 'forward path' in line:
                            if "GetRxData" in line:
                                command = command + "@" + line.strip().removeprefix("[DEBUG] [forwardFinished] ").removesuffix(" =>")
                                print(command)
                                cmds.add(command)
                                command = ""
            for cmd in cmds:
                tempCmds = cmd.split("@")
                print(tempCmds[0]) 
                print(tempCmds[1]) 
                print()