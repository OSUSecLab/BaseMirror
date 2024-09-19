import os, time
from subprocess import *
import threading
import sys

if(sys.version[:1] == "3"):
    import _thread as thread
else:
    import thread


tids = list(range(3))
start_time = 0


def run_one(app, tid):
	project = "Test" + str(tid)
	os.system('java -cp lib/ghidra.jar:lib/json.jar:main.jar main %s %s' % (app, project))
	tids.append(tid)

def get_ril_paths():
	current_dir = os.path.dirname(os.path.abspath(__file__))
	ril_dir = os.path.join(current_dir, "ril_binaries")
	print(ril_dir)
	result = []

	for root, dirs, files in os.walk(ril_dir):
		for file in files:
			if file == "libsec-ril.so":
				file_path = os.path.join(root, file)
				result.append(file_path)
	return result

def run_all():
	start_time = time.time()
	so_paths = get_ril_paths()

	for app in so_paths:
		while len(tids) == 0:
			time.sleep(60)
		tid = tids.pop()
		run_one(app, tid)
		# thread.start_new_thread( run_one, (app, tid) )


if __name__ == '__main__':
	run_all()
	total_time = time.time() - start_time
	print("finish time: %f" % total_time)