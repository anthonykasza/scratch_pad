# It would be nice to put this on a webserver and wrap it in a webUI
# I'd like to have pcap upload ability
# I'd love to see addBroScript called via checkboxes in a form (select the scripts you'd like to have run on your pcap)

import os
import glob
import sys
import hashlib
import json
import binascii
import tempfile
import shutil
from elasticsearch import Elasticsearch

def sumFile(f, block_size=2**20):
    sum = hashlib.sha256()
    while True:
        data = f.read(block_size)
        if not data:
            break
        sum.update(data)
    return sum.digest().encode("hex")

class Pcap2Bro2Es:
    def __init__(self, pcap_name, bro_bin="/usr/local/bro/bin/bro"):
        self.working_dir = os.getcwd()
        self.temp_dir = tempfile.mkdtemp()
        self.pcap_name   = pcap_name
        self.pcapf       = open(pcap_name, 'rb')
        self.pcap_sum    = sumFile(self.pcapf)
        self.bro_bin     = bro_bin
        self.bro_cmd     = self.bro_bin
        self.bro_scripts = []
        self.bro_flags   = []

    def _tempDirCleaner(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        os.chdir(self.working_dir)

    def logShits(self, msg):
        # Fixme
        print msg

    def addBroFlag(self, flag):
        self.bro_flags.append( flag )

    def addBroScript(self, script_name):
        self.bro_scripts.append( script_name )

    def buildBroCmd(self):
        # These flags and scripts are REQUIRED
        self.addBroFlag( ("-C", "") )
        self.addBroFlag( ("-r", self.pcap_name) )
        self.addBroScript("/usr/local/bro/share/bro/policy/tuning/json-logs.bro")
        for each_tuple in self.bro_flags:
            for each_flag in each_tuple:
                self.bro_cmd = self.bro_cmd + ' ' + each_flag
        for each_script in self.bro_scripts:
            self.bro_cmd = self.bro_cmd + ' ' + each_script

    def runBroCmd(self):
        os.chdir(self.temp_dir)
        if os.system(self.bro_cmd) != 0:
            self.logShits("system call to Bro binary failed") 

    def indexBroLogs(self, es_index="bro_logs"):
        log_json = []
        es = Elasticsearch()
        es_id = self.pcap_sum
        all_bro_logs = glob.glob('*.log') # we should still be in self.temp_dir
        for es_type in all_bro_logs:
            with open(es_type) as file:
                for each_line in file:
                    try:
                        log_json.append(json.loads(each_line))
                    except:
                        self.logShits(".log file in temp_dir likely not JSON")
            es.index(index=es_index, doc_type=os.path.basename(es_type), id=es_id, body={'records':log_json})
            # the best debugging is print pepper
            doc_url = "/" + es_index + "/" + os.path.basename(es_type) + "/" + es_id
            self.logShits("es document created at " + doc_url)
        self._tempDirCleaner()

    def go(self):
        self.buildBroCmd()
        self.runBroCmd()
        self.indexBroLogs()


def main():
    pcap_name = sys.argv[1]
    doit = Pcap2Bro2Es(pcap_name)
    doit.go()

if __name__ == "__main__":
    main()
