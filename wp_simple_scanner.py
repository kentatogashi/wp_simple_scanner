#!/usr/local/bin/python
# coding: utf-8

import sys
import os
import subprocess
import traceback

LOG = os.path.abspath(os.path.dirname(__file__)) + '/scanner.log'

class Scanner:
    def __init__(self, target):
        self.warnings = set()
        self.threshold_cnt = 66
        self.target = target
        self.keywords = [
            'base64_decode',
            'eval',
            'create_function',
            '$_POST'
        ]
        self.whitelist = [
            'ionCube Loader',
            'Google+ embeds',
            'WORDFENCE_VERSION',
            'Wordfence',
            'wfDateLocalization'
        ]
        self.logged = False
        self.is_suspect = False
        self.logfile = LOG
        self.log_fh = open(self.logfile, 'a')

    def run(self):
        self.inspect()
        if len(self.warnings) > 0:
            self.check_keyword()

    def _any(self, line, whitelist):
        for w in whitelist:
            if w in line:
                return True
        return False

    def inspect(self):
        wtb = {}
        is_include_pattern=False
        f = open(self.target, 'r')
        linenum = 0
        for line in f:
            if linenum == 10:
                break
            line = line.rstrip()
            if line.count > 500:
                self.add('long line')
            if ('@include' in line) and ('.ico";' in line or '\\x69co";' in line or 'i\\x63o";' in line \
                or '\\x69c\\x6f";' in line or 'ic\\x6f";' in line or '\\x2eico' in line):
                self.add('early suspect strings')
            if linenum == 0 and "DOCTYPE html PUBLIC" in line:
                break
            if self._any(line, self.whitelist):
                break
            if self.is_multibyte(line):
                continue
            if line[0] in ['*', '#']:
                continue
            for chr_ in line:
                if chr_ == " ": continue
                if not chr_ in wtb.keys():
                    wtb[chr_] = 0
                else:
                    wtb[chr_] += 1
            linenum += 1
        f.close()
        if len(wtb) > self.threshold_cnt:
            self.warnings.add('many ascii characters.')
            self.debug("SUSPICIOUS : %s has %d ascii characters" % (self.target, len(wtb)))
        if is_include_pattern:
            self.warnings.add('suspect include pattern.')
            self.debug("SUSPICIOUS : %s matched include pattern" % self.target)

    def check_keyword(self):
        for keyword in self.keywords:
            p = subprocess.Popen(['grep', '-q', keyword, self.target])
            p.communicate()
            if p.returncode == 0:
                self.warnings.add('suspect keyword pattern')
                self.debug("SUSPICIOUS : %s has %s" % (self.target, keyword))

    def is_multibyte(self, string):
        try:
            for ch in string:
                ch.encode('ascii', 'strict')
        except UnicodeDecodeError:
            return True
        return False

    def debug(self, message):
        print(message)

    def logger(self):
        if not self.logged:
            cmd1 = 'ls -lc %s' % (self.target)
            p1=subprocess.Popen(cmd1, stdout=subprocess.PIPE, shell=True)
            out1, _ = p1.communicate()
            cmd2 = 'head -10 %s' % (self.target)
            p2=subprocess.Popen(cmd2, stdout=subprocess.PIPE, shell=True)
            out2, _ = p2.communicate()
            self.log_fh.write("###START SCAN\n")
            self.log_fh.write("###FILE\n")
            self.log_fh.write("%s\n" % (self.target))
            self.log_fh.write("###STAT\n")
            self.log_fh.write(out1.split("\n")[0] + "\n")
            self.log_fh.write("###HEAD\n")
            self.log_fh.write(out2 + "\n")
            self.log_fh.write("###END SCAN\n")
            self.log_fh.close()
            self.logged = True

def get_files(userid):
    path = '/usr/home/%s/html' % (userid)
    return [os.path.join(d, file) \
            for (d, _, files) in os.walk(path) \
            for file in files if file.endswith('.php')]

if __name__ == '__main__':
   userid = sys.argv[1]
   if os.path.exists(LOG):
       os.unlink(LOG)
   for line in get_files(userid):
       line = line.rstrip('\r\n')
       scanner = Scanner(line)
       scanner.run()
