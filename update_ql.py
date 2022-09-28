import pickle
import unicornafl
unicornafl.monkeypatch()
import argparse
from qiling import Qiling
import pefile
from unicorn import *

def ckeck_option(ql, args):
	if args.nvram_file:
		update_nvram(ql, args.nvram_file)

def update_nvram(ql, nvram_file):
	with open(nvram_file, 'rb') as nvram:
		ql.env.update(pickle.load(nvram))


