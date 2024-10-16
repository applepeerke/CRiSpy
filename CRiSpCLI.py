#!/usr/bin/python
# ---------------------------------------------------------------------------------------------------------------------
# CRiSpCLI.py
#
# Author      : Peter Heijligers
# Description : Code Review involving Search patterns
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-08-24 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

import getopt
import sys

from src.core.BusinessLayer.CRiSpy import CRiSpy
from root_functions import get_root_dir
from src.gl.Const import SEARCH_DATA_PATH
from src.gl.Enums import Color, LogType, ApplicationTypeEnum
from src.gl.Validate import *

# Parameters
input_dir = EMPTY
application_type = ApplicationTypeEnum.Any
custom_pattern = SEARCH_DATA_PATH
title = EMPTY
company = EMPTY
verbose = False
filter_mode = True
quick_scan = False
output = LogType.Both
output_dir = EMPTY
data_dir = f'{get_root_dir()}Data'

usage = 'usage: crispcli.py -i <inputdir> -c <company>  -t <title> -p <pattern>  -o <output> -l <outputdir> ' \
        '-b <codebasetype>-v -a -q -s -h'
errorText = Color.RED + "Error:" + Color.NC + " "


# ---------------------------------------------------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------------------------------------------------


def main(argv):
    global input_dir, custom_pattern, title, company, verbose, filter_mode, quick_scan, output, \
        output_dir, application_type, data_dir

    try:
        opts, args = getopt.getopt(
            argv, "ahqsvb:i:t:p:c:l:",
            ["bcodebasetype=",
             "iinputdir=",
             "ttitle=",
             "ppattern=",
             "ccompany=",
             "ooutput=",
             "loutputdir="
             ])
    except getopt.GetoptError:
        sys.exit(2)

    sync_cve = False
    for opt, arg in opts:
        if opt == "-h":
            try:
                text_file = open("src/help.txt", "r")
                lines = text_file.readlines()
                for line in lines:
                    print(line.rstrip('\r\n'))
                text_file.close()
            except IOError:
                print(usage)
            sys.exit(0)

        elif opt in ("-i", "--inputdir"):
            input_dir = normalize_dir(arg, False)
            if input_dir == QUIT or not os.path.isdir(input_dir):
                exit_program('Parameter -i input directory is not valid or does not exist.')

        elif opt in ("-b", "--applicationtype"):
            application_type = arg
            if not isValidName(arg) or application_type not in [e for e in ApplicationTypeEnum]:
                exit_program('Parameter -b project type is not valid.')

        elif opt in ("-t", "--title"):
            if not isValidName(arg, blank_allowed=True):
                exit_program('Parameter -t title is not a valid name.')
            title = arg

        elif opt in ("-p", "--pattern"):
            custom_pattern = validate_text(arg, False)
            if custom_pattern == QUIT:
                exit_program('Parameter -p pattern is not a valid text.')

        elif opt in ("-c", "--company"):
            if not isValidName(arg):
                exit_program('Parameter -c company is not a valid name.')
            company = arg

        elif opt in ("-o", "--output"):
            if not isValidName(arg):
                exit_program('Parameter -o output is not a valid name.')
            output = arg

        elif opt in ("-l", "--outputdir"):
            output_dir = normalize_dir(arg, False)
            if output_dir == QUIT or not os.path.isdir(output_dir):
                exit_program('Parameter -l output directory is not valid or does not exist.')

        elif opt == "-s":
            sync_cve = True

        elif opt == "-v":
            verbose = True

        elif opt == "-q":
            quick_scan = True

        elif opt == "-a":
            filter_mode = False

    if not input_dir:
        exit_program('Parameter -i <inputdir> is required.')

    crispy = CRiSpy(input_dir=input_dir, application_type=application_type, log_title=title, company_name=company,
                    custom_search_pattern=custom_pattern, verbose=verbose, filter_findings=filter_mode, cli_mode=True,
                    quick_scan=quick_scan, synchronize_cve=sync_cve, output_type=output, output_dir=output_dir,
                    data_dir=data_dir)
    result = crispy.start()
    text = result.text if not result.OK else EMPTY
    exit_program(text)


def exit_program(error_text=EMPTY):
    if error_text:
        print(f'\n{errorText} {error_text}')
        print(usage)
        print('use parameter "-h" for help.')
    sys.exit(0)


# ---------------------------------------------------------------------------------------------------------------------
# M a i n l i n e
# ---------------------------------------------------------------------------------------------------------------------


if __name__ == "__main__":
    main(sys.argv[1:])
