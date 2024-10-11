import unittest
import os
import fnmatch

from src.gl.Functions import path_leaf_only


def find_UT_files(basedir=os.curdir):
    """
    Return all file paths matching the specified file type in the specified base directory (recursively).
    """
    for path, dirs, files in os.walk(os.path.abspath( basedir)):
        for filename in fnmatch.filter(files, '*.py'):
            if filename.startswith('UT_Core') and not filename.endswith('All.py'):
                name, ext = os.path.splitext(filename)
                dir_name = path_leaf_only(path)
                yield f'{dir_name}.{name}'


suite = unittest.TestSuite()

for t in sorted([t for t in find_UT_files()]):
    try:
        # If the module defines a suite() get_index, call it to get the suite.
        mod = __import__(t, globals(), locals(), ['suite'])
        suitefn = getattr(mod, 'suite')
        suite.addTest(suitefn())
    except (ImportError, AttributeError):
        # else, just load all the test cases from the module.
        suite.addTest(unittest.defaultTestLoader.loadTestsFromName(t))

unittest.TextTestRunner().run(suite)
