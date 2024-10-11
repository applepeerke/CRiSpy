#!/usr/bin/python
# ---------------------------------------------------------------------------------------------------------------------
# UT_Core_400_SearchPatterns.py
#
# Author      : Peter Heijligers
# Description : Process SearchPatterns.csv and look if all search patterns generate findings in itself...
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-10-10 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
import unittest

from src.gl.BusinessLayer.SessionManager import Singleton as Session, normalize_dir
from src.gl.Const import EMPTY
from src.utils.XmlPom2Dict import XmlPom2Dict

Session().set_paths(unit_test=True)
input_dir = normalize_dir(f'{Session().design_dir}XML')


def strip_prefix(child, prefix):
    return child.replace(prefix, EMPTY) if prefix else child


class ParseXmlTestCase(unittest.TestCase):

    def test_TC01_get_versions(self):
        xml_parser = XmlPom2Dict()
        versions = xml_parser.get_versions(f'{input_dir}pom.xml')
        self.assertTrue(versions)
        self.assertTrue(xml_parser.result.OK)

    def test_TC02_get_spring_security(self):
        xml_parser = XmlPom2Dict()
        texts = xml_parser.get_texts(
            f'{input_dir}pom.xml', parent_tree=['<dependencies>', '<dependency>'], tag='<groupId>')
        self.assertTrue(len(texts) > 0)
        self.assertTrue('org.springframework.security' in texts)


if __name__ == '__main__':
    unittest.main()
