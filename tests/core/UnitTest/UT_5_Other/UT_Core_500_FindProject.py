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
import os
import unittest

from src.core.Functions.Functions import get_root_dir
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Enums import *

Session().set_paths(unit_test=True)
UT_projects_dir = None

prediction_dict = {
    "20170928 - KPN MijnKPN - iOS - Release 3.20.0 2/MijnKPN-3.20.0":
        [Language.iOS, "MijnKPN"],
    "20180227 MijnKPN/Aanlevering/mijnkpn-android-release-3.21.0@3f1e224d381/MijnKPN/src":
        [Language.Java, "mijnkpn-android"],
    "20170927 - KPN MijnKPN - Android - Release-3.19.1/mijnkpn-android-release-3.19.1/MijnKPN/src":
        [Language.Java, "mijnkpn-android"],
    "20170828 - KPN Central Identity - Release 1.19.8/VA_8e952288/VA_8e952288/app":
        [Language.JavaScript, "KPN Central Identity - Release"],
    "20170828 - KPN Central Identity - Release 1.19.8/VA_release_1.19.8/VA_release_1.19.8":
        [Language.Python, "KPN Central Identity - Release"],
    "20171116 - KPN DE API de-fixed/vulnerability_assessment_a1636e1ece73e668ddabda834"
    "fb94b16e5b1d830/src":
        [Language.Python, "KPN DE API de-fixed"],
    "20171116 - KPN DE API de-appointments/vulnerability_assessment_c0e2d7bde00ed6555577ce9"
    "fe06309142d9d6bf8/src":
        [Language.Python, "KPN DE API de-appointments"],
    "20170830 - KPN All Java plugin dists/kpncompresentation-1.2.6-dist/src":
        [Language.Java, "kpncompresentation"],
    "20170830 - KPN All Java plugin dists/kpnconnectors-1.1.0-dist/src":
        [Language.Java, "kpnconnectors"],
    "20170830 - KPN All Java plugin dists/kpnrestservices-1.1.0-dist/src":
        [Language.Java, "kpnrestservices"],
    "20171204 - KPN GX Open/Aanlevering/kpncompresentation-1.3.0-dist/src":
        [Language.Java, "kpncompresentation"],
    "20171204 - KPN GX Open/Aanlevering/kpnzakelijkblog-1.0.0-dist/src":
        [Language.Java, "kpnzakelijkblog"],
    "20171204 - KPN GX Open/Aanlevering/kpnexposedrestservices-1.2.0-dist/src":
        [Language.Java, "kpnexposedrestservices"],
    "20180221 de-mobile 1.1.0/Aanlevering/vulnerability_assessment_1.1.0/":
        [Language.JavaScript, "de-mobile"],
    "20180108 - KPN OmniCRM/OmniCRM-code-Sprint71/Domain.Mosaic":
        [Language.NET, "Domain.Mosaic"],
    "20180108 - KPN OmniCRM/OmniCRM-code-Sprint71/Server.DWQ":
        [Language.NET, "Server.DWQ"],
    "20180108 - KPN OmniCRM/OmniCRM-code-Sprint71/Server.MosaicWCFService":
        [Language.NET, "Server.MosaicWCFService"],
    "20180108 - KPN OmniCRM/OmniCRM-code-Sprint71/CCustomTokenManagerWCF":
        [Language.NET, "CustomTokenManagerWCF"],
    "20171004 - KPN DE Selfcare - Release 1.0.0/service-de-api/code_1.11.0/de":
        [Language.Python, "service-de"],
    "20171004 - KPN DE Selfcare - Release 1.0.0/code_1.0.0/selfcare/main":
        [Language.Python, "KPN DE Selfcare - Release"],
    "20171004 - KPN DE Selfcare - Release 1.0.0/authz-middleware/code_3.7.1/authz_middleware":
        [Language.Python, "authz-middleware"],
    "20171208 - KPN DE Selfcare/de-selfcare_1.3.0a1/code_1.3.0a1/selfcare":
        [Language.Python, "de-selfcare"],
    "20180221 de-messaging 9.4.0/Aanlevering/de-messaging/src":
        [Language.Python, "de-messaging"],
    "20180306 de-babelfish/Aanlevering/de-babelfish/src":
        [Language.Python, "de-babelfish"],
    "20170818 - KPN Central Identity - WS phone identification/src":
        [Language.Python, "KPN Central Identity - WS phone identification"],
    "20180221 de-business 1.6.0/Aanlevering/vulnerability_assessment_1.6.0/"
    "vulnerability_assessment_1.6.0/src":
        [Language.Python, "de-business"],
    "20170816 - KPN Mobile - Phone numbers - Release 1.4.0/vulnerability_assessment_1.4.0/src":
        [Language.Python, "KPN Mobile - Phone numbers "],
    "20180302 URL shortner/Aanlevering/src":
        [Language.Python, "*UNKNOWN"]
}


class FindProjectNameTestCase(unittest.TestCase):

    def test_TC01_ValidateProjects(self):
        global UT_projects_dir
        UT_projects_dir = f'{get_root_dir()}UT/Projects/'
        for key, value in prediction_dict.items():
            self.assertTrue(os.path.exists(UT_projects_dir + key))


if __name__ == '__main__':
    unittest.main()
