import unittest
from src.core.Plugins.ExternalLinks import ExternalLinks
from src.gl.BusinessLayer.SessionManager import Singleton as Session

EL = ExternalLinks()
session = Session()


class ExternalLinksTestCase(unittest.TestCase):

    def test_TC01_External_links(self):
        session.set_paths(unit_test=True, suffix=__name__)
        input_path = f'{session.design_dir}UT_External_links.txt'
        EL.get_rows_with_external_links(input_path, base_path=session.log_dir, write_results=True)
        rows = EL.get_rows_with_external_links(input_path, write_results=False)
        self.assertEqual(len(rows), 19)


if __name__ == '__main__':
    unittest.main()
