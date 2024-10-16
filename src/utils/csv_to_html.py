from src.gl.Const import SPECIAL_CHARS
from src.gl.Functions import sanitize_text_to_alphanum_and_underscore

PGM = 'csv_to_html'


class HtmlCell:
    @property
    def value(self):
        return self._value

    @property
    def th_class(self):
        return self._th_class

    @property
    def tr_class(self):
        return self._tr_class

    @property
    def td_class(self):
        return self._td_class

    def __init__(self, value, th_class='', tr_class='', td_class=''):
        self._value: str = value
        self._th_class = th_class
        self._tr_class = tr_class
        self._td_class = td_class

    
class CsvToHtml:

    def __init__(self):
        self._html = []

    def start(self, rows, header_row_count=1, sanitize=True, styles=None) -> str:
        self._html = []
        sanitized_rows = [[HtmlCell(value=self._sanitize(cell, sanitize)) for cell in row] for row in rows]
        self._header(styles)
        self._body(sanitized_rows, header_row_count)
        self._footer()
        out_html_rows = [''.join(row) for row in self._html]
        out_html = ''.join(out_html_rows)
        return out_html

    def _header(self, styles):
        self._html.append('<html>')
        self._html.append('<header>')
        self._html.append('<style>')
        if styles:
            [self._html.append(style) for style in styles]
        self._html.append('th { color: White; background-color: rgb(0, 0, 255);}')
        self._html.append('</style>')
        self._html.append('</header>')

    def _body(self, rows, header_row_count):
        self._html.append('<body><div><table>')
        header_count = 0

        for row in rows:
            self._html.append(f'<tr>')
            # Header row(s)
            if header_count < header_row_count:
                header_count += 1
                [self._html.append(f'<th>{cell.value}</th>') for cell in row]
            # Detail rows
            else:
                [self._html.append(f'<td{cell.td_class}>{cell.value}</td>') for cell in row]
            self._html.append('</tr>')
        self._html.append('</table></div></body>')

    def _footer(self):
        self._html.append('</html>')

    @staticmethod
    def _sanitize(value, sanitize) -> str:
        return sanitize_text_to_alphanum_and_underscore(value, special_chars=SPECIAL_CHARS) if sanitize else value
