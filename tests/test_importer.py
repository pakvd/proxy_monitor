import unittest
from io import BytesIO

from openpyxl import Workbook

from app.importer import parse_xlsx, workbook_bytes


def _save(rows):
    book = Workbook()
    sheet = book.active
    for row in rows:
        sheet.append(row)
    buffer = BytesIO()
    book.save(buffer)
    return buffer.getvalue()


class ImporterTests(unittest.TestCase):
    def test_russian_headers_and_numeric_password(self):
        raw = _save([
            ["ip", "порт", "логин", "пароль", "адрес", "модем"],
            ["10.1.1.1", 30001, "user", 12345, "ферма", "vlan-7"],
        ])
        rows, errors = parse_xlsx(raw)
        self.assertEqual(errors, [])
        self.assertEqual(rows[0]["host"], "10.1.1.1")
        self.assertEqual(rows[0]["port"], 30001)
        self.assertEqual(rows[0]["password"], "12345")
        self.assertEqual(rows[0]["address"], "ферма")
        self.assertEqual(rows[0]["name"], "vlan-7")
        self.assertEqual(rows[0]["protocol"], "http")

    def test_row_error_does_not_drop_valid_rows(self):
        raw = _save([
            ["ip", "port", "login", "password", "address"],
            ["10.0.0.2", 8000, "a", "b", "farm"],
            ["bad host", 8000, "a", "b", "farm"],
            ["10.0.0.2", 8000, "a", "b", "farm"],
        ])
        rows, errors = parse_xlsx(raw)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(errors), 2)

    def test_rejects_non_xlsx(self):
        with self.assertRaises(ValueError):
            parse_xlsx(b"not an excel file")

    def test_roundtrip_template_has_headers(self):
        rows, errors = parse_xlsx(workbook_bytes([], example=True))
        self.assertEqual(errors, [])
        self.assertEqual(rows[0]["host"], "203.0.113.10")
        self.assertEqual(rows[0]["address"], "farm-01")


if __name__ == "__main__":
    unittest.main()
