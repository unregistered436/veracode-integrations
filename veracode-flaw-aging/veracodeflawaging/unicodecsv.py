# MIT License
#
# Copyright (c) 2019 Veracode
# Author: Chris Campbell
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Purpose:  Unicode CSV utilities


try:
    import cStringIO
except ImportError:
    # import will fail on py3, but that's not a problem
    pass
import sys
import codecs
import csv
import logging


class UnicodeWriter:
    """A CSV writer which will write rows to CSV file "f", which is encoded in the given encoding."""
    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwargs):
        # Redirect output to a queue
        self.queue = cStringIO.StringIO()
        self.writer = csv.writer(self.queue, dialect=dialect, **kwargs)
        self.stream = f
        self.encoder = codecs.getincrementalencoder(encoding)()

    def writerow(self, row):
        self.writer.writerow([s.encode("utf-8") if hasattr(s, "encode") else s for s in row])
        # Fetch UTF-8 output from the queue ...
        data = self.queue.getvalue()
        data = data.decode("utf-8")
        # ... and reencode it into the target encoding
        data = self.encoder.encode(data)
        # write to the target stream
        self.stream.write(data)
        # empty queue
        self.queue.truncate(0)

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def create_csv(row_list, filepath):
    """Create a new CSV file from a list of rows."""
    try:
        with open(filepath, 'w', newline="\n", encoding="utf-8") as f:
            if sys.version_info >= (3,):
                wr = csv.writer(f, quoting=csv.QUOTE_ALL, escapechar='\\')
            else:
                wr = UnicodeWriter(f, quoting=csv.QUOTE_ALL, escapechar='\\')
            wr.writerows(row_list)
    except Exception as e:
        print("Unexpected exception occurred while attempting to write to CSV file.")
        raise