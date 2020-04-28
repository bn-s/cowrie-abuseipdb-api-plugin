import csv
import os

from twisted.internet import defer, threads

from cowrie.output.abuseipdb import utils


class CSVAuthor:
    def __init__(self):
        self.report_file = os.path.join(utils.cfg.plugin_path, 'bulk_report.csv')
        self.temp_file = os.path.join(utils.cfg.plugin_path, 'bulk_report.tmp')

    @defer.inlineCallbacks
    def csv_updater(self, dicts, reporting=False):
        try:
            os.rename(self.report_file, self.temp_file)
        except FileNotFoundError:
            pass

        reader = yield threads.deferToThread(self.csv_reader)
        writer = yield threads.deferToThread(self.csv_writer)
        yield threads.deferToThread(self.pipeline, reader, writer, dicts, reporting)

        try:
            os.remove(self.temp_file)
        except FileNotFoundError:
            pass

    def pipeline(self, reader, writer, dict, reporting):
        # TODO: Times, comments, cats, etc.
        # TODO: reporting/updating switch to complete sections before sending
        try:
            next(writer)

            while True:
                current = next(reader)

                if current['IP'] in dict:
                    # TODO: update last seen time...
                    ip = current['IP']
                    updated = self.update_count(current, dict[ip])
                    del dict[ip]

                else:
                    updated = current

                if reporting:
                    # Complete cats, comments, etc.
                    pass

                writer.send(updated)

        except StopIteration:
            for k, v in dict.items():
                pass
                # TODO: Write new IPs to file
                # d = {k: _, ..., }
                # writer.send(d)
            # Kill writer's while loop
            writer.send(False)

    def csv_reader(self):
        with open(self.temp_file, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                yield row

    def csv_writer(self, keys=['IP', 'Categories', 'ReportDate', 'Comment']):
        with open(self.report_file, mode='w') as f:
            author = csv.DictWriter(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, fieldnames=keys)
            author.writeheader()
            while True:
                d = yield
                if not d:
                    break
                author.writerow(d)
        yield

    def update_count(self, entry, count):
        entry['Comment'] = int(entry['Comment']) + count
        return entry
