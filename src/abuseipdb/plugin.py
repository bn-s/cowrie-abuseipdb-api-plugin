import pickle

import cowrie.core.output
from cowrie.output.abuseipdb import observers, utils


class AbuseIPDB(cowrie.core.output.Output):
    def start(self):
        self.watchdoge = observers.WatchDoge()

        try:
            with open(utils.cfg.doge_dump, 'rb') as doge_dump:
                self.watchdoge.dogebook.update(pickle.load(doge_dump))
        except FileNotFoundError:
            pass

        self.watchdoge.dogebook.all_clean()

        utils.Log.message('starting with doge_book: {}'.format(self.watchdoge.dogebook))

    def stop(self):
        self.watchdoge.dogebook.all_clean()
        utils.Log.message('stopping with doge_book: {}'.format(self.watchdoge.dogebook))

        dump_me = {}
        for k, v in self.watchdoge.dogebook.items():
            dump_me[k] = v

        with open(utils.cfg.doge_dump, 'wb') as doge_dump:
            pickle.dump(dump_me, doge_dump, protocol=pickle.HIGHEST_PROTOCOL)

    def write(self, event):
        if event['eventid'].rsplit('.', 1)[0] == 'cowrie.login':
            utils.Log.message('Login attempt {}'.format(event['src_ip']))
            self.watchdoge.such_h4x0r(event['src_ip'])
