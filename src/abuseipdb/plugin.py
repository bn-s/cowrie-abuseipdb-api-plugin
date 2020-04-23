import pickle

import cowrie.core.output

from cowrie.output.abuseipdb import observers, utils


class AbuseIPDB(cowrie.core.output.Output):
    def start(self):
        self.watchdoge = observers.WatchDoge()

        try:
            with open(utils.cfg.doge_dump, 'rb') as doge_dump:
                self.watchdoge._dogebook = pickle.load(doge_dump)
        except FileNotFoundError:
            pass
        except EOFError:
            pass

        utils.Log.message('starting with doge_book: {}'.format(self.watchdoge._dogebook))

    def stop(self):
        utils.Log.message('stopping with doge_book: {}'.format(self.watchdoge._dogebook))

        with open(utils.cfg.doge_dump, 'wb') as doge_dump:
            pickle.dump(self.watchdoge._dogebook, doge_dump)

    def write(self, event):
        if event['eventid'].rsplit('.', 1)[0] == 'cowrie.login':
            utils.Log.message('Login attempt {}'.format(event['src_ip']))
            self.watchdoge.such_h4x0r(event['src_ip'])
