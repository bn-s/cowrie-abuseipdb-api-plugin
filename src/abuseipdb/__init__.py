from cowrie.output.abuseipdb import plugin, utils


class Output(plugin.AbuseIPDB):
    def start(self):
        utils.Log.starting()
        super().start()
