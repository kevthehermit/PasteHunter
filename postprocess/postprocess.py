# This gets the raw paste, yara rules and the paste id
# Post runs after paste is stored.
# We call in post process modules
# If we are in elastic search we update the document


class PostProcess:
    def __init__(self):
        self.raw_paste = ''
        self.yararules = []
        self.pasteid = ''

    def run(self):
        pass
