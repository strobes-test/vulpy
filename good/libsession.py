import json


class Session:
    def __init__(self, session_file):
        self.session_file = session_file
        self.data = {}
        self.load()

    def load(self):
        try:
            with open(self.session_file, "r") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            self.data = {}

    def save(self):
        with open(self.session_file, "w") as f:
            json.dump(self.data, f)

    def set(self, key, value):
        self.data[key] = value
        self.save()

    def get(self, key, default=None):
        return self.data.get(key, default)

    def delete(self, key):
        if key in self.data:
            del self.data[key]
            self.save()
