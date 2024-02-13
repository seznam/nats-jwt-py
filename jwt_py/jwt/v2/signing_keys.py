class SigningKeys(dict):
    def add(self, *keys: str) -> None:
        for key in keys:
            self[key] = None
