class _Missing:
    def __eq__(self, other):
        return False

    def __ne__(self, other):
        return True


MISSING = _Missing()

__all__ = ['MISSING']
