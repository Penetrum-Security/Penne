import argparse


class Parser(argparse.ArgumentParser):

    def __init__(self):
        super().__init__()

    @staticmethod
    def optparse():
        parser = argparse.ArgumentParser(
            prog="penne",
            usage="penne",
            description="PenneAV is a cross compatible opensource anti-virus"
        )
        req = parser.add_argument_group("Required arguments")
        return parser.parse_args()

