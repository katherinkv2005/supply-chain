import subprocess


def build():

    subprocess.run(
        ["docker", "build", "-t", "validator", "."],
        check=False
    )


def run():

    subprocess.run(
        ["docker", "run", "--rm", "validator"],
        check=False
    )