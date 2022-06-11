from setuptools import setup

setup(
    name="try",
    version="0.0.1",
    packages=["feature", "fetch", "manipulate"]
    install_requires=[
        "tqdm",
        "lief",
        "capstone",
        "filebrowser @ git+https://github.com/dagrons/fbrowser@master",
    ]
)
